"""Привилегированный node-agent (ADR-0041, спецификация adminchat-agentic-devops, раздел 2).

Крошечный HTTP-сервер на стандартной библиотеке Python (http.server, без FastAPI и без внешних
зависимостей). Разворачивается DaemonSet-ом по одному поду на каждый узел кластера и даёт панели
adminchat возможность исполнять произвольные команды в пространстве имён самого хоста через
nsenter, то есть с правами рута на узле (чистка диска, docker и containerd prune, df, top, kill
процесса, systemctl). Это god-mode-поверхность по отношению к узлу, поэтому она закрыта общим
секретом NODEAGENT_TOKEN, слушается только внутрикластерно (без Ingress) и принимает строго
argv-список, а не строку оболочки, так что инъекция оболочки исключена принципиально.

ENV:
  NODE_NAME       имя узла (downward API spec.nodeName), возвращается в ответах и логах
  NODEAGENT_TOKEN общий секрет доступа; заголовок X-NodeAgent-Token сверяется за постоянное время
  NODEAGENT_PORT  порт прослушивания (по умолчанию 9110), слушаем 0.0.0.0 только внутри кластера

API:
  GET  /health              вернуть {"status":"ok","node":"<NODE_NAME>"}
  POST /run                 заголовок X-NodeAgent-Token, тело {"argv":[...],"timeout":30};
                            исполнить argv в пространстве хоста через nsenter и вернуть
                            {"exit_code","stdout","stderr","duration_ms","node"}
"""
from __future__ import annotations

import hmac
import json
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Имя сервиса для канона структурного JSON-лога (ADR-0032): ts, level, service, msg.
SERVICE = "node-agent"

# Имя узла из downward API (spec.nodeName). Пусто допустимо, но в проде задаётся всегда.
NODE_NAME = os.getenv("NODE_NAME", "")

# Общий секрет доступа. Сервис fail-closed: если токен не задан, любой POST /run отклоняется 401,
# потому что сверять предъявленный токен не с чем, а открывать рут на узле без замка недопустимо.
NODEAGENT_TOKEN = os.getenv("NODEAGENT_TOKEN", "")

# Порт прослушивания. Слушаем на всех интерфейсах пода (hostNetwork), но наружу узел не публикуется
# (без Ingress и без Service типа LoadBalancer), поэтому доступ остаётся внутрикластерным.
PORT = int(os.getenv("NODEAGENT_PORT", "9110"))

# Ограничение объёма вывода: по 256 килобайт на stdout и stderr, чтобы гигантский вывод команды
# не раздул ответ и память. При обрезке добавляется явная пометка.
MAX_OUTPUT_BYTES = 256 * 1024
TRUNCATED_MARK = "\n...[обрезано]"

# Разумные пределы таймаута исполнения (в секундах): не меньше секунды, не больше десяти минут.
MIN_TIMEOUT = 1
MAX_TIMEOUT = 600

# Префикс nsenter для входа в пространства имён процесса с PID 1 (то есть самого хоста): монтирование
# (m), UTS (u), IPC (i) и сеть (n). Двойной дефис отделяет опции nsenter от исполняемой команды и её
# аргументов, чтобы флаги внутри argv не были ошибочно приняты за флаги nsenter.
NSENTER_PREFIX = ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--"]

# Код возврата, которым помечается превышение таймаута (соглашение утилиты timeout из coreutils).
TIMEOUT_EXIT_CODE = 124


def log(level: str, msg: str, **fields) -> None:
    """Структурный JSON-лог по канону проекта (ADR-0032): ts, level, service, msg плюс поля.

    Сам токен доступа сюда никогда не передаётся: логируется только факт исполнения (argv,
    exit_code, duration_ms), но не секрет.
    """
    now = time.time()
    obj = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % int((now % 1) * 1000),
        "level": level,
        "service": SERVICE,
        "msg": msg,
    }
    if NODE_NAME:
        obj["node"] = NODE_NAME
    for k, v in fields.items():
        obj[k] = v
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _truncate(raw: bytes) -> str:
    """Декодировать вывод и ограничить его MAX_OUTPUT_BYTES, добавив пометку при обрезке."""
    if len(raw) > MAX_OUTPUT_BYTES:
        return raw[:MAX_OUTPUT_BYTES].decode("utf-8", "replace") + TRUNCATED_MARK
    return raw.decode("utf-8", "replace")


def validate_body(body: dict) -> tuple[list, int]:
    """Проверить тело запроса /run и вернуть пару (argv, timeout).

    Правила: argv это непустой список строк, timeout это число в пределах MIN_TIMEOUT..MAX_TIMEOUT.
    При нарушении бросается ValueError с русским пояснением, которое вызывающий переводит в ответ 400.
    """
    if not isinstance(body, dict):
        raise ValueError("тело запроса должно быть объектом JSON")
    argv = body.get("argv")
    if not isinstance(argv, list) or not argv:
        raise ValueError("поле argv должно быть непустым списком")
    if not all(isinstance(a, str) for a in argv):
        raise ValueError("все элементы argv должны быть строками")
    timeout = body.get("timeout", 30)
    # bool это подтип int в Python, поэтому логическое значение таймаутом считать нельзя.
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("поле timeout должно быть числом")
    if not (MIN_TIMEOUT <= timeout <= MAX_TIMEOUT):
        raise ValueError("поле timeout должно быть в пределах %d..%d секунд" % (MIN_TIMEOUT, MAX_TIMEOUT))
    return argv, timeout


def build_command(argv: list) -> list:
    """Собрать полный argv для subprocess.run: префикс nsenter плюс переданный список.

    Ключевая гарантия безопасности: команда передаётся как список аргументов, а не как строка
    оболочки, поэтому shell=True и sh -c не используются нигде, и метасимволы оболочки внутри argv
    не интерпретируются. Инъекция оболочки невозможна конструктивно.
    """
    return NSENTER_PREFIX + list(argv)


def run_host_command(argv: list, timeout: float) -> dict:
    """Исполнить argv в пространстве имён хоста через nsenter и вернуть словарь результата.

    subprocess.run вызывается со списком аргументов (без shell=True), с захватом stdout и stderr в
    байтах и с жёстким таймаутом. При превышении таймаута возвращается exit_code=124 и пометка в
    stderr; вывод в любом случае ограничивается по объёму.
    """
    cmd = build_command(argv)
    started = time.monotonic()
    try:
        proc = subprocess.run(  # noqa: S603 - список аргументов, без оболочки, инъекция исключена
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        duration_ms = int((time.monotonic() - started) * 1000)
        result = {
            "exit_code": proc.returncode,
            "stdout": _truncate(proc.stdout or b""),
            "stderr": _truncate(proc.stderr or b""),
            "duration_ms": duration_ms,
            "node": NODE_NAME,
        }
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.monotonic() - started) * 1000)
        partial_out = _truncate(exc.stdout or b"") if isinstance(exc.stdout, (bytes, bytearray)) else ""
        partial_err = _truncate(exc.stderr or b"") if isinstance(exc.stderr, (bytes, bytearray)) else ""
        note = "команда прервана по таймауту %.0f с ...[обрезано по времени]" % timeout
        result = {
            "exit_code": TIMEOUT_EXIT_CODE,
            "stdout": partial_out,
            "stderr": (partial_err + "\n" + note).strip(),
            "duration_ms": duration_ms,
            "node": NODE_NAME,
        }
    log("info", "исполнение команды на узле", argv=argv, exit_code=result["exit_code"],
        duration_ms=result["duration_ms"])
    return result


def token_ok(presented: str) -> bool:
    """Сверить предъявленный токен с секретом за постоянное время (hmac.compare_digest).

    Fail-closed: если секрет NODEAGENT_TOKEN не задан на сервере, доступ запрещён всегда, потому что
    открывать рут на узле без замка нельзя.
    """
    if not NODEAGENT_TOKEN:
        return False
    if not presented:
        return False
    return hmac.compare_digest(presented, NODEAGENT_TOKEN)


class Handler(BaseHTTPRequestHandler):
    # Отключаем стандартный текстовый лог http.server: ведём собственный структурный JSON.
    def log_message(self, fmt, *args):  # noqa: N802 - имя задано базовым классом
        return

    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 - имя задано базовым классом
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "node": NODE_NAME})
            return
        self._send_json(404, {"error": "не найдено"})

    def do_POST(self):  # noqa: N802 - имя задано базовым классом
        if self.path != "/run":
            self._send_json(404, {"error": "не найдено"})
            return
        # Fail-closed проверка токена ДО разбора тела: без совпадения возвращаем 401 и ничего не
        # исполняем. Сам токен в лог не попадает.
        presented = self.headers.get("X-NodeAgent-Token", "")
        if not token_ok(presented):
            log("warn", "отказ в доступе к /run без валидного токена")
            self._send_json(401, {"error": "нет доступа"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError):
            self._send_json(400, {"error": "тело запроса не является корректным JSON"})
            return
        try:
            argv, timeout = validate_body(body)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return
        result = run_host_command(argv, timeout)
        self._send_json(200, result)


def main() -> None:
    if not NODEAGENT_TOKEN:
        # Не падаем на старте (health-проба должна отвечать), но громко предупреждаем: пока токен не
        # задан, /run отклоняет всё, то есть сервис бесполезен, но и не опасен.
        log("warn", "NODEAGENT_TOKEN не задан: эндпоинт /run будет fail-closed отклонять все запросы")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    log("info", "node-agent запущен", port=PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
