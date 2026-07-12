"""Привилегированный узловой агент (node-agent) продукта aegil.

Крошечный HTTP-сервер на стандартной библиотеке Python (http.server, без FastAPI и без внешних
зависимостей). Разворачивается объектом DaemonSet по одному поду на каждый узел кластера и даёт
панели агента возможность исполнять произвольные команды в пространстве имён самого хоста через
nsenter, то есть с правами суперпользователя на узле (чистка диска, prune образов docker и
containerd, df, top, снятие зависшего процесса, systemctl). Это god-mode-поверхность по отношению
к узлу, поэтому она закрыта общим секретом, доступна строго внутрикластерно (без Ingress, только
по адресу пода через Service, без публикации порта узла) и принимает строго argv-список, а не
строку оболочки, так что инъекция оболочки исключена принципиально.

Переменные окружения (единый префикс продукта AEGIL_):
  AEGIL_NODE_NAME       имя узла (downward API spec.nodeName), возвращается в ответах и логах.
  AEGIL_NODEAGENT_TOKEN общий секрет доступа; заголовок X-NodeAgent-Token сверяется за
                           постоянное время. Сервис fail-closed: при пустом секрете любой запрос
                           на исполнение отклоняется.
  AEGIL_NODEAGENT_PORT  порт прослушивания (по умолчанию 9110); слушаем адрес пода внутри
                           кластера.

API:
  GET  /health  вернуть {"status":"ok","node":"<node>"} без требования токена (для readiness-пробы).
  POST /run     заголовок X-NodeAgent-Token, тело {"argv":[...],"timeout":30}; исполнить argv в
                пространстве хоста через nsenter и вернуть
                {"exit_code","stdout","stderr","duration_ms","node"}.
"""
from __future__ import annotations

import hmac
import json
import os
import signal
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Имя сервиса для канона структурного JSON-лога: ts, level, service, msg.
SERVICE = "node-agent"

# Имя узла из downward API (spec.nodeName). Пусто допустимо, но в промышленной эксплуатации задаётся
# всегда. Единый префикс продукта AEGIL_.
NODE_NAME = os.getenv("AEGIL_NODE_NAME", "")

# Общий секрет доступа. Сервис fail-closed: если токен не задан, любой запрос на исполнение
# отклоняется с кодом 401, потому что сверять предъявленный токен не с чем, а открывать доступ
# суперпользователя на узле без замка недопустимо.
NODEAGENT_TOKEN = os.getenv("AEGIL_NODEAGENT_TOKEN", "")

# Порт прослушивания. Слушаем на всех интерфейсах пода, но порт узла не публикуется (в манифесте нет
# hostPort и hostNetwork), поэтому доступ остаётся строго внутрикластерным через Service по адресу
# пода, а сетевая политика допускает вход только от пода панели.
PORT = int(os.getenv("AEGIL_NODEAGENT_PORT", "9110"))

# Ограничение объёма вывода: по 256 килобайт на stdout и stderr, чтобы гигантский вывод команды не
# раздул ответ и память. При обрезке добавляется явная пометка.
MAX_OUTPUT_BYTES = 256 * 1024
TRUNCATED_MARK = "\n...[обрезано]"

# Верхняя граница размера тела запроса. Обработчик читает не больше этого числа байт независимо от
# объявленного Content-Length, поэтому огромный Content-Length не может исчерпать память пода (лимит
# памяти пода составляет 96Mi) и увести его в OOM. Значение с запасом покрывает разумный argv.
MAX_BODY_BYTES = 64 * 1024

# Верхняя граница на число элементов argv и на суммарную длину аргументов в байтах. Защищает от
# распухания как самой команды, так и памяти при её сборке и логировании.
MAX_ARGV_ITEMS = 1024
MAX_ARGV_TOTAL_BYTES = 32 * 1024

# Разумные пределы таймаута исполнения (в секундах): не меньше секунды, не больше десяти минут.
MIN_TIMEOUT = 1
MAX_TIMEOUT = 600

# Таймаут на неактивное соединение сокета (в секундах). Без него неаутентифицированный медленный
# поток соединений (slowloris) исчерпывает пул потоков ThreadingHTTPServer и кладёт сервис.
SOCKET_TIMEOUT = 15

# Префикс nsenter для входа в пространства имён процесса с PID 1 (то есть самого хоста): монтирование
# (m), UTS (u), IPC (i) и сеть (n). Двойной дефис отделяет опции nsenter от исполняемой команды и её
# аргументов, чтобы флаги внутри argv не были ошибочно приняты за флаги nsenter.
NSENTER_PREFIX = ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--"]

# Код возврата, которым помечается превышение таймаута (соглашение утилиты timeout из coreutils).
TIMEOUT_EXIT_CODE = 124

# Флаги, значение которых (следующий за ними элемент argv или часть вида --flag=value) считается
# чувствительным и не выводится в лог в открытом виде. Список консервативен и покрывает
# распространённые способы передать секрет аргументом командной строки.
SENSITIVE_FLAGS = frozenset({
    "-p", "--password", "--pass", "--passwd",
    "--token", "--secret", "--api-key", "--apikey", "--key",
    "--auth", "--credential", "--credentials", "-P",
})
MASK = "***"


def clean_environ() -> dict:
    """Собрать очищенное окружение для исполняемой на хосте команды.

    Дочерний процесс НЕ должен наследовать секреты процесса-агента, прежде всего
    AEGIL_NODEAGENT_TOKEN: иначе любая исполненная на узле команда может прочитать его через
    /proc/self/environ и утечь секрет. Поэтому передаётся минимальное безопасное окружение без
    переменных с префиксом AEGIL_ и без прочих потенциально чувствительных значений.
    """
    safe = {}
    path = os.environ.get("PATH")
    if path:
        safe["PATH"] = path
    # Локаль и терминал безвредны и иногда нужны утилитам для корректного вывода.
    for key in ("LANG", "LC_ALL", "TERM"):
        val = os.environ.get(key)
        if val:
            safe[key] = val
    return safe


def _mask_argv(argv: list) -> list:
    """Вернуть копию argv с замаскированными значениями чувствительных флагов для лога.

    Маскируются: элемент, следующий за чувствительным флагом (например значение после --password), и
    встроенная форма --flag=value, где значение вырезается. Значение argv[0] (сама программа) не
    маскируется. Функция не мутирует исходный список.
    """
    masked = []
    mask_next = False
    for i, item in enumerate(argv):
        if mask_next:
            masked.append(MASK)
            mask_next = False
            continue
        if i == 0:
            masked.append(item)
            continue
        if item in SENSITIVE_FLAGS:
            masked.append(item)
            mask_next = True
            continue
        if item.startswith("--") and "=" in item:
            name = item.split("=", 1)[0]
            if name in SENSITIVE_FLAGS:
                masked.append(name + "=" + MASK)
                continue
        masked.append(item)
    return masked


def log(level: str, msg: str, **fields) -> None:
    """Структурный JSON-лог по канону проекта: ts, level, service, msg плюс поля.

    Сам токен доступа сюда никогда не передаётся. Значения аргументов команды в лог в открытом виде
    не пишутся: логируется только argv[0] и число аргументов, а при необходимости передать сам набор
    он предварительно маскируется вызывающим кодом.
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

    Правила: argv это непустой список строк с ограничением на число элементов (MAX_ARGV_ITEMS) и на
    суммарную длину в байтах (MAX_ARGV_TOTAL_BYTES); timeout это число в пределах
    MIN_TIMEOUT..MAX_TIMEOUT. При нарушении бросается ValueError с русским пояснением, которое
    вызывающий переводит в ответ 400.
    """
    if not isinstance(body, dict):
        raise ValueError("тело запроса должно быть объектом JSON")
    argv = body.get("argv")
    if not isinstance(argv, list) or not argv:
        raise ValueError("поле argv должно быть непустым списком")
    if not all(isinstance(a, str) for a in argv):
        raise ValueError("все элементы argv должны быть строками")
    if len(argv) > MAX_ARGV_ITEMS:
        raise ValueError("поле argv содержит слишком много элементов (не более %d)" % MAX_ARGV_ITEMS)
    total = sum(len(a.encode("utf-8")) for a in argv)
    if total > MAX_ARGV_TOTAL_BYTES:
        raise ValueError("суммарная длина argv превышает допустимую (%d байт)" % MAX_ARGV_TOTAL_BYTES)
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
    не интерпретируются. Инъекция оболочки невозможна конструктивно. Разделитель -- в конце префикса
    отсекает попытку подсунуть в argv флаги самого nsenter: всё, что идёт после --, nsenter трактует
    как исполняемую программу и её аргументы, а не как свои опции.
    """
    return NSENTER_PREFIX + list(argv)


def _kill_process_group(proc: "subprocess.Popen") -> None:
    """Снять всю группу процессов дочернего процесса, а не только его самого.

    Процесс запущен в отдельной сессии (start_new_session=True), поэтому его идентификатор процесса
    совпадает с идентификатором группы. Сначала посылается SIGTERM всей группе, затем, если группа не
    завершилась, SIGKILL. Это не оставляет на хосте порождённых команд сирот процессами
    суперпользователя. Если группа уже исчезла, ProcessLookupError игнорируется.
    """
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def run_host_command(argv: list, timeout: float) -> dict:
    """Исполнить argv в пространстве имён хоста через nsenter и вернуть словарь результата.

    Процесс запускается через subprocess.Popen со списком аргументов (без shell=True) в отдельной
    сессии (start_new_session=True), чтобы при превышении таймаута снималась вся группа процессов, а
    не только прямой потомок: иначе порождённые командой сироты остались бы на хосте процессами
    суперпользователя. Дочернему процессу передаётся очищенное окружение без секретов агента. Вывод в
    любом случае ограничивается по объёму.
    """
    cmd = build_command(argv)
    env = clean_environ()
    started = time.monotonic()
    proc = subprocess.Popen(  # noqa: S603 - список аргументов, без оболочки, инъекция исключена
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        start_new_session=True,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        duration_ms = int((time.monotonic() - started) * 1000)
        result = {
            "exit_code": proc.returncode,
            "stdout": _truncate(out or b""),
            "stderr": _truncate(err or b""),
            "duration_ms": duration_ms,
            "node": NODE_NAME,
        }
    except subprocess.TimeoutExpired:
        # Снимаем ВСЮ группу процессов, а не только прямого потомка, чтобы не осталось сирот.
        _kill_process_group(proc)
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = b"", b""
        duration_ms = int((time.monotonic() - started) * 1000)
        partial_out = _truncate(out or b"")
        partial_err = _truncate(err or b"")
        note = "команда прервана по таймауту %.0f с ...[обрезано по времени]" % timeout
        result = {
            "exit_code": TIMEOUT_EXIT_CODE,
            "stdout": partial_out,
            "stderr": (partial_err + "\n" + note).strip(),
            "duration_ms": duration_ms,
            "node": NODE_NAME,
        }
    # Логируем только имя программы (argv[0]) и число аргументов: полные значения аргументов в лог не
    # пишутся, чтобы секреты, переданные аргументами командной строки, не утекли в хранилище логов.
    log("info", "исполнение команды на узле", program=argv[0], argc=len(argv),
        exit_code=result["exit_code"], duration_ms=result["duration_ms"])
    return result


def token_ok(presented: str) -> bool:
    """Сверить предъявленный токен с секретом за постоянное время (hmac.compare_digest).

    Оба значения приводятся к байтам перед сравнением, поэтому не-ASCII токен не роняет обработчик
    ошибкой TypeError (compare_digest над разнородными строками с не-ASCII символами недопустим).
    Fail-closed: если секрет не задан на сервере или предъявленный токен пуст, доступ запрещён
    всегда, потому что открывать доступ суперпользователя на узле без замка нельзя.
    """
    if not NODEAGENT_TOKEN:
        return False
    if not presented:
        return False
    presented_b = presented.encode("utf-8", "surrogatepass")
    secret_b = NODEAGENT_TOKEN.encode("utf-8", "surrogatepass")
    return hmac.compare_digest(presented_b, secret_b)


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
        # Аутентификация выполняется ДО чтения тела запроса: без совпадения токена возвращаем 401 и не
        # читаем и не исполняем ничего. Сверка вынесена в token_ok, которая приводит оба значения к
        # байтам, поэтому не-ASCII токен не роняет обработчик. Сам токен в лог не попадает.
        presented = self.headers.get("X-NodeAgent-Token", "")
        if not token_ok(presented):
            log("warn", "отказ в доступе к /run без валидного токена")
            self._send_json(401, {"error": "нет доступа"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length < 0:
            length = 0
        # Верхняя граница размера тела: объявленный Content-Length больше лимита сразу отклоняется, и
        # даже при корректном заголовке читается не более MAX_BODY_BYTES байт, поэтому огромное тело
        # не исчерпает память пода.
        if length > MAX_BODY_BYTES:
            self._send_json(413, {"error": "тело запроса превышает допустимый размер"})
            return
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
        log("warn", "AEGIL_NODEAGENT_TOKEN не задан: эндпоинт /run будет fail-closed отклонять все запросы")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    # Таймаут на соединение: обработчик не ждёт медленный поток вечно, поэтому неаутентифицированный
    # slowloris не удерживает потоки бесконечно и не исчерпывает их пул.
    server.timeout = SOCKET_TIMEOUT
    Handler.timeout = SOCKET_TIMEOUT
    log("info", "node-agent запущен", port=PORT)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
