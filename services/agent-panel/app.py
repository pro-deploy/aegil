"""Панель агента kube-sentinel: лёгкий сервис на FastAPI, отдающий одностраничный чат-интерфейс
автономного девопс-агента. Панель наблюдает кластер и узлы, ведёт центр инцидентов и журнал
аудита, а любой запрос оператора на естественном языке исполняет полноценным агентным циклом
языковой модели (agent_exec): модель сама смотрит состояние, выполняет команды на кластере и на
узлах (чтение и безопасный ремонт автономно, финансы и разрушительное через подтверждение) и
объясняет по-русски. Панель наружу не публикуется (ClusterIP без Ingress), вход закрыт токеном
оператора, доступ идёт через закрытый контур.

Конфигурация продукта задаётся переменными окружения с префиксом SENTINEL_ (см. config.py и
docs/CONVENTIONS.md). Единственный обязательный параметр самой панели это SENTINEL_OPERATORS,
аллоу-лист операторов вида «имя:токен,...»: без хотя бы одного оператора панель не поднимается
(fail-closed). Если языковая модель не настроена (нет ключа или адреса), агентный цикл вырождается
в исполнителя одиночной команды оператора без планирования.
"""
from __future__ import annotations

import hmac
import os
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

import agent_exec
import audit
import autopilot
import config
import guards
import incidents
import injection
import k8s
import llm_metrics
import outcomes
import rca_client
import slo
import updater

HELP = (
    "Панель агента kube-sentinel. Пишите запрос на естественном языке, агент сам разберётся.\n"
    "Примеры: «сколько места на узлах и почисти неиспользуемые образы», «покажи упавшие поды»,\n"
    "«перезапусти сервис X», «что происходит в кластере».\n"
    "Команды: /help этот список, /status сводка кластера, /health здоровье панели,\n"
    "/agent состояние агента, /mode observe|safe_repair|full уровень автономии,\n"
    "/report отчёт агента за сутки."
)

# Каталог для палитры интерфейса (ввод «/»). Только инфраструктурные команды продукта, без
# доменных: доменные операции живут во внешнем приложении и вызываются через app_adapter агентом.
COMMAND_CATALOG = [
    {"name": "/help", "desc": "список команд и подсказка", "confirm": False},
    {"name": "/status", "desc": "сводка состояния кластера", "confirm": False},
    {"name": "/health", "desc": "здоровье панели и RCA", "confirm": False},
    {"name": "/agent", "desc": "состояние агента: уровень автономии, бюджет, гарды", "confirm": False},
    {"name": "/mode", "desc": "уровень автономии observe, safe_repair или full", "confirm": False},
    {"name": "/report", "desc": "отчёт агента за сутки", "confirm": False},
]

# Ограничение частоты неудачных входов: защита от перебора токена. Простой счётчик по источнику.
_MAX_AUTH_FAILURES = int(os.getenv("SENTINEL_AUTH_MAX_FAILURES", "10"))
_AUTH_WINDOW_SECONDS = int(os.getenv("SENTINEL_AUTH_WINDOW_SECONDS", "300"))
_auth_failures: dict = {}
_auth_lock = threading.Lock()


def _load_operators() -> dict:
    """Аллоу-лист операторов: каждый входит своим токеном, действие атрибутируется ему в аудите.
    Панель fail-closed: без единого валидного оператора не поднимается, дефолтного пароля нет."""
    ops: dict = {}
    raw = os.getenv("SENTINEL_OPERATORS", "").strip()
    if raw:
        for pair in raw.split(","):
            if ":" not in pair:
                continue
            name, token = pair.split(":", 1)
            name, token = name.strip(), token.strip()
            if name and token:
                ops[token] = name
    return ops


OPERATORS = _load_operators()
if not OPERATORS:
    raise RuntimeError("Задайте SENTINEL_OPERATORS (имя:токен,...): "
                       "панель не запускается без хотя бы одного оператора")
RCA_URL = config.RCA_URL
BASE_DIR = Path(__file__).parent
INDEX_HTML = (BASE_DIR / "index.html").read_text(encoding="utf-8")

app = FastAPI(title="kube-sentinel-panel")


@app.on_event("startup")
def _startup() -> None:
    """Восстановление ленты инцидентов и гардов из журнала (переживают перезапуск) и запуск
    цикла автономного агента: наблюдение источников, диагноз по каталогу алертов, действия по
    плейбукам под детерминированными гардами. В режиме сухого прогона (AGENT_AUTONOMOUS выключен)
    агент только наблюдает и эскалирует."""
    incidents.load()
    guards.load()
    threading.Thread(target=autopilot.run_loop, args=(RCA_URL,), daemon=True).start()


def _source(request: Request) -> str:
    return request.client.host if request.client else "-"


def _rate_limited(src: str, now: float) -> bool:
    """Слишком много неудачных входов с источника за окно: блокируем перебор токена."""
    with _auth_lock:
        count, first = _auth_failures.get(src, (0, now))
        if now - first > _AUTH_WINDOW_SECONDS:
            count, first = 0, now
        return count >= _MAX_AUTH_FAILURES


def _note_auth_failure(src: str, now: float) -> None:
    with _auth_lock:
        count, first = _auth_failures.get(src, (0, now))
        if now - first > _AUTH_WINDOW_SECONDS:
            count, first = 0, now
        _auth_failures[src] = (count + 1, first)


def _auth(request: Request) -> str:
    """Возвращает имя оператора по токену. Сравнение за постоянное время со всеми операторами.
    Неудачные попытки ограничиваются по частоте и пишутся в аудит (обнаружение перебора)."""
    now = time.time()
    src = _source(request)
    if _rate_limited(src, now):
        raise HTTPException(status_code=429, detail="too many failed attempts")
    raw = request.headers.get("authorization", "")
    tok = raw[7:].strip() if raw.lower().startswith("bearer ") else raw.strip()
    matched = ""
    for token, name in OPERATORS.items():
        if tok and hmac.compare_digest(tok, token):
            matched = name
    if not matched:
        _note_auth_failure(src, now)
        audit.audit_write("?", "auth.fail", {"source": src}, "panel", False,
                          "неудачная аутентификация", op_type=audit.OP_READ)
        raise HTTPException(status_code=401, detail="unauthorized")
    with _auth_lock:
        _auth_failures.pop(src, None)  # успешный вход сбрасывает счётчик источника
    return matched


class ChatReq(BaseModel):
    message: str


class ConfirmReq(BaseModel):
    token: str


class ReadReq(BaseModel):
    key: Optional[str] = None


class AgentRunReq(BaseModel):
    message: str


class AgentModeReq(BaseModel):
    mode: str


class UpdateApplyReq(BaseModel):
    confirm: bool = False


@app.get("/")
def index() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML)


@app.get("/manifest.webmanifest")
def manifest() -> FileResponse:
    return FileResponse(BASE_DIR / "manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js")
def service_worker() -> FileResponse:
    return FileResponse(BASE_DIR / "sw.js", media_type="application/javascript")


@app.get("/icon.svg")
def icon() -> FileResponse:
    return FileResponse(BASE_DIR / "icon.svg", media_type="image/svg+xml")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "kube-sentinel-panel"}


def _agent_reply(result: dict) -> dict:
    """Сворачивает трейс агентного цикла в структурированный ответ чата: ответ крупно, выполненные
    команды чипами с тегом узла, точкой статуса и раскрываемым выводом, рассуждение под сноской.
    Отложенные finance и destructive возвращаются карточкой подтверждения."""
    steps = result.get("steps", []) or []
    for s in steps:
        if s.get("outcome") == "pending_confirm" and s.get("confirm_token"):
            return {"type": "confirm", "token": s["confirm_token"],
                    "message": s.get("message", "Требуется подтверждение оператора.")}
    cmds, notes, answer = [], [], ""
    for s in steps:
        st = s.get("step") or s.get("type")
        if st in ("act", "node_cmd"):
            argv = s.get("argv")
            argv = " ".join(argv) if isinstance(argv, list) else str(argv or "")
            res = s.get("result") if isinstance(s.get("result"), dict) else {}
            out = (res.get("stdout") or res.get("detail") or res.get("error") or "").strip()
            ok = (s.get("outcome") in ("executed", None) and not res.get("error")
                  and res.get("exit_code") in (0, None))
            cmds.append({"cmd": argv, "node": s.get("node") or "", "ok": bool(ok),
                         "out": out[:1500], "blocked": s.get("outcome") == "blocked"})
        elif st == "explain" and s.get("text"):
            notes.append(s["text"])
        elif st == "done" and s.get("summary"):
            answer = s["summary"]
        elif st == "error" and s.get("text"):
            notes.append(s["text"])
    if not answer:
        answer = notes[-1] if notes else "Готово."
    return {"type": "agent", "answer": answer, "cmds": cmds, "notes": notes}


@app.post("/chat")
def chat(req: ChatReq, request: Request) -> dict:
    """Главный чат. /help даёт справку, остальное (и команды, и свободный текст) уходит в
    агентный цикл: модель понимает запрос, наблюдает и действует. Никакого каталога фраз."""
    operator = _auth(request)
    m = (req.message or "").strip()
    if not m:
        return {"type": "message", "text": "Пустой запрос. Напишите, что нужно сделать, или /help."}
    if m == "/help":
        return {"type": "message", "text": HELP}
    result = agent_exec.run(m.lstrip("/"), operator)
    return _agent_reply(result)


@app.post("/confirm")
def confirm(req: ConfirmReq, request: Request) -> dict:
    """Подтверждение отложенной команды (finance, destructive или manual safe_write) по
    одноразовому токену. Исполнение через те же гарды и аудит."""
    operator = _auth(request)
    return agent_exec.confirm(req.token, operator)


@app.post("/agent/run")
def agent_run(req: AgentRunReq, request: Request) -> dict:
    operator = _auth(request)
    return agent_exec.run(req.message, operator)


@app.post("/agent/confirm")
def agent_confirm(req: ConfirmReq, request: Request) -> dict:
    operator = _auth(request)
    return agent_exec.confirm(req.token, operator)


@app.post("/agent/mode")
def agent_mode(req: AgentModeReq, request: Request) -> dict:
    _auth(request)
    return {"mode": agent_exec.set_mode(req.mode)}


@app.get("/agent/state")
def agent_state(request: Request) -> dict:
    _auth(request)
    return agent_exec.state_summary()


@app.get("/commands")
def commands_list(request: Request) -> dict:
    _auth(request)
    return {"commands": COMMAND_CATALOG}


# --- Операторская консоль: обзор кластера, ассистент без tool-calling, ремонт кнопкой ---
# Ассистент намеренно НЕ использует протокол вызова инструментов: он опирается на простой
# диалог с моделью и на инъекцию актуального состояния кластера в системную подсказку. Так
# консоль работает даже с моделями без поддержки tool-calling (например gemma в vLLM без
# парсера инструментов), а сами действия по кластеру выполняются детерминированными кнопками
# через RBAC панели, а не догадками модели.

class AskReq(BaseModel):
    message: str
    history: Optional[list] = None


class RestartReq(BaseModel):
    name: str


def _cluster_context() -> str:
    """Компактная сводка состояния кластера для системной подсказки ассистента."""
    lines: list = []
    try:
        groups = incidents.list_groups()
    except Exception:
        groups = []
    if groups:
        lines.append("Активные инциденты:")
        for g in groups[:8]:
            lines.append("- [%s/%s] %s (детекторы: %s, событий: %s)" % (
                g.get("band", ""), g.get("status", ""), g.get("title", ""),
                ",".join(g.get("detectors") or []), g.get("count", 0)))
    else:
        lines.append("Активных инцидентов нет.")
    pods = k8s.list_pods()
    if pods:
        bad = [p for p in pods if p.get("phase") != "Running" or p.get("waiting_reason") or p.get("restarts")]
        lines.append("Проблемные поды:" if bad else "Все поды в норме.")
        for p in bad[:12]:
            reason = p.get("waiting_reason") or ("OOMKilled" if p.get("oom_killed") else p.get("phase"))
            lines.append("- %s: %s, рестартов %s" % (p.get("name"), reason, p.get("restarts")))
    return "\n".join(lines)


@app.get("/overview")
def overview(request: Request) -> dict:
    """Состояние пространства имён для консоли: поды и деплойменты. Только чтение."""
    _auth(request)
    return {
        "namespace": config.NAMESPACE,
        "autonomy": config.autonomy(),
        "pods": k8s.list_pods() or [],
        "deployments": k8s.list_deployments() or [],
    }


@app.post("/ask")
def ask(req: AskReq, request: Request) -> dict:
    """Чат-ассистент SRE. Простой диалог с моделью без инструментов, с инъекцией сводки
    кластера в системную подсказку. Работает с любой OpenAI-совместимой моделью."""
    _auth(request)
    msg = (req.message or "").strip()
    if not msg:
        return {"answer": "Пустой вопрос."}
    if not config.LLM_MODEL:
        return {"answer": "Модель не настроена (SENTINEL_LLM_MODEL пуст)."}
    # Состояние кластера собрано из логов подов, то есть из недоверенного источника: строка лога
    # может содержать инъекцию в подсказку. Заключаем контекст в ограду данных и помечаем попытки
    # инъекции, чтобы модель трактовала его как данные, а не как указания (см. injection.py).
    ctx = injection.sanitize(_cluster_context(), "состояние кластера и логи подов")
    t0 = time.perf_counter()
    try:
        from openai import OpenAI
        client = OpenAI(base_url=(config.LLM_BASE_URL or None),
                        api_key=(config.LLM_API_KEY or "sk-noauth"),
                        timeout=float(config.LLM_TIMEOUT))
        system = ("Ты ассистент SRE в операторской консоли kube-sentinel. Отвечай по-русски, "
                  "кратко и по делу, давай конкретные шаги и команды kubectl. Ниже актуальное "
                  "состояние кластера, опирайся на него как на данные.\n\n" + ctx)
        messages = [{"role": "system", "content": system}]
        for h in (req.history or [])[-6:]:
            role, content = h.get("role"), h.get("content")
            if role in ("user", "assistant") and content:
                messages.append({"role": role, "content": str(content)[:4000]})
        messages.append({"role": "user", "content": msg})
        r = client.chat.completions.create(model=config.LLM_MODEL, messages=messages,
                                           max_tokens=800, temperature=0.3)
        dt = (time.perf_counter() - t0) * 1000.0
        usage = getattr(r, "usage", None)
        llm_metrics.record(config.LLM_MODEL, dt,
                           getattr(usage, "prompt_tokens", 0) or 0,
                           getattr(usage, "completion_tokens", 0) or 0, ok=True)
        return {"answer": (r.choices[0].message.content or "").strip() or "(пустой ответ модели)"}
    except Exception as exc:
        llm_metrics.record(config.LLM_MODEL, (time.perf_counter() - t0) * 1000.0,
                           ok=False, error=str(exc))
        return {"answer": "ошибка обращения к модели: %s" % exc}


@app.post("/action/restart")
def action_restart(req: RestartReq, request: Request) -> dict:
    """Детерминированный перезапуск деплоймента (rollout restart) через RBAC панели. Проверка
    allowlist/denylist в k8s.rollout_restart, аудит факта."""
    operator = _auth(request)
    import datetime as _dt
    now_iso = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    res = k8s.rollout_restart((req.name or "").strip(), now_iso)
    ok, detail = (res if isinstance(res, tuple) else (None, "нет данных"))
    audit.audit_write(operator, "action.restart", {"name": req.name}, req.name or "?",
                      bool(ok), str(detail), op_type=audit.OP_EXECUTE, danger_class="safe_write")
    return {"ok": bool(ok), "detail": detail}


class PodLogsReq(BaseModel):
    pod: str
    lines: int = 120


@app.post("/pod/logs")
def pod_logs(req: PodLogsReq, request: Request) -> dict:
    """Хвост логов пода по имени. Только чтение, для просмотра из консоли."""
    _auth(request)
    pod = (req.pod or "").strip()
    if not k8s._NAME_RE.match(pod):
        return {"ok": False, "message": "неверное имя пода"}
    tail = k8s.pod_log_tail(pod, lines=min(500, max(10, int(req.lines or 120))))
    if tail is None:
        return {"ok": False, "message": "логи недоступны (панель вне кластера или под исчез)"}
    return {"ok": True, "pod": pod, "logs": tail}


@app.get("/slo")
def slo_state(request: Request) -> dict:
    """Состояние целей уровня обслуживания: индикатор, бюджет ошибок, скорость прожигания и
    уровень серьёзности по свежему окну RCA. Доля ошибок берётся из фактов детерминированного
    разбора. Только чтение."""
    _auth(request)
    error_rate = 0.0
    try:
        out = rca_client.analyze(config.RCA_URL, {"use_baseline": False, "minutes": 15})
        error_rate = float((out.get("facts", {}) or {}).get("error_rate", 0.0) or 0.0)
    except Exception:
        pass
    return slo.summary(error_rate)


@app.get("/llm/metrics")
def llm_metrics_state(request: Request) -> dict:
    """Наблюдаемость инференса модели: задержки, токены, стоимость, доля ошибок и дрейф. Только
    чтение (слой LLMOps)."""
    _auth(request)
    return llm_metrics.summary()


@app.get("/update/check")
def update_check(request: Request) -> dict:
    """Проверка канала самообновления: текущая и доступная версия продукта. Только чтение."""
    _auth(request)
    return updater.check()


@app.post("/update/apply")
def update_apply(req: UpdateApplyReq, request: Request) -> dict:
    """Применение обновления. Высокорисковая операция: выполняется ТОЛЬКО при явном подтверждении
    владельца (confirm=true), автономно никогда. Факт применения пишется в аудит."""
    operator = _auth(request)
    res = updater.apply(bool(req.confirm), operator)
    if req.confirm:
        audit.audit_write(operator, "update.apply", {"confirm": True}, "panel",
                          True, str(res.get("message") or res.get("deployments") or res),
                          op_type=audit.OP_EXECUTE, danger_class="destructive")
    return res


def _incident_pod(g: dict) -> str | None:
    v = g.get("last_verdict") or {}
    params = v.get("params") or {}
    pod = params.get("pod")
    if pod and k8s._NAME_RE.match(str(pod)):
        return str(pod)
    return None


def _action_hints(g: dict) -> list:
    if g.get("lifecycle") != "escalated":
        return []
    hints = []
    pod = _incident_pod(g)
    if pod:
        hints.append({"action": "logs", "label": "Показать логи", "pod": pod})
    if g.get("last_verdict"):
        hints.append({"action": "details", "label": "Подробности"})
    return hints


@app.get("/incidents")
def incidents_list(request: Request) -> dict:
    _auth(request)
    groups = incidents.list_groups()
    for g in groups:
        hints = _action_hints(g)
        if hints:
            g["action_hints"] = hints
    return {"groups": groups, "unread": incidents.unread_count()}


@app.post("/incidents/logs")
def incidents_logs(req: ReadReq, request: Request) -> dict:
    _auth(request)
    g = incidents.get_group(str(req.key or ""))
    if not g:
        return {"ok": False, "message": "Инцидент не найден."}
    pod = _incident_pod(g)
    if not pod:
        return {"ok": False, "message": "Виновный под неизвестен для этого инцидента."}
    tail = k8s.pod_log_tail(pod, lines=100)
    if tail is None:
        return {"ok": False, "message": "Логи недоступны (панель вне кластера или под исчез)."}
    return {"ok": True, "pod": pod, "logs": tail}


@app.post("/incidents/ack")
def incidents_ack(req: ReadReq, request: Request) -> dict:
    operator = _auth(request)
    g = incidents.acknowledge(req.key or "", operator)
    if not g:
        return {"ok": False, "message": "Инцидент не найден."}
    incidents.mark_read(req.key)
    return {"ok": True, "lifecycle": g["lifecycle"], "unread": incidents.unread_count()}


@app.post("/incidents/read")
def incidents_read(req: ReadReq, request: Request) -> dict:
    _auth(request)
    incidents.mark_read(req.key)
    return {"unread": incidents.unread_count()}


def _run_incident_agent(key: str, operator: str) -> dict:
    """Общий путь кнопок «Решить» и «Разобрать»: запускает агентный цикл над вердиктом инцидента
    (расследование плюс безопасный ремонт), пишет ход в ленту и возвращает трейс. В продукте
    «Решить» больше не сваливает на оператора «ручную очистку», а действительно устраняет."""
    g = incidents.get_group(key or "")
    if not g:
        return {"ok": False, "message": "Инцидент не найден."}
    verdict = g.get("last_verdict") or {}
    trace = agent_exec.investigate(verdict, operator=operator)
    steps = trace.get("steps") or []
    done = [s.get("summary", "") for s in steps if s.get("step") == "done" and s.get("summary")]
    executed = sum(1 for s in steps if s.get("outcome") == "executed")
    pending = [s for s in steps if s.get("outcome") in ("pending_confirm", "proposed")]
    summary = done[-1] if done else "агент собрал факты по инциденту"
    note = (f"Разбор оператором «{operator}»: {summary}. Выполнено действий: {executed}. "
            f"На подтверждение: {len(pending)}.")
    incidents.add_note(key or "", operator, note)
    if executed and not pending:
        incidents.resolve_operator(key or "", operator, "agent")
        # Замыкание активного обучения: успешно устранённый инцидент становится размеченным
        # примером (вердикт плюс действие плюс исход) для дообучения маршрутизатора.
        outcomes.record(verdict, summary, resolved=True)
    incidents.mark_read(key)
    return {"ok": True, "trace": trace, "mode": trace.get("mode"),
            "unread": incidents.unread_count()}


@app.post("/incidents/solve")
def incidents_solve(req: ReadReq, request: Request) -> dict:
    """Кнопка «Решить»: в продукте идёт тем же агентным путём, что и «Разобрать» (расследование
    плюс безопасный ремонт), а не узким каталогом. Так «Решить» реально устраняет причину."""
    operator = _auth(request)
    return _run_incident_agent(req.key or "", operator)


@app.post("/incidents/investigate")
def incidents_investigate(req: ReadReq, request: Request) -> dict:
    """Кнопка «Разобрать»: агентный цикл над вердиктом инцидента (расследование плюс ремонт)."""
    operator = _auth(request)
    return _run_incident_agent(req.key or "", operator)


@app.post("/incidents/purge-noise")
def incidents_purge_noise(request: Request) -> dict:
    operator = _auth(request)
    res = incidents.purge_noise(operator)
    return {"ok": True, "purged": res["purged"], "ids": res["ids"],
            "unread": incidents.unread_count()}
