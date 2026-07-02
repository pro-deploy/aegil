"""Панель агента kube-sentinel: лёгкий сервис на FastAPI, отдающий одностраничный чат-интерфейс
автономного девопс-агента. Панель наблюдает кластер и узлы, ведёт центр инцидентов и журнал
аудита, а любой запрос оператора на естественном языке исполняет полноценным агентным циклом
языковой модели (agent_exec): модель сама смотрит состояние, выполняет команды на кластере и на
узлах (чтение и безопасный ремонт автономно, финансы и разрушительное через подтверждение) и
объясняет по-русски. Панель наружу не публикуется (ClusterIP без Ingress), вход закрыт токеном
оператора, доступ идёт через закрытый контур.

ENV:
  PANEL_OPERATORS   аллоу-лист операторов «имя:токен,...» (или PANEL_TOKEN плюс PANEL_OPERATOR)
  RCA_URL           адрес сервиса разбора логов (см. config.py)
  LLM_SERVICE_URL   адрес языковой модели (см. llm.py)
  PANEL_HOST        интерфейс прослушивания (default: 127.0.0.1, только localhost/туннель)
  PANEL_NO_LLM=1    принудительный фолбэк без планирования (одна команда оператора)
"""
from __future__ import annotations

import hmac
import os
import threading
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

import agent_exec
import autopilot
import config
import guards
import incidents
import k8s
import llm

HELP = (
    "Панель агента kube-sentinel. Пишите запрос на естественном языке, агент сам разберётся.\n"
    "Примеры: «сколько места на узлах и почисти неиспользуемые образы», «покажи упавшие поды»,\n"
    "«перезапусти сервис X», «что происходит в кластере».\n"
    "Команды: /help этот список, /status сводка кластера, /health здоровье панели,\n"
    "/agent состояние агента, /mode auto|manual режим, /report отчёт агента за сутки."
)

# Каталог для палитры интерфейса (ввод «/»). Только инфраструктурные команды продукта, без
# доменных: доменные операции живут во внешнем приложении и вызываются через app_adapter агентом.
COMMAND_CATALOG = [
    {"name": "/help", "desc": "список команд и подсказка", "confirm": False},
    {"name": "/status", "desc": "сводка состояния кластера", "confirm": False},
    {"name": "/health", "desc": "здоровье панели и RCA", "confirm": False},
    {"name": "/agent", "desc": "состояние агента: режим, бюджет, гарды", "confirm": False},
    {"name": "/mode", "desc": "переключить режим auto или manual", "confirm": False},
    {"name": "/report", "desc": "отчёт агента за сутки", "confirm": False},
]


def _load_operators() -> dict:
    """Аллоу-лист операторов: каждый входит своим токеном, действие атрибутируется ему в аудите.
    Панель fail-closed: без единого валидного оператора не поднимается, дефолтного пароля нет."""
    ops: dict = {}
    raw = os.getenv("PANEL_OPERATORS", os.getenv("ADMINCHAT_OPERATORS", "")).strip()
    if raw:
        for pair in raw.split(","):
            if ":" not in pair:
                continue
            name, token = pair.split(":", 1)
            name, token = name.strip(), token.strip()
            if name and token:
                ops[token] = name
    single = os.getenv("PANEL_TOKEN", os.getenv("ADMINCHAT_TOKEN", "")).strip()
    if single:
        ops[single] = os.getenv("PANEL_OPERATOR", "operator")
    return ops


OPERATORS = _load_operators()
if not OPERATORS:
    raise RuntimeError("Задайте PANEL_OPERATORS (имя:токен,...) или PANEL_TOKEN: "
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


def _auth(request: Request) -> str:
    """Возвращает имя оператора по токену. Сравнение за постоянное время со всеми операторами."""
    raw = request.headers.get("authorization", "")
    tok = raw[7:].strip() if raw.lower().startswith("bearer ") else raw.strip()
    matched = ""
    for token, name in OPERATORS.items():
        if tok and hmac.compare_digest(tok, token):
            matched = name
    if not matched:
        raise HTTPException(status_code=401, detail="unauthorized")
    return matched


def _agent_llm():
    """Функция завершения модели для агентного цикла либо None (фолбэк без планирования)."""
    if os.getenv("PANEL_NO_LLM", os.getenv("ADMINCHAT_AGENT_NO_LLM", "")).strip() in ("1", "true", "yes"):
        return None
    return llm.complete


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
    result = agent_exec.run(m.lstrip("/"), operator, llm_complete=_agent_llm())
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
    return agent_exec.run(req.message, operator, llm_complete=_agent_llm())


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
    trace = agent_exec.investigate(verdict, operator=operator, llm_complete=_agent_llm())
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
