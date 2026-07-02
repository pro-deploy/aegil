"""Сервис детерминированного анализа RCA (ADR-0032, Часть B). Принимает окно логов
(напрямую или через чтение из Loki), прогоняет детерминированное ядро
(агрегатор фактов, детекторы D1-D12, байесовский скоринг, сборку вердикта с
гардами) и возвращает вердикт по пятиполевой схеме. Языковая модель здесь не
участвует: она подключается на краях отдельно. Сервис сам логирует по канону
(структурный JSON, service=rca, trace_id).

ENV:
  LOKI_URL    (default: http://loki:3100)   — адрес хранилища логов
  LOKI_QUERY  (default: {namespace="krokki"}) — селектор LogQL по умолчанию
"""
from __future__ import annotations

import os
import time

import httpx
from fastapi import FastAPI
from pydantic import BaseModel

import setfit_model
import store
import stuck as stuckmod
from aggregator import aggregate
from cache import BoundedCache
from cascade import classify_and_learn
from loki import DEFAULT_QUERY, fetch_window
from pipeline import analyze
from report import formulate

app = FastAPI(title="krokki-rca")

# Структурный JSON-лог по канону (ADR-0032): ts, level, service, msg, trace_id.
import json as _json
import logging as _logging
import time as _time
from contextvars import ContextVar

_SERVICE = "rca"
_trace_ctx: ContextVar[str] = ContextVar("trace_id", default="")


class _JsonFormatter(_logging.Formatter):
    def format(self, record: _logging.LogRecord) -> str:
        ct = record.created
        obj = {
            "ts": _time.strftime("%Y-%m-%dT%H:%M:%S", _time.gmtime(ct)) + ".%03dZ" % int((ct % 1) * 1000),
            "level": {"warning": "warn", "critical": "fatal"}.get(record.levelname.lower(), record.levelname.lower()),
            "service": _SERVICE,
            "msg": record.getMessage(),
        }
        tid = _trace_ctx.get()
        if tid:
            obj["trace_id"] = tid
        for _k, _v in getattr(record, "fields", {}).items():
            obj[_k] = _v
        if record.exc_info:
            obj["error"] = self.formatException(record.exc_info)
        return _json.dumps(obj, ensure_ascii=False)


def _setup_logging() -> None:
    _handler = _logging.StreamHandler()
    _handler.setFormatter(_JsonFormatter())
    _root = _logging.getLogger()
    _root.handlers[:] = [_handler]
    _root.setLevel(_logging.INFO)


_setup_logging()
_trace_log = _logging.getLogger(_SERVICE)


def _trace_id(request) -> str:
    tid = request.headers.get("x-trace-id", "")
    if not tid:
        parts = request.headers.get("traceparent", "").split("-")
        if len(parts) >= 2 and len(parts[1]) == 32:
            tid = parts[1]
    return tid


@app.middleware("http")
async def _trace_mw(request, call_next):
    token = _trace_ctx.set(_trace_id(request))
    try:
        response = await call_next(request)
        tid = _trace_ctx.get()
        if tid:
            response.headers["X-Trace-Id"] = tid
        return response
    finally:
        _trace_ctx.reset(token)


# baseline берётся тем же окном со сдвигом назад на неделю (глава 7).
BASELINE_LAG_HOURS = 168

# Адрес llm-сервиса для формулировки отчёта (модель только облекает факты в текст).
LLM_URL = os.getenv("LLM_SERVICE_URL", "http://llm:9102").rstrip("/")


def _llm_complete(prompt: str) -> str:
    with httpx.Client(timeout=120.0) as c:
        r = c.post(f"{LLM_URL}/completion", json={"prompt": prompt})
        r.raise_for_status()
        return r.json().get("text", "")


# Обученный классификатор маршрутизации, если готов; иначе каскад падёт на фолбэк.
_setfit = setfit_model.load()

# Кэш baseline: он меняется медленно, поэтому кэшируем окно на час, чтобы не
# запрашивать хранилище логов на каждый разбор. Тревога при заполнении логируется.
_baseline_cache = BoundedCache(
    capacity=32, ttl_seconds=3600,
    on_alarm=lambda n, cap: _trace_log.warning(
        "baseline cache near full", extra={"fields": {"event": "cache.alarm", "size": n, "cap": cap}}),
)


class AnalyzeReq(BaseModel):
    records: list[dict] | None = None      # окно логов напрямую (для тестов/интеграций)
    baseline: list[dict] | None = None     # baseline-окно напрямую
    query: str | None = None               # селектор LogQL, если читаем из Loki
    minutes: int = 60                      # ширина окна
    use_baseline: bool = True              # тянуть baseline со сдвигом на неделю
    delta: float = 1.0                     # коэффициент полноты данных
    formulate: bool = False                # облечь вердикт в отчёт языковой моделью


class RouteReq(BaseModel):
    query: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": _SERVICE}


@app.post("/route")
def route_endpoint(req: RouteReq) -> dict:
    """Маршрутизация запроса инженера с активным обучением (route_triage): SetFit,
    при неуверенности эскалация к Gemma 4 с записью примера, иначе ключевой фолбэк."""
    branches, source = classify_and_learn(
        req.query, setfit=_setfit, llm_complete=_llm_complete, recorder=store.record_example)
    _trace_log.info("route", extra={"fields": {
        "event": "rca.route", "branches": ",".join(branches), "source": source}})
    return {"query": req.query, "branches": branches, "source": source}


@app.post("/reload-model")
def reload_model() -> dict:
    """Перезагружает обученную модель маршрутизации (после выгрузки тренером в S3)."""
    global _setfit
    _setfit = setfit_model.load()
    return {"loaded": _setfit is not None}


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeReq) -> dict:
    if req.records is not None:
        records = req.records
        baseline = req.baseline
    else:
        q = req.query or DEFAULT_QUERY
        records = fetch_window(q, minutes=req.minutes)
        baseline = None
        if req.use_baseline:
            baseline = _baseline_cache.get(q)
            if baseline is None:
                baseline = fetch_window(q, minutes=req.minutes, end=time.time() - BASELINE_LAG_HOURS * 3600)
                _baseline_cache.set(q, baseline)
    out = analyze(records, baseline=baseline, delta=req.delta)
    if req.formulate:
        out["report"] = formulate(out["verdict"], out["facts"], _llm_complete)
    v = out["verdict"]
    _trace_log.info("analyze", extra={"fields": {
        "event": "rca.analyze",
        "lines": out["facts"]["total_lines"],
        "status": v["status"],
        "band": v["confidence"]["band"],
    }})
    return out


POSTGRES_DSN = os.getenv("POSTGRES_DSN", "")


def _service_note(service: str) -> str:
    """Уточняет, что с сервисом-тормозом: сыпет ошибками или тихо завис. Читает недавнее окно
    логов из Loki и смотрит ошибки именно этого сервиса. Best-effort: без Loki возвращает пусто."""
    try:
        recs = fetch_window(DEFAULT_QUERY, minutes=30)
        f = aggregate(recs)
    except Exception:
        return ""
    errs = (f.get("by_service_errors", {}) or {}).get(service, 0)
    if errs:
        sigs = ", ".join(sorted((f.get("error_signals", {}) or {}))) or "см. логи"
        return f"Сервис {service} сыпет ошибками ({errs} за 30 мин: {sigs})."
    return (f"У сервиса {service} ошибок в логах нет: он завис или перегружен и не завершает "
            f"стадию (тихий простой).")


@app.post("/stuck")
def stuck_endpoint() -> dict:
    """Ищет застрявшие в обработке задания и собирает по ним вердикт для центра инцидентов.
    Долгий простой это инцидент, даже без ошибок в логах: конвейер не движется."""
    items = stuckmod.find_stuck(POSTGRES_DSN)
    note = ""
    if items:
        # Сервис-тормоз доминирующей группы: по нему уточняем причину по логам.
        groups: dict = {}
        for s in items:
            groups[s["service"]] = groups.get(s["service"], 0) + 1
        svc = max(groups, key=groups.get)
        note = _service_note(svc)
    v = stuckmod.build_verdict(items, service_note=note)
    _trace_log.info("stuck", extra={"fields": {
        "event": "rca.stuck", "count": len(items), "status": v["status"]}})
    return v
