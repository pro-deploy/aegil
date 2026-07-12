"""Сервис детерминированного анализа первопричин kube-sentinel.

Принимает окно логов (напрямую в теле запроса или через чтение из Loki), прогоняет
детерминированное ядро (агрегатор фактов, каталог детекторов, байесовский скоринг,
сборку вердикта с гардами) и возвращает вердикт по пятиполевой схеме. Языковая
модель здесь не считает и не выдумывает: она подключается на краях, для разбора
запроса инженера и для формулировки отчёта по уже посчитанным фактам, и её вывод
проходит гард заземления.

Вся конфигурация вынесена под единый префикс SENTINEL_. Обращение к Loki обёрнуто:
недоступность источника отдаётся вызывающему как осмысленный код 502 с пояснением,
а не как голый отказ сервера. Таймауты обращения к Loki и к языковой модели заданы
раздельно и настраиваются окружением.
"""
from __future__ import annotations

import json as _json
import logging as _logging
import os
import time
import time as _time
from contextvars import ContextVar
from typing import List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import metrics
import setfit_model
import store
from aggregator import aggregate
from cache import BoundedCache
from cascade import classify_and_learn
from loki import DEFAULT_QUERY, LokiError, fetch_window
from pipeline import analyze
from report import formulate

app = FastAPI(title="kube-sentinel-rca")

_SERVICE = "rca"
_trace_ctx: ContextVar = ContextVar("trace_id", default="")


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


# Базовая линия берётся тем же окном со сдвигом назад (по умолчанию на неделю).
BASELINE_LAG_HOURS = int(os.getenv("SENTINEL_RCA_BASELINE_LAG_HOURS", "168"))

# Адрес языковой модели для формулировки отчёта (модель только облекает факты в текст).
LLM_URL = os.getenv("SENTINEL_LLM_BASE_URL", "http://llm:9102").rstrip("/")
# Раздельный таймаут обращения к языковой модели (генерация дольше, чем чтение логов).
LLM_TIMEOUT = float(os.getenv("SENTINEL_LLM_TIMEOUT", "120"))


def _llm_complete(prompt: str) -> str:
    with httpx.Client(timeout=LLM_TIMEOUT) as c:
        r = c.post(f"{LLM_URL}/completion", json={"prompt": prompt})
        r.raise_for_status()
        return r.json().get("text", "")


# Обученный классификатор маршрутизации, если готов; иначе каскад падёт на фолбэк.
_setfit = setfit_model.load()

# Кэш базовой линии: она меняется медленно, поэтому кэшируем окно на час, чтобы не
# запрашивать хранилище логов на каждый разбор. Тревога при заполнении логируется.
_baseline_cache = BoundedCache(
    capacity=int(os.getenv("SENTINEL_RCA_BASELINE_CACHE_CAP", "32")),
    ttl_seconds=float(os.getenv("SENTINEL_RCA_BASELINE_CACHE_TTL", "3600")),
    on_alarm=lambda n, cap: _trace_log.warning(
        "baseline cache near full", extra={"fields": {"event": "cache.alarm", "size": n, "cap": cap}}),
)


class AnalyzeReq(BaseModel):
    records: Optional[List[dict]] = None   # окно логов напрямую (для тестов и интеграций)
    baseline: Optional[List[dict]] = None  # базовое окно напрямую
    query: Optional[str] = None            # селектор LogQL, если читаем из Loki
    minutes: int = 60                      # ширина окна
    use_baseline: bool = True              # тянуть базовую линию со сдвигом назад
    delta: float = 1.0                     # коэффициент полноты данных
    formulate: bool = False                # облечь вердикт в отчёт языковой моделью
    metrics: Optional[dict] = None         # факты метрик окна напрямую (для тестов и интеграций)
    baseline_metrics: Optional[dict] = None  # факты метрик базовой линии напрямую
    use_metrics: bool = False              # читать метрики золотых сигналов из Prometheus


class RouteReq(BaseModel):
    query: str


class OutcomeReq(BaseModel):
    fingerprint: str                       # отпечаток симптома разрешённого инцидента
    status: Optional[str] = None           # статус вердикта на момент ремонта
    root_cause: Optional[str] = None       # диагностированная первопричина
    action: Optional[str] = None           # применённое действие ремонта
    resolved: bool = True                  # был ли инцидент фактически устранён


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": _SERVICE}


@app.post("/route")
def route_endpoint(req: RouteReq) -> dict:
    """Маршрутизация запроса инженера с активным обучением: обученный классификатор,
    при неуверенности эскалация к большой модели с записью примера, иначе ключевой
    фолбэк."""
    branches, source = classify_and_learn(
        req.query, setfit=_setfit, llm_complete=_llm_complete, recorder=store.record_example)
    _trace_log.info("route", extra={"fields": {
        "event": "rca.route", "branches": ",".join(branches), "source": source}})
    return {"query": req.query, "branches": branches, "source": source}


@app.post("/reload-model")
def reload_model() -> dict:
    """Перезагружает обученную модель маршрутизации после выгрузки тренером."""
    global _setfit
    _setfit = setfit_model.load()
    return {"loaded": _setfit is not None}


@app.post("/outcome")
def outcome_endpoint(req: OutcomeReq) -> dict:
    """Запись исхода ремонта: замыкает контур активного обучения на фактических результатах
    устранения инцидентов. Успешно устранённый инцидент фиксируется как размеченный пример
    для последующего дообучения. При недоступности Postgres отвечает осмысленным кодом 502,
    а не голым отказом сервера и не падением."""
    from store import DSN, record_outcome

    if not DSN:
        raise HTTPException(status_code=502, detail="хранилище исходов недоступно: SENTINEL_POSTGRES_DSN не задан")
    try:
        ok = record_outcome(DSN, req.fingerprint, req.status, req.root_cause, req.action, req.resolved)
    except Exception as exc:  # защита от неожиданного сбоя драйвера базы данных
        _trace_log.warning("outcome store unavailable", extra={"fields": {
            "event": "rca.outcome_error", "error": str(exc)}})
        raise HTTPException(status_code=502, detail=f"хранилище исходов недоступно: {exc}")
    if not ok:
        raise HTTPException(status_code=502, detail="хранилище исходов недоступно: исход не сохранён")
    _trace_log.info("outcome", extra={"fields": {
        "event": "rca.outcome", "fingerprint": req.fingerprint,
        "status": req.status, "resolved": req.resolved}})
    return {"recorded": True, "fingerprint": req.fingerprint, "resolved": req.resolved}


@app.get("/outcomes/stats")
def outcomes_stats_endpoint() -> dict:
    """Сводка по накопленным исходам ремонтов для наблюдаемости (всего, устранено, неустранено).
    При недоступности Postgres возвращает нулевую сводку с пометкой недоступности, а не отказ,
    чтобы опрос наблюдаемости не падал."""
    from store import outcomes_stats as _stats

    return _stats(store.DSN)


def _read_window(query: str, minutes: int, use_baseline: bool):
    """Читает окно и, при необходимости, базовую линию из Loki. Ошибку источника
    поднимает как LokiError, чтобы обработчик отдал осмысленный код, а не голый 500."""
    records = fetch_window(query, minutes=minutes)
    baseline = None
    if use_baseline:
        baseline = _baseline_cache.get(query)
        if baseline is None:
            baseline = fetch_window(query, minutes=minutes,
                                    end=time.time() - BASELINE_LAG_HOURS * 3600)
            _baseline_cache.set(query, baseline)
    return records, baseline


@app.post("/analyze")
def analyze_endpoint(req: AnalyzeReq) -> dict:
    if req.records is not None:
        records = req.records
        baseline = req.baseline
    else:
        query = req.query or DEFAULT_QUERY
        try:
            records, baseline = _read_window(query, req.minutes, req.use_baseline)
        except LokiError as exc:
            _trace_log.warning("loki unavailable", extra={"fields": {
                "event": "rca.loki_error", "error": str(exc)}})
            raise HTTPException(status_code=502, detail=f"источник логов недоступен: {exc}")

    # Метрики золотых сигналов: напрямую из тела либо чтением из Prometheus (мягкая деградация,
    # при недоступности хранилища анализ логов продолжается без метрик).
    metric_facts = req.metrics
    if metric_facts is None and (req.use_metrics or metrics.PROM_URL):
        metric_facts = metrics.fetch(minutes=req.minutes)

    out = analyze(records, baseline=baseline, delta=req.delta,
                  metric_facts=metric_facts, baseline_metric_facts=req.baseline_metrics)
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
