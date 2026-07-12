"""Наблюдаемость инференса языковой модели (слой LLMOps) для kube-sentinel.

Автономный агент опирается на языковую модель, поэтому сама модель это часть
эксплуатируемой системы, и её надо наблюдать так же строго, как сервисы. Модуль
инструментирует каждый вызов модели и ведёт детерминированную статистику: задержку
ответа, число токенов подсказки и ответа, оценочную стоимость, долю ошибок и признак
дрейфа задержки (сравнение свежего окна вызовов с предыдущим). Это отвечает на
эксплуатационные вопросы: не деградировала ли модель по скорости, во сколько обходятся
токены, часто ли отказывает провайдер.

Состояние персистентно и живёт вне рабочего дерева агента (каталог данных
SENTINEL_STATE_DIR, файл переопределяется переменной SENTINEL_LLM_METRICS), как и прочие
журналы продукта, чтобы статистика переживала перезапуск и не попадала под удаление
детерминированным классификатором. Модуль потокобезопасен: обработчики FastAPI и
автопилот пишут метрики параллельно под единой реентерабельной блокировкой. При
недоступности каталога данных модуль откатывается на временный каталог и не мешает работе.

Стоимость токенов настраивается окружением (SENTINEL_LLM_COST_PROMPT и
SENTINEL_LLM_COST_COMPLETION, цена за тысячу токенов); для локальной модели она нулевая,
и тогда наблюдается только скорость и надёжность, а не деньги.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from pathlib import Path

_LOCK = threading.RLock()
_BUFFER: list = []          # окно последних записей в памяти
_LOADED = False

MAX_RECORDS = int(os.getenv("SENTINEL_LLM_METRICS_MAX", "2000"))
RETENTION_SECONDS = int(os.getenv("SENTINEL_LLM_METRICS_RETENTION_SECONDS", str(24 * 3600)))


def _cost_per_1k(name: str) -> float:
    try:
        return float(os.getenv(name, "0"))
    except (TypeError, ValueError):
        return 0.0


def _path() -> Path:
    explicit = os.getenv("SENTINEL_LLM_METRICS")
    if explicit:
        return Path(explicit)
    return Path(os.getenv("SENTINEL_STATE_DIR", "/data")) / "llm-metrics.log.jsonl"


def _writable_path() -> Path:
    p = _path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        return p
    except OSError:
        return Path(tempfile.gettempdir()) / "sentinel-llm-metrics.log.jsonl"


def _load(now: float) -> None:
    global _LOADED
    if _LOADED:
        return
    _LOADED = True
    try:
        with _writable_path().open("r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if now - rec.get("ts", 0) <= RETENTION_SECONDS:
                    _BUFFER.append(rec)
    except OSError:
        pass
    if len(_BUFFER) > MAX_RECORDS:
        del _BUFFER[:-MAX_RECORDS]


def record(model: str, latency_ms: float, prompt_tokens: int = 0, completion_tokens: int = 0,
           ok: bool = True, error: str = "", now: float | None = None) -> dict:
    """Регистрирует один вызов модели. Возвращает записанную строку. Стоимость считается по
    ценам за тысячу токенов из окружения (нуль для локальной модели)."""
    now = time.time() if now is None else now
    pt, ct = int(prompt_tokens or 0), int(completion_tokens or 0)
    cost = (pt / 1000.0) * _cost_per_1k("SENTINEL_LLM_COST_PROMPT") + \
           (ct / 1000.0) * _cost_per_1k("SENTINEL_LLM_COST_COMPLETION")
    rec = {"ts": round(now, 3), "model": str(model or ""), "latency_ms": round(float(latency_ms or 0), 1),
           "prompt_tokens": pt, "completion_tokens": ct, "cost": round(cost, 6),
           "ok": bool(ok), "error": str(error or "")[:200]}
    with _LOCK:
        _load(now)
        _BUFFER.append(rec)
        if len(_BUFFER) > MAX_RECORDS:
            del _BUFFER[:-MAX_RECORDS]
        try:
            with _writable_path().open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except OSError:
            pass
    return rec


def _pct(values: list, q: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    idx = int(round(q * (len(s) - 1)))
    return s[idx]


def summary(now: float | None = None) -> dict:
    """Сводная статистика инференса за окно удержания: число вызовов, доля ошибок, задержки
    (медиана, 95-й перцентиль, среднее), токены, стоимость, пропускная способность и признак
    дрейфа задержки (среднее свежей половины окна против предыдущей)."""
    now = time.time() if now is None else now
    with _LOCK:
        _load(now)
        recs = [r for r in _BUFFER if now - r.get("ts", 0) <= RETENTION_SECONDS]
    if not recs:
        return {"calls": 0, "error_rate": 0.0, "latency_p50_ms": 0.0, "latency_p95_ms": 0.0,
                "latency_avg_ms": 0.0, "prompt_tokens": 0, "completion_tokens": 0,
                "cost_total": 0.0, "tokens_per_min": 0.0, "latency_drift": 0.0}
    lat = [r["latency_ms"] for r in recs]
    errors = sum(1 for r in recs if not r.get("ok"))
    pt = sum(r.get("prompt_tokens", 0) for r in recs)
    ct = sum(r.get("completion_tokens", 0) for r in recs)
    cost = sum(r.get("cost", 0.0) for r in recs)
    span_min = max((recs[-1]["ts"] - recs[0]["ts"]) / 60.0, 1 / 60.0)
    # Дрейф задержки: среднее по свежей половине вызовов против предыдущей. Положительное
    # значение означает замедление модели, отрицательное ускорение.
    half = len(lat) // 2
    drift = 0.0
    if half >= 1 and len(lat) >= 4:
        older = sum(lat[:half]) / half
        newer = sum(lat[half:]) / (len(lat) - half)
        drift = round(newer - older, 1)
    return {
        "calls": len(recs),
        "error_rate": round(errors / len(recs), 4),
        "latency_p50_ms": round(_pct(lat, 0.5), 1),
        "latency_p95_ms": round(_pct(lat, 0.95), 1),
        "latency_avg_ms": round(sum(lat) / len(lat), 1),
        "prompt_tokens": pt,
        "completion_tokens": ct,
        "cost_total": round(cost, 4),
        "tokens_per_min": round((pt + ct) / span_min, 1),
        "latency_drift": drift,
    }


def reset() -> None:
    """Сбрасывает окно в памяти (для тестов и ручной очистки метрик сессии)."""
    global _LOADED
    with _LOCK:
        _BUFFER.clear()
        _LOADED = True
