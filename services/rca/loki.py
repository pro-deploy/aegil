"""Читатель окна логов из Loki для анализатора RCA (ADR-0032, Часть B). Забирает
строки за окно через query_range, разбирает JSON-конверт канона в записи и
сохраняет исходную строку в поле _raw для дословных цитат в реестре свидетельств.
Адрес Loki берётся из LOKI_URL.
"""
from __future__ import annotations

import json
import os
import time

import httpx

LOKI_URL = os.getenv("LOKI_URL", "http://loki:3100").rstrip("/")
DEFAULT_QUERY = os.getenv("LOKI_QUERY", '{namespace="krokki"}')


def _parse(line: str) -> dict:
    """Разбирает строку лога: JSON-конверт канона в запись, иначе сырьё как msg.
    Исходная строка кладётся в _raw для дословного цитирования (гард главы 9)."""
    try:
        obj = json.loads(line)
        if isinstance(obj, dict):
            obj["_raw"] = line
            return obj
    except (ValueError, TypeError):
        pass
    return {"msg": line, "_raw": line, "level": "info", "service": "unknown"}


def fetch_window(query: str = DEFAULT_QUERY, minutes: int = 60, limit: int = 5000,
                 end: float | None = None) -> list[dict]:
    """Возвращает записи за окно [end-minutes, end], отсортированные по времени.
    end это Unix-время в секундах (по умолчанию текущее). Для baseline подаётся
    end со сдвигом назад (например на сто шестьдесят восемь часов, глава 7)."""
    end_ns = int((end if end is not None else time.time()) * 1e9)
    start_ns = end_ns - int(minutes * 60 * 1e9)
    params = {
        "query": query,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": str(limit),
        "direction": "forward",
    }
    with httpx.Client(timeout=30.0) as c:
        r = c.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params)
        r.raise_for_status()
        data = r.json()
    records: list[dict] = []
    for stream in data.get("data", {}).get("result", []):
        for _ts_ns, line in stream.get("values", []):
            records.append(_parse(line))
    records.sort(key=lambda rec: str(rec.get("ts", "")))
    return records
