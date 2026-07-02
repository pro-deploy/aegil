"""Неизменяемый журнал аудита действий оператора (ADR-0033). Append-only, одна строка
это один канонический JSON-объект (тот же канон, что и остальные логи KROKKI, ADR-0032),
поэтому действия супер-администратора сами становятся объектом наблюдаемости. Даже при
полностью локальном доступе журнал обязателен: 152-ФЗ требует протоколировать обращение к
персональным данным и биометрии и внутри контура.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

AUDIT_PATH = Path(os.getenv("ADMINCHAT_AUDIT", str(Path(__file__).parent / "audit.log.jsonl")))


def _now() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)


def audit_write(operator: str, command: str, params: dict, target: str,
                confirmed: bool, result: str, trace_id: str = "") -> dict:
    """Пишет запись аудита и возвращает её. Ошибка записи не глотается молча: аудит это
    обязательное условие исполнения привилегированной команды, поэтому пусть падает громко."""
    rec = {
        "ts": _now(),
        "service": "adminchat",
        "event": "admin.action",
        "operator": operator,
        "command": command,
        "params": params,
        "target": target,
        "confirmed": confirmed,
        "result": result,
    }
    if trace_id:
        rec["trace_id"] = trace_id
    line = json.dumps(rec, ensure_ascii=False)
    # Долговечная копия обязательна и уходит в stdout той же канонической строкой: агент Alloy
    # заберёт её в Loki, так действия супер-администратора становятся частью контура
    # наблюдаемости (ADR-0032). Это и есть неизменяемый аудит.
    print(line, flush=True)
    # Локальная копия best-effort: сбой файловой системы (например, только-чтение) не должен
    # ронять запрос, потому что долговечная запись уже ушла в контур.
    try:
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    return rec
