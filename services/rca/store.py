"""Запись размеченных примеров маршрутизации в Postgres (ADR-0032, Часть B; книга
Биркина, глава 10). Пример это запрос инженера и ветки, размеченные большой моделью
при эскалации. Тренер потом дообучает SetFit на накопленных примерах. Запись
best-effort и не должна ронять маршрутизацию: при отсутствии драйвера или сбое
подключения пример просто не сохраняется (мягкая деградация).

Адрес базы берётся из POSTGRES_DSN (тот же кластерный Postgres, база krokki).
"""
from __future__ import annotations

import os

DSN = os.getenv("POSTGRES_DSN", "")


def record_example(query: str, labels: list, source: str = "llm") -> bool:
    """Сохраняет пример в rca_route_examples. Возвращает True при успехе."""
    if not DSN or not query or not labels:
        return False
    try:
        import psycopg2

        conn = psycopg2.connect(DSN)
        try:
            with conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO rca_route_examples (query, labels, source) VALUES (%s, %s, %s)",
                    (query, list(labels), source),
                )
        finally:
            conn.close()
        return True
    except Exception:
        return False
