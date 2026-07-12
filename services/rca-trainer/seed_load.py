"""Засев размеченных примеров маршрутизатора сервиса разбора первопричин
aegil в таблицу rca_route_examples. Инструмент читает сидовый датасет
seed_dataset.jsonl (по одной JSON-записи на строку с полями text и labels) и
вставляет каждый пример теми же полями, что пишет recorder боевого каскада
(services/rca/store.py): query, labels, source. Отличие лишь в источнике: у сида
source равен seed, а trained_at остаётся NULL, поэтому тренер увидит записи как новые
и включит их в первое же дообучение SetFit.

Идемпотентность обеспечивается на стороне базы уникальным индексом по
нормализованному тексту примера и вставкой с оговоркой ON CONFLICT DO NOTHING.
Прежняя схема читала всё множество текстов таблицы в память и сравнивала на стороне
клиента, из-за чего два параллельных запуска засева могли одновременно увидеть
отсутствие примера и вставить дубликаты. Перенос идемпотентности в уникальный индекс
делает засев безопасным при повторных и параллельных запусках: конфликт разрешает
сама база атомарно.

Подключение к Postgres берётся из переменной окружения AEGIL_POSTGRES_DSN, той же,
что использует тренер train.py и recorder store.py, поэтому засев работает в том же
кластерном Postgres. Способ открытия соединения инъектируется через параметр connect,
что позволяет проверять логику модульно без сети, подменяя соединение заглушкой.
"""
from __future__ import annotations

import json
import os

BRANCHES = ("logs", "alerts", "network", "anomalies", "dependencies", "releases")

DSN = os.getenv("AEGIL_POSTGRES_DSN", "")
SEED_PATH = os.getenv(
    "AEGIL_SEED_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed_dataset.jsonl"))
SEED_SOURCE = "seed"

# Определение таблицы и уникального индекса. Схема создаётся идемпотентно, чтобы засев
# на чистой базе не требовал отдельного шага миграции. Индекс по нормализованному
# тексту это тот же ключ идемпотентности, что использует recorder боевого каскада.
_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS rca_route_examples (
        id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        query       text NOT NULL,
        labels      text[] NOT NULL,
        source      text NOT NULL DEFAULT 'llm',
        query_norm  text GENERATED ALWAYS AS (lower(btrim(query))) STORED,
        created_at  timestamptz NOT NULL DEFAULT now(),
        trained_at  timestamptz
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS rca_route_examples_query_norm_uq "
    "ON rca_route_examples (query_norm)",
)


def load_seed(path: str = SEED_PATH) -> list:
    """Читает сидовый датасет из JSONL и возвращает список записей вида
    (query, labels), где labels отфильтрованы по канону веток в каноническом порядке.
    Пустые строки пропускаются. Записи без текста или без валидных веток отбрасываются,
    чтобы в базу не попал мусор."""
    items = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            text = str(obj.get("text") or "").strip()
            raw = {str(x) for x in (obj.get("labels") or [])}
            labels = [b for b in BRANCHES if b in raw]
            if text and labels:
                items.append((text, labels))
    return items


def _ensure_schema(cur) -> None:
    """Идемпотентно создаёт таблицу и уникальный индекс идемпотентности."""
    for stmt in _SCHEMA:
        cur.execute(stmt)


def seed(path: str = SEED_PATH, dsn: str = DSN, connect=None) -> dict:
    """Идемпотентно вставляет сидовые примеры в rca_route_examples. Возвращает сводку
    вида {total, inserted, skipped}. Параметр connect позволяет подменить способ
    открытия соединения (для тестов), по умолчанию используется psycopg2.connect.

    Идемпотентность обеспечивает база: вставка идёт с оговоркой ON CONFLICT DO NOTHING
    по уникальному индексу нормализованного текста, поэтому повторная и параллельная
    вставка одного и того же примера не создаёт дубликата. Число фактически вставленных
    строк определяется по признаку вставки, возвращаемому RETURNING, а разница с общим
    числом примеров относится к пропущенным (уже присутствующим)."""
    items = load_seed(path)
    if connect is None:
        import psycopg2

        connect = psycopg2.connect
    conn = connect(dsn)
    inserted = skipped = 0
    try:
        with conn, conn.cursor() as cur:
            _ensure_schema(cur)
            for text, labels in items:
                cur.execute(
                    "INSERT INTO rca_route_examples (query, labels, source) "
                    "VALUES (%s, %s, %s) ON CONFLICT (query_norm) DO NOTHING RETURNING id",
                    (text, list(labels), SEED_SOURCE),
                )
                if cur.fetchone() is not None:
                    inserted += 1
                else:
                    skipped += 1
    finally:
        conn.close()
    return {"total": len(items), "inserted": inserted, "skipped": skipped}


def main() -> None:
    if not DSN:
        print(json.dumps({"msg": "skip: no AEGIL_POSTGRES_DSN"}, ensure_ascii=False), flush=True)
        return
    summary = seed()
    print(json.dumps({"msg": "seed done", **summary}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
