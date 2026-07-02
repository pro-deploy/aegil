"""Засев размеченных примеров маршрутизатора RCA в таблицу rca_route_examples
(ADR-0032, Часть B; книга Биркина, глава 10.6). Читает сидовый датасет
seed_dataset.jsonl (по одной JSON-записи на строку с полями text и labels) и
вставляет каждый пример теми же полями, что пишет recorder боевого каскада
(services/rca/store.py): query, labels, source. Отличие лишь в источнике: у сида
source равен seed, а trained_at остаётся NULL, поэтому тренер увидит записи как
новые и включит их в первое же дообучение SetFit.

Инструмент идемпотентен: повторный запуск не создаёт дубликатов. Идемпотентность
опирается на хеш текста примера (нормализованного): перед вставкой считывается
множество уже присутствующих в таблице текстов, и совпадающие по хешу примеры
пропускаются. Это позволяет безопасно перезапускать засев и дозасевать датасет
новыми строками, не плодя копии.

Подключение к Postgres берётся из той же переменной окружения POSTGRES_DSN, что
использует тренер train.py и recorder store.py, поэтому засев работает в том же
кластерном Postgres (база krokki). Доступ к базе инъектируется через параметр
connect, что позволяет проверять логику модульно без сети, подменяя соединение
заглушкой.
"""
from __future__ import annotations

import hashlib
import json
import os

BRANCHES = ("logs", "alerts", "network", "anomalies", "dependencies", "releases")

DSN = os.getenv("POSTGRES_DSN", "")
SEED_PATH = os.getenv(
    "RCA_SEED_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed_dataset.jsonl"))
SEED_SOURCE = "seed"


def _text_hash(text: str) -> str:
    """Хеш нормализованного текста примера для сравнения на дубликаты. Нормализация
    приводит регистр к нижнему и схлопывает окружающие пробелы, чтобы отличия только
    в регистре или в крайних пробелах не порождали дубликат."""
    norm = " ".join((text or "").lower().split())
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


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


def _existing_hashes(cur) -> set:
    """Множество хешей текстов, уже присутствующих в rca_route_examples. Считается по
    полю query, тем же, куда пишут recorder и засев, поэтому дубли ловятся независимо
    от источника (seed, llm или human)."""
    cur.execute("SELECT query FROM rca_route_examples")
    return {_text_hash(row[0]) for row in cur.fetchall()}


def seed(path: str = SEED_PATH, dsn: str = DSN, connect=None) -> dict:
    """Идемпотентно вставляет сидовые примеры в rca_route_examples. Возвращает сводку
    вида {total, inserted, skipped}. Параметр connect позволяет подменить способ
    открытия соединения (для тестов), по умолчанию используется psycopg2.connect.

    Идемпотентность: перед вставкой считывается множество уже имеющихся текстов по
    хешу, и совпадающие примеры пропускаются. В пределах одного запуска повторяющиеся
    тексты внутри самого датасета также вставляются лишь однажды."""
    items = load_seed(path)
    if connect is None:
        import psycopg2

        connect = psycopg2.connect
    conn = connect(dsn)
    inserted = skipped = 0
    try:
        with conn, conn.cursor() as cur:
            seen = _existing_hashes(cur)
            for text, labels in items:
                h = _text_hash(text)
                if h in seen:
                    skipped += 1
                    continue
                cur.execute(
                    "INSERT INTO rca_route_examples (query, labels, source) VALUES (%s, %s, %s)",
                    (text, list(labels), SEED_SOURCE),
                )
                seen.add(h)
                inserted += 1
    finally:
        conn.close()
    return {"total": len(items), "inserted": inserted, "skipped": skipped}


def main() -> None:
    if not DSN:
        print(json.dumps({"msg": "skip: no POSTGRES_DSN"}, ensure_ascii=False), flush=True)
        return
    summary = seed()
    print(json.dumps({"msg": "seed done", **summary}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
