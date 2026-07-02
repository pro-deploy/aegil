"""Модульный тест идемпотентности засева примеров маршрутизатора RCA (ADR-0032,
Часть B). Проверяет, что seed_load.seed вставляет каждый пример ровно один раз,
проставляет источник seed и не создаёт дубликатов при повторном запуске. База
подменяется заглушкой в памяти, поэтому тест идёт без сети и без Postgres.

Запуск без зависимостей: python3 services/rca-trainer/test_seed_load.py
"""
import seed_load


class _Cursor:
    """Минимальная заглушка курсора psycopg2 над списком строк в памяти. Понимает два
    запроса засева: выборку всех текстов query и вставку одной записи."""

    def __init__(self, store):
        self._store = store
        self._fetch = []

    def execute(self, sql, params=None):
        s = sql.strip().upper()
        if s.startswith("SELECT QUERY FROM RCA_ROUTE_EXAMPLES"):
            self._fetch = [(row["query"],) for row in self._store]
        elif s.startswith("INSERT INTO RCA_ROUTE_EXAMPLES"):
            query, labels, source = params
            self._store.append({"query": query, "labels": list(labels), "source": source})
        else:
            raise AssertionError(f"неожиданный запрос: {sql!r}")

    def fetchall(self):
        return self._fetch

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Conn:
    """Заглушка соединения: контекст-менеджер (как транзакция psycopg2) и фабрика
    курсоров поверх общего списка строк, чтобы состояние сохранялось между запусками."""

    def __init__(self, store):
        self._store = store
        self.closed = False

    def cursor(self):
        return _Cursor(self._store)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def close(self):
        self.closed = True


def main() -> None:
    store = []  # общее хранилище строк, переживает несколько соединений

    def connect(_dsn):
        return _Conn(store)

    items = seed_load.load_seed()
    assert items, "датасет пуст, засеивать нечего"
    total_items = len(items)

    # Первый прогон: все примеры вставляются, дубликатов нет.
    r1 = seed_load.seed(dsn="stub", connect=connect)
    assert r1["total"] == total_items, r1
    assert r1["inserted"] == total_items, r1
    assert r1["skipped"] == 0, r1
    assert len(store) == total_items, len(store)

    # Все строки помечены источником seed.
    assert all(row["source"] == "seed" for row in store), "источник должен быть seed"
    # Ветки строк принадлежат канону.
    canon = set(seed_load.BRANCHES)
    assert all(set(row["labels"]) <= canon for row in store), "ветки вне канона"

    # Второй прогон по тому же хранилищу: ничего не вставляется, всё пропускается.
    r2 = seed_load.seed(dsn="stub", connect=connect)
    assert r2["inserted"] == 0, r2
    assert r2["skipped"] == total_items, r2
    assert len(store) == total_items, "идемпотентность нарушена: появились дубли"

    # Хеш текста устойчив к регистру и крайним пробелам.
    assert seed_load._text_hash("  Диск ЗАПОЛНЕН  ") == seed_load._text_hash("диск заполнен")

    print(f"seed_load: all asserts passed; inserted {total_items}, second run skipped all")


if __name__ == "__main__":
    main()
