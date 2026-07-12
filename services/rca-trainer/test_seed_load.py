"""Модульный тест идемпотентности засева примеров маршрутизатора сервиса разбора
первопричин aegil. Проверяет, что seed_load.seed вставляет каждый пример
ровно один раз, проставляет источник seed и не создаёт дубликатов при повторном
запуске. Идемпотентность теперь обеспечивает база уникальным индексом по
нормализованному тексту и вставкой ON CONFLICT DO NOTHING; заглушка курсора
воспроизводит это поведение, дедуплицируя по нормализованному тексту и возвращая
признак вставки через RETURNING. Тест идёт без сети и без Postgres.

Запуск без зависимостей: python3 services/rca-trainer/test_seed_load.py
"""
import seed_load


def _norm(text: str) -> str:
    """Нормализация текста, эквивалентная выражению query_norm = lower(btrim(query))
    из уникального индекса базы."""
    return (text or "").strip().lower()


class _Cursor:
    """Минимальная заглушка курсора psycopg2 над списком строк в памяти. Понимает
    создание схемы (игнорируется) и вставку с ON CONFLICT ... RETURNING id, где
    конфликт разрешается по нормализованному тексту как в уникальном индексе базы."""

    def __init__(self, store):
        self._store = store
        self._last = None  # результат RETURNING последней вставки

    def execute(self, sql, params=None):
        s = " ".join(sql.strip().upper().split())
        if s.startswith("CREATE TABLE") or s.startswith("CREATE UNIQUE INDEX"):
            self._last = None
            return
        if s.startswith("INSERT INTO RCA_ROUTE_EXAMPLES"):
            query, labels, source = params
            key = _norm(query)
            if any(_norm(row["query"]) == key for row in self._store):
                # Конфликт по уникальному индексу: DO NOTHING, RETURNING ничего не даёт.
                self._last = None
                return
            new_id = f"id-{len(self._store)}"
            self._store.append({"id": new_id, "query": query,
                                "labels": list(labels), "source": source})
            self._last = (new_id,)
            return
        raise AssertionError(f"неожиданный запрос: {sql!r}")

    def fetchone(self):
        return self._last

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

    # Второй прогон по тому же хранилищу: ничего не вставляется, всё пропускается
    # (конфликт по уникальному индексу разрешает база).
    r2 = seed_load.seed(dsn="stub", connect=connect)
    assert r2["inserted"] == 0, r2
    assert r2["skipped"] == total_items, r2
    assert len(store) == total_items, "идемпотентность нарушена: появились дубли"

    print(f"seed_load: all asserts passed; inserted {total_items}, second run skipped all")


def test_seed_idempotent() -> None:
    """Обёртка для стандартного сборщика тестов (pytest): проверка идемпотентности
    засева не должна оставаться невидимой для CI."""
    main()


if __name__ == "__main__":
    main()
