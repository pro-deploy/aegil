"""Тесты записи исходов ремонтов в модуле store сервиса RCA. Собираемый вид pytest, без сети.

Соединение с Postgres подменяется фейком через параметр connect, поэтому проверки идут офлайн.
Замыкание контура активного обучения проверяется по фактам: исход попадает в таблицу
repair_outcomes, схема создаётся идемпотентно при первом обращении, сбой не гасится молча, а
сводка считает устранённые и неустранённые исходы.

Запуск: cd services/rca && python3 -m pytest -q test_store.py
"""
import pytest

import store


class _FakeCursor:
    """Минимальный курсор: фиксирует исполненные операторы и отдаёт заранее заданную строку для
    выборки сводки."""

    def __init__(self, owner):
        self._owner = owner

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        self._owner.executed.append((sql, params))

    def fetchone(self):
        return self._owner.fetchone_row


class _FakeConn:
    """Подделка psycopg2-соединения: поддерживает контекстный менеджер (as с conn), выдаёт курсор,
    копит исполненные операторы. Флаг closed имитирует живость соединения."""

    def __init__(self, fetchone_row=(0, 0, 0)):
        self.executed = []
        self.closed = 0
        self.fetchone_row = fetchone_row

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _FakeCursor(self)

    def close(self):
        self.closed = 1


@pytest.fixture(autouse=True)
def _reset_module_state():
    # Каждый тест начинается с чистого модульного состояния соединения и схемы.
    store._reset_conn()
    yield
    store._reset_conn()


def _fake_connect_factory(conn):
    def _connect(dsn):
        return conn

    return _connect


def test_record_outcome_writes_row(monkeypatch):
    # Исход ремонта попадает в repair_outcomes с полным набором полей.
    monkeypatch.setattr(store, "DSN", "postgresql://x")
    conn = _FakeConn()
    ok = store.record_outcome("postgresql://x", "incident|oom|out_of_memory", "incident",
                              "out_of_memory", "restart", True,
                              connect=_fake_connect_factory(conn))
    assert ok is True
    inserts = [e for e in conn.executed if "INSERT INTO repair_outcomes" in e[0]]
    assert len(inserts) == 1
    _, params = inserts[0]
    assert params == ("incident|oom|out_of_memory", "incident", "out_of_memory", "restart", True)


def test_record_outcome_creates_schema_once(monkeypatch):
    # Схема обеих таблиц создаётся идемпотентно при первом обращении и не пересоздаётся при втором.
    monkeypatch.setattr(store, "DSN", "postgresql://x")
    conn = _FakeConn()
    connect = _fake_connect_factory(conn)
    store.record_outcome("postgresql://x", "fp1", "incident", "rc", "act", True, connect=connect)
    creates_first = [e for e in conn.executed if e[0].strip().upper().startswith("CREATE")]
    assert any("repair_outcomes" in e[0] for e in creates_first)
    n_creates = len(creates_first)
    store.record_outcome("postgresql://x", "fp2", "incident", "rc", "act", True, connect=connect)
    creates_after = [e for e in conn.executed if e[0].strip().upper().startswith("CREATE")]
    # Второй вызов не добавил новых CREATE: схема готова, повторного создания нет.
    assert len(creates_after) == n_creates


def test_record_outcome_empty_fingerprint_skipped(monkeypatch):
    # Пустой отпечаток не пишется: без соединения возвращается False, работа продолжается штатно.
    monkeypatch.setattr(store, "DSN", "postgresql://x")
    called = {"n": 0}

    def _connect(dsn):
        called["n"] += 1
        return _FakeConn()

    assert store.record_outcome("postgresql://x", "", "s", "rc", "a", True, connect=_connect) is False
    assert called["n"] == 0


def test_record_outcome_no_dsn_returns_false(monkeypatch):
    # Без адреса базы запись не выполняется (мягкая деградация).
    monkeypatch.setattr(store, "DSN", "")
    assert store.record_outcome("", "fp", "s", "rc", "a", True) is False


def test_record_outcome_logs_and_returns_false_on_error(monkeypatch, caplog):
    # Сбой записи журналируется на warning, а не гасится молча, и возвращается False.
    monkeypatch.setattr(store, "DSN", "postgresql://x")

    def _boom(dsn):
        raise RuntimeError("база недоступна")

    import logging
    with caplog.at_level(logging.WARNING, logger="rca.store"):
        ok = store.record_outcome("postgresql://x", "fp", "s", "rc", "a", True, connect=_boom)
    assert ok is False
    assert any("исход ремонта" in r.message for r in caplog.records)


def test_outcomes_stats_counts(monkeypatch):
    # Сводка считает всего, устранено и неустранено из одной строки выборки.
    monkeypatch.setattr(store, "DSN", "postgresql://x")
    conn = _FakeConn(fetchone_row=(5, 3, 2))
    stats = store.outcomes_stats("postgresql://x", connect=_fake_connect_factory(conn))
    assert stats == {"total": 5, "resolved": 3, "failed": 2, "available": True}


def test_outcomes_stats_no_dsn(monkeypatch):
    # Без адреса базы отдаётся нулевая сводка с пометкой недоступности.
    monkeypatch.setattr(store, "DSN", "")
    stats = store.outcomes_stats("")
    assert stats == {"total": 0, "resolved": 0, "failed": 0, "available": False}


def test_outcomes_stats_error_returns_unavailable(monkeypatch):
    # Сбой чтения отдаёт нулевую сводку с пометкой недоступности, а не бросает.
    monkeypatch.setattr(store, "DSN", "postgresql://x")

    def _boom(dsn):
        raise RuntimeError("нет базы")

    stats = store.outcomes_stats("postgresql://x", connect=_boom)
    assert stats["available"] is False
    assert stats["total"] == 0


def test_default_connect_signature_matches_get_conn_call():
    """Регресс: _get_conn вызывает connect(DSN) с одним аргументом, поэтому дефолтный _connect
    обязан принимать ровно один позиционный параметр. Живой прогон вскрыл рассинхрон сигнатур,
    который юнит-тесты пропускали, подставляя фейковый connect."""
    import inspect
    import store
    params = list(inspect.signature(store._connect).parameters.values())
    positional = [p for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
    assert len(positional) == 1, f"_connect должен принимать один аргумент dsn, а принимает {len(positional)}"
