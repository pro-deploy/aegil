"""Тесты веб-слоя сервиса RCA. Собираемый вид pytest, без сети.

Обращения к Loki и языковой модели заменяются подделками через monkeypatch, поэтому
проверки идут офлайн.

Запуск: cd services/rca && python3 -m pytest -q test_app.py
"""
import pytest
from starlette.testclient import TestClient

import app as appmod
from loki import LokiError


@pytest.fixture
def client():
    return TestClient(appmod.app)


def test_app_title_is_domain_agnostic():
    # Наследный брендинг убран: заголовок продукта нейтральный.
    assert "krokki" not in appmod.app.title.lower()
    assert appmod.app.title == "kube-sentinel-rca"


def test_no_stuck_endpoint(client):
    # Наследный эндпоинт застрявших заданий удалён вместе с модулем.
    assert client.post("/stuck").status_code == 404


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "service": "rca"}


def test_analyze_with_direct_records(client):
    text = [{"msg": f"i={i}", "level": "info", "_ts_ns": i} for i in range(6)]
    text += [{"msg": "connection refused", "level": "error", "service": "api",
              "pod": f"p{i}", "namespace": "prod", "_ts_ns": 100 + i} for i in range(5)]
    r = client.post("/analyze", json={"records": text})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"]["status"] != "healthy"
    assert "connection_refused" in (body["verdict"]["root_cause"] or "")


def test_analyze_loki_error_returns_502(client, monkeypatch):
    # Недоступность источника отдаётся осмысленным кодом 502, а не голым отказом 500.
    def _boom(*a, **k):
        raise LokiError("источник недоступен")

    monkeypatch.setattr(appmod, "fetch_window", _boom)
    r = client.post("/analyze", json={"query": "{app=\"x\"}", "use_baseline": False})
    assert r.status_code == 502
    assert "недоступен" in r.json()["detail"]


def test_analyze_reads_from_loki_when_no_records(client, monkeypatch):
    canned = [{"msg": "out of memory", "level": "fatal", "service": "db",
               "pod": "db-0", "namespace": "prod", "_ts_ns": 1}] * 5

    def _fake_fetch(query, minutes=60, end=None):
        return list(canned)

    monkeypatch.setattr(appmod, "fetch_window", _fake_fetch)
    r = client.post("/analyze", json={"query": "{app=\"x\"}", "use_baseline": False})
    assert r.status_code == 200
    assert r.json()["facts"]["total_lines"] == 5


def test_route_endpoint_keyword_fallback(client):
    # Без обученной модели маршрутизация падает на детерминированный ключевой фолбэк.
    r = client.post("/route", json={"query": "connection refused"})
    assert r.status_code == 200
    body = r.json()
    assert body["branches"] == ["network"]
    assert body["source"] == "keyword"


def test_outcome_records_when_store_ok(client, monkeypatch):
    # Успешная запись исхода ремонта: DSN задан, store.record_outcome отвечает успехом.
    import store

    captured = {}

    def _rec(dsn, fingerprint, status, root_cause, action, resolved, **k):
        captured.update(dict(dsn=dsn, fingerprint=fingerprint, status=status,
                             root_cause=root_cause, action=action, resolved=resolved))
        return True

    monkeypatch.setattr(store, "DSN", "postgresql://x")
    monkeypatch.setattr(store, "record_outcome", _rec)
    r = client.post("/outcome", json={"fingerprint": "incident|oom|out_of_memory",
                                      "status": "incident", "root_cause": "out_of_memory",
                                      "action": "restart", "resolved": True})
    assert r.status_code == 200
    body = r.json()
    assert body["recorded"] is True
    assert body["fingerprint"] == "incident|oom|out_of_memory"
    assert captured["resolved"] is True
    assert captured["root_cause"] == "out_of_memory"


def test_outcome_returns_502_when_dsn_missing(client, monkeypatch):
    # Без адреса Postgres хранилище исходов недоступно: осмысленный 502, а не голый 500.
    import store

    monkeypatch.setattr(store, "DSN", "")
    r = client.post("/outcome", json={"fingerprint": "x"})
    assert r.status_code == 502
    assert "недоступно" in r.json()["detail"]


def test_outcome_returns_502_on_postgres_error(client, monkeypatch):
    # Сбой драйвера базы данных отдаётся осмысленным 502, а не падением сервиса.
    import store

    def _boom(*a, **k):
        raise RuntimeError("postgres недоступен")

    monkeypatch.setattr(store, "DSN", "postgresql://x")
    monkeypatch.setattr(store, "record_outcome", _boom)
    r = client.post("/outcome", json={"fingerprint": "x", "resolved": False})
    assert r.status_code == 502
    assert "недоступно" in r.json()["detail"]


def test_outcome_returns_502_when_not_saved(client, monkeypatch):
    # Запись best-effort вернула False (пример не сохранён): тоже осмысленный 502.
    import store

    monkeypatch.setattr(store, "DSN", "postgresql://x")
    monkeypatch.setattr(store, "record_outcome", lambda *a, **k: False)
    r = client.post("/outcome", json={"fingerprint": "x"})
    assert r.status_code == 502


def test_outcomes_stats_endpoint(client, monkeypatch):
    # Сводка исходов отдаётся как есть из store.outcomes_stats.
    import store

    monkeypatch.setattr(store, "DSN", "postgresql://x")
    monkeypatch.setattr(store, "outcomes_stats",
                        lambda dsn, **k: {"total": 3, "resolved": 2, "failed": 1, "available": True})
    r = client.get("/outcomes/stats")
    assert r.status_code == 200
    assert r.json() == {"total": 3, "resolved": 2, "failed": 1, "available": True}


def test_env_prefix_is_sentinel():
    # Конфигурация под единым префиксом SENTINEL_: наследные беспрефиксные имена убраны.
    import loki
    assert loki.LOKI_URL == loki.os.getenv("SENTINEL_LOKI_URL", "http://loki:3100").rstrip("/")
