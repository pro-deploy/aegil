"""Тесты клиента сервиса разбора первопричин: отправка исхода ремонта. Собираемый вид pytest,
без сети. HTTP-транспорт httpx подменяется подделкой через monkeypatch, поэтому проверки идут
офлайн.

Запуск: cd services/agent-panel && python3 -m pytest -q test_rca_client.py
"""
import httpx
import pytest

import rca_client


class _FakeResponse:
    """Минимальный ответ httpx: код состояния и повтор поведения raise_for_status на кодах 4xx и
    5xx."""

    def __init__(self, status_code=200):
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("ошибка", request=None, response=None)


class _FakeClient:
    """Подделка httpx.Client: фиксирует адрес и тело последнего запроса, отдаёт заранее заданный
    ответ либо бросает заранее заданное исключение (для проверки таймаута и обрыва)."""

    last_url = None
    last_json = None
    last_timeout = None
    response = _FakeResponse()
    raise_exc = None

    def __init__(self, timeout=None):
        _FakeClient.last_timeout = timeout

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def post(self, url, json=None):
        _FakeClient.last_url = url
        _FakeClient.last_json = json
        if _FakeClient.raise_exc is not None:
            raise _FakeClient.raise_exc
        return _FakeClient.response


@pytest.fixture(autouse=True)
def _patch_httpx(monkeypatch):
    _FakeClient.last_url = None
    _FakeClient.last_json = None
    _FakeClient.last_timeout = None
    _FakeClient.response = _FakeResponse()
    _FakeClient.raise_exc = None
    monkeypatch.setattr(rca_client.httpx, "Client", _FakeClient)


def test_record_outcome_success():
    # Успешный ответ: True, запрос уходит на /outcome с явным таймаутом и телом исхода.
    payload = {"fingerprint": "incident|oom|out_of_memory", "resolved": True}
    ok = rca_client.record_outcome("http://rca:9107/", payload)
    assert ok is True
    assert _FakeClient.last_url == "http://rca:9107/outcome"
    assert _FakeClient.last_json == payload
    assert _FakeClient.last_timeout == 10.0


def test_record_outcome_http_error_returns_false():
    # Ошибочный код состояния: мягкая деградация до False без исключения.
    _FakeClient.response = _FakeResponse(status_code=502)
    assert rca_client.record_outcome("http://rca:9107", {"fingerprint": "x"}) is False


def test_record_outcome_timeout_returns_false():
    # Таймаут обращения: мягкая деградация до False без исключения.
    _FakeClient.raise_exc = httpx.TimeoutException("таймаут")
    assert rca_client.record_outcome("http://rca:9107", {"fingerprint": "x"}) is False


def test_record_outcome_connect_error_returns_false():
    # Обрыв соединения: мягкая деградация до False без исключения.
    _FakeClient.raise_exc = httpx.ConnectError("соединение отклонено")
    assert rca_client.record_outcome("http://rca:9107", {"fingerprint": "x"}) is False
