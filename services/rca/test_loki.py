"""Тесты приёма логов из Loki. Собираемый вид pytest, без сети.

Сеть заменяется поддельным клиентом httpx на уровне модуля, поэтому проверки идут
детерминированно и офлайн.

Запуск: cd services/rca && python3 -m pytest -q test_loki.py
"""
import httpx
import pytest

import loki
from loki import LokiError, _parse, fetch_window


def test_parse_structured_json():
    r = _parse('{"level":"error","service":"api","msg":"boom"}', 42)
    assert r["level"] == "error"
    assert r["service"] == "api"
    assert r["_raw"].startswith("{")
    assert r["_ts_ns"] == 42


def test_parse_plain_text_infers_level():
    # Ключевая проверка: произвольная текстовая строка лога пода видима и получает
    # уровень из текста, а не отбрасывается как «не наш канон».
    r = _parse("panic: runtime error: invalid memory address", 7)
    assert r["level"] == "fatal"
    assert r["msg"] == "panic: runtime error: invalid memory address"
    assert r["_ts_ns"] == 7


def test_parse_json_without_level_infers_from_msg():
    r = _parse('{"service":"api","msg":"connection refused"}', 1)
    assert r["level"] == "error"


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


class _FakeClient:
    """Поддельный клиент httpx: отдаёт заранее заданные страницы по вызовам get."""

    def __init__(self, pages, timeout=None):
        self._pages = list(pages)
        self._i = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url, params=None):
        page = self._pages[self._i] if self._i < len(self._pages) else {"data": {"result": []}}
        self._i += 1
        return _FakeResponse(page)


def _stream(values):
    return {"data": {"result": [{"stream": {}, "values": values}]}}


# Реалистичные метки времени в наносекундах эпохи внутри десятиминутного окна,
# чтобы условие выхода за нижнюю границу окна не срывало пагинацию преждевременно.
_BASE = 1_700_000_000_000_000_000  # порядка наносекунд текущей эпохи


def test_fetch_window_sorts_by_loki_timestamp(monkeypatch):
    # Одна короткая страница: записи сортируются по метке времени Loki, а не по
    # лексикографике строкового поля, которого во внешнем логе нет вовсе.
    page = _stream([
        [str(_BASE + 300), "third"],
        [str(_BASE + 100), "first"],
        [str(_BASE + 200), "second"],
    ])
    monkeypatch.setattr(loki, "httpx", _fake_httpx([page]))
    recs = fetch_window("{app=\"x\"}", minutes=10, end=(_BASE + 400) / 1e9)
    assert [r["msg"] for r in recs] == ["first", "second", "third"]
    assert [r["_ts_ns"] for r in recs] == [_BASE + 100, _BASE + 200, _BASE + 300]


def test_fetch_window_paginates_without_losing_tail(monkeypatch):
    # Полная первая страница (равна лимиту) вынуждает пагинацию назад по времени;
    # конец окна не теряется молча. Здесь лимит понижен до 2.
    page1 = _stream([[str(_BASE + 500), "e"], [str(_BASE + 400), "d"]])   # полна
    page2 = _stream([[str(_BASE + 300), "c"], [str(_BASE + 200), "b"]])   # полна
    page3 = _stream([[str(_BASE + 100), "a"]])                           # неполна -> стоп
    monkeypatch.setattr(loki, "httpx", _fake_httpx([page1, page2, page3]))
    recs = fetch_window("{app=\"x\"}", minutes=10, limit=2, end=(_BASE + 600) / 1e9)
    assert [r["msg"] for r in recs] == ["a", "b", "c", "d", "e"]


def test_fetch_window_raises_lokierror_on_failure(monkeypatch):
    class _Boom:
        Client = None
        Timeout = httpx.Timeout
        HTTPError = httpx.HTTPError

        class _C:
            def __init__(self, timeout=None):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def get(self, url, params=None):
                raise httpx.ConnectError("loki down")

    boom = _Boom()
    boom.Client = _Boom._C
    monkeypatch.setattr(loki, "httpx", boom)
    with pytest.raises(LokiError):
        fetch_window("{app=\"x\"}", minutes=10)


def _fake_httpx(pages):
    """Собирает поддельный модуль httpx с заранее заданными страницами ответа."""
    class _Module:
        Timeout = httpx.Timeout
        HTTPError = httpx.HTTPError

        @staticmethod
        def Client(timeout=None):
            return _FakeClient(pages, timeout=timeout)

    return _Module()
