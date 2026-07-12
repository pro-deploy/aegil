"""Тесты маршрутизации запроса инженера. Собираемый вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_router.py
"""
from router import BRANCHES, route


def test_keyword_routing():
    assert route("почему connection refused после деплоя?") == ["network", "releases"]
    assert route("что случилось?") == ["logs"]
    assert route("виден всплеск ошибок") == ["logs", "anomalies"]
    assert route("покажи каскад по зависимостям сервисов") == ["dependencies"]
    assert route("release network") == ["network", "releases"]


def test_pluggable_classifier_overrides_fallback():
    class FakeSetFit:
        def predict(self, q):
            return ["alerts", "anomalies"]

    assert route("любой запрос", classifier=FakeSetFit()) == ["alerts", "anomalies"]


def test_empty_classifier_degrades_to_logs():
    class Empty:
        def predict(self, q):
            return []

    assert route("x", classifier=Empty()) == ["logs"]


def test_branches_canon():
    assert BRANCHES == ("logs", "alerts", "network", "anomalies", "dependencies", "releases")
