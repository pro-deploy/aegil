"""Модульный тест маршрутизации запроса (ADR-0032, Часть B).
Запуск без зависимостей: python3 services/rca/test_router.py
"""
from router import BRANCHES, route


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def main() -> None:
    _eq("network+releases", route("почему connection refused после деплоя?"),
        ["network", "releases"])
    _eq("logs default", route("что случилось?"), ["logs"])
    _eq("anomalies", route("виден всплеск ошибок"), ["logs", "anomalies"])
    _eq("dependencies", route("покажи каскад по зависимостям сервисов"),
        ["dependencies"])
    _eq("ordered by canon", route("release network"), ["network", "releases"])

    # Подключаемый обученный классификатор (эмуляция SetFit) перекрывает фолбэк.
    class FakeSetFit:
        def predict(self, q):
            return ["alerts", "anomalies"]

    _eq("pluggable classifier", route("любой запрос", classifier=FakeSetFit()),
        ["alerts", "anomalies"])

    # Пустой ответ классификатора деградирует к ветке логов.
    class Empty:
        def predict(self, q):
            return []

    _eq("empty degrades to logs", route("x", classifier=Empty()), ["logs"])
    _eq("branches canon", BRANCHES,
        ("logs", "alerts", "network", "anomalies", "dependencies", "releases"))
    print("router: all asserts passed")


if __name__ == "__main__":
    main()
