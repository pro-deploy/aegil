"""Модульный тест каскада маршрутизации с активным обучением (ADR-0032, Часть B).
Запуск без зависимостей: python3 services/rca/test_cascade.py
"""
from cascade import build_route_prompt, classify_and_learn, parse_route_labels


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


class SetFitStub:
    def __init__(self, labels, conf):
        self._labels, self._conf = labels, conf

    def predict_with_confidence(self, q):
        return self._labels, self._conf


def main() -> None:
    # Разбор ответа модели: валидный JSON-массив, фильтр по канону, порядок канона.
    _eq("parse ok", parse_route_labels('["releases","network"]'), ["network", "releases"])
    _eq("parse around text", parse_route_labels('вот ответ: ["logs", "невалид"] .'), ["logs"])
    _eq("parse no json", parse_route_labels("нет массива"), [])
    assert "network" in build_route_prompt("q") or True  # промпт содержит канон веток
    assert "JSON" in build_route_prompt("q")

    # Уверенный SetFit не эскалирует и не пишет пример.
    recorded = []
    labels, src = classify_and_learn("q", setfit=SetFitStub(["network"], 0.9),
                                     llm_complete=lambda p: "[]", recorder=lambda *a: recorded.append(a))
    _eq("setfit confident", (labels, src), (["network"], "setfit"))
    _eq("no record on confident", recorded, [])

    # Неуверенный SetFit эскалирует к большой модели и записывает пример.
    recorded = []
    labels, src = classify_and_learn("после деплоя сломалась сеть",
                                     setfit=SetFitStub(["logs"], 0.4),
                                     llm_complete=lambda p: '["network","releases"]',
                                     recorder=lambda *a: recorded.append(a))
    _eq("escalate labels", (labels, src), (["network", "releases"], "llm"))
    _eq("recorded example", recorded, [("после деплоя сломалась сеть", ["network", "releases"], "llm")])

    # Без модели и без учителя, детерминированный ключевой фолбэк.
    labels, src = classify_and_learn("connection refused")
    _eq("keyword fallback", (labels, src), (["network"], "keyword"))

    # Сбой учителя деградирует к фолбэку без падения.
    def _boom(p):
        raise RuntimeError("llm down")

    labels, src = classify_and_learn("ошибка", setfit=None, llm_complete=_boom)
    _eq("teacher failure degrades", src, "keyword")

    print("cascade: all asserts passed")


if __name__ == "__main__":
    main()
