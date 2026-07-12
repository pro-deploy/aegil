"""Тесты каскада маршрутизации с активным обучением. Собираемый вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_cascade.py
"""
from cascade import build_route_prompt, classify_and_learn, parse_route_labels


class SetFitStub:
    def __init__(self, labels, conf):
        self._labels, self._conf = labels, conf

    def predict_with_confidence(self, q):
        return self._labels, self._conf


def test_parse_route_labels():
    assert parse_route_labels('["releases","network"]') == ["network", "releases"]
    assert parse_route_labels('вот ответ: ["logs", "невалид"] .') == ["logs"]
    assert parse_route_labels("нет массива") == []


def test_route_prompt_carries_canon():
    prompt = build_route_prompt("q")
    assert "network" in prompt
    assert "JSON" in prompt


def test_confident_setfit_no_escalation():
    recorded = []
    labels, src = classify_and_learn("q", setfit=SetFitStub(["network"], 0.9),
                                     llm_complete=lambda p: "[]", recorder=lambda *a: recorded.append(a))
    assert (labels, src) == (["network"], "setfit")
    assert recorded == []


def test_uncertain_setfit_escalates_and_records():
    recorded = []
    labels, src = classify_and_learn("после деплоя сломалась сеть",
                                     setfit=SetFitStub(["logs"], 0.4),
                                     llm_complete=lambda p: '["network","releases"]',
                                     recorder=lambda *a: recorded.append(a))
    assert (labels, src) == (["network", "releases"], "llm")
    assert recorded == [("после деплоя сломалась сеть", ["network", "releases"], "llm")]


def test_keyword_fallback_without_model():
    assert classify_and_learn("connection refused") == (["network"], "keyword")


def test_teacher_failure_degrades():
    def _boom(p):
        raise RuntimeError("llm down")

    _, src = classify_and_learn("ошибка", setfit=None, llm_complete=_boom)
    assert src == "keyword"
