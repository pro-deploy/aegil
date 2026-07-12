"""Тесты формулировки отчёта и гарда заземления. Собираемый вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_report.py
"""
from pipeline import analyze
from report import build_prompt, deterministic_summary, formulate, is_grounded
from test_aggregator import RECORDS


def test_deterministic_without_model():
    out = analyze(RECORDS)
    r0 = formulate(out["verdict"])
    assert r0["source"] == "deterministic"
    assert "Первопричина" in r0["report"]


def test_healthy_summary():
    healthy = {"status": "healthy", "confidence": {"value": 0.09, "band": "low"}, "evidence": []}
    assert deterministic_summary(healthy) == "Инцидент не обнаружен: значимого сигнала в окне нет."


def test_model_report_accepted():
    out = analyze(RECORDS)
    r1 = formulate(out["verdict"], out["facts"], llm_complete=lambda p: "Сжатый отчёт по инциденту.")
    assert r1["source"] == "model"
    assert r1["report"] == "Сжатый отчёт по инциденту."


def test_ungrounded_model_rejected():
    out = analyze(RECORDS)

    def _liar(p):
        return "Инцидент вызван отказом Postgres на узле 10.0.0.9, потеряно 5000 записей."

    r = formulate(out["verdict"], out["facts"], llm_complete=_liar)
    assert r["source"] == "deterministic"
    assert r["reason"] == "model_output_ungrounded"


def test_grounded_model_accepted():
    out = analyze(RECORDS)

    def _honest(p):
        return "Первичный отказ connection_refused у цели billing; проверить доступность billing."

    r = formulate(out["verdict"], out["facts"], llm_complete=_honest)
    assert r["source"] == "model"


def test_grounding_token_not_substring():
    # Негативная проверка дырявой подстрочной проверки: число «10» НЕ считается
    # заземлённым лишь потому, что цифры «10» встречаются внутри таймстампа или
    # длинного идентификатора. Требуется совпадение отдельного токена.
    verdict = {"evidence": [{"snippet": "2026-07-01T12:00:10Z error at line 5"}]}
    assert is_grounded("Потеряно 10 записей", verdict, None) is False
    # А настоящий отдельный токен «5» из контекста заземляется.
    assert is_grounded("на строке 5", verdict, None) is True


def test_model_failure_degrades():
    out = analyze(RECORDS)

    def _boom(p):
        raise RuntimeError("llm down")

    assert formulate(out["verdict"], out["facts"], llm_complete=_boom)["source"] == "deterministic"


def test_empty_model_output_degrades():
    out = analyze(RECORDS)
    assert formulate(out["verdict"], out["facts"], llm_complete=lambda p: "   ")["source"] == "deterministic"


def test_prompt_carries_facts_and_ban():
    out = analyze(RECORDS)
    prompt = build_prompt(out["verdict"], out["facts"])
    assert "connection_refused" in prompt
    assert "не выдумыв" in prompt
