"""Модульный тест формулировки отчёта (ADR-0032, Часть B).
Запуск без зависимостей: python3 services/rca/test_report.py
"""
from pipeline import analyze
from report import build_prompt, deterministic_summary, formulate
from test_aggregator import RECORDS


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def main() -> None:
    out = analyze(RECORDS)
    verdict, facts = out["verdict"], out["facts"]

    # Без модели, детерминированная сводка.
    r0 = formulate(verdict)
    _eq("no-model source", r0["source"], "deterministic")
    assert "Первопричина" in r0["report"], r0["report"]

    # Здоровое окно.
    healthy = {"status": "healthy", "confidence": {"value": 0.09, "band": "low"}, "evidence": []}
    _eq("healthy summary", deterministic_summary(healthy),
        "Инцидент не обнаружен: значимого сигнала в окне нет.")

    # С моделью, отчёт берётся от неё.
    r1 = formulate(verdict, facts, llm_complete=lambda p: "Сжатый отчёт по инциденту.")
    _eq("model source", r1["source"], "model")
    _eq("model report", r1["report"], "Сжатый отчёт по инциденту.")

    # Гард заземления: модель, добавившая факты сверх приведённых (несуществующий хост,
    # база, число записей), отбраковывается и заменяется детерминированной сводкой.
    def _liar(p):
        return "Инцидент вызван отказом Postgres на узле 10.0.0.9, потеряно 5000 записей."
    r_lie = formulate(verdict, facts, llm_complete=_liar)
    _eq("ungrounded rejected", r_lie["source"], "deterministic")
    _eq("ungrounded reason", r_lie["reason"], "model_output_ungrounded")

    # Заземлённый отчёт с фактами из вердикта (сигнал, цель) принимается.
    def _honest(p):
        return "Первичный отказ connection_refused у цели llm; проверить доступность llm."
    r_ok = formulate(verdict, facts, llm_complete=_honest)
    _eq("grounded accepted", r_ok["source"], "model")

    # Сбой модели, мягкая деградация к детерминированной сводке.
    def _boom(p):
        raise RuntimeError("llm down")

    r2 = formulate(verdict, facts, llm_complete=_boom)
    _eq("degrade source", r2["source"], "deterministic")

    # Пустой ответ модели тоже деградирует.
    r3 = formulate(verdict, facts, llm_complete=lambda p: "   ")
    _eq("empty degrades", r3["source"], "deterministic")

    # Промпт содержит первопричину и запрет выдумывать (гард).
    prompt = build_prompt(verdict, facts)
    assert "connection_refused" in prompt, "промпт должен нести посчитанные факты"
    assert "не выдумыв" in prompt, "промпт должен запрещать выдумывание"

    print("report: all asserts passed")


if __name__ == "__main__":
    main()
