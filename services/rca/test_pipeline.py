"""Модульный тест оркестрации анализа (ADR-0032, Часть B).
Запуск без зависимостей: python3 services/rca/test_pipeline.py
"""
from pipeline import analyze
from test_aggregator import RECORDS
from test_detectors import BASELINE_RECORDS


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def main() -> None:
    out = analyze(RECORDS)
    for key in ("facts", "detectors", "score", "verdict"):
        assert key in out, f"нет ключа {key}"

    _eq("total_lines", out["facts"]["total_lines"], 6)
    _eq("verdict status", out["verdict"]["status"], "degraded")
    _eq("verdict band", out["verdict"]["confidence"]["band"], "uncertain")
    _eq("root_cause", out["verdict"]["root_cause"], "Первичный отказ «connection_refused» у цели llm")

    # baseline повышает уверенность (срабатывают D2 и D3).
    out_b = analyze(RECORDS, baseline=BASELINE_RECORDS)
    assert out_b["score"]["confidence"] >= out["score"]["confidence"]

    # Коэффициент полноты понижает уверенность.
    out_d = analyze(RECORDS, delta=0.5)
    assert out_d["score"]["confidence"] < out["score"]["confidence"]

    print("pipeline: all asserts passed")


if __name__ == "__main__":
    main()
