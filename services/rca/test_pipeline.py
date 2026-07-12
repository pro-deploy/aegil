"""Тесты оркестрации анализа. Собираемый вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_pipeline.py
"""
from pipeline import analyze
from test_aggregator import RECORDS
from test_detectors import BASELINE_RECORDS


def test_analyze_shape():
    out = analyze(RECORDS)
    for key in ("facts", "detectors", "score", "verdict"):
        assert key in out
    assert out["facts"]["total_lines"] == 6
    assert out["verdict"]["status"] == "degraded"
    assert out["verdict"]["confidence"]["band"] == "uncertain"
    assert out["verdict"]["root_cause"] == "Первичный отказ «connection_refused» у цели billing"


def test_baseline_raises_confidence():
    out = analyze(RECORDS)
    out_b = analyze(RECORDS, baseline=BASELINE_RECORDS)
    assert out_b["score"]["confidence"] >= out["score"]["confidence"]


def test_delta_lowers_confidence():
    out = analyze(RECORDS)
    out_d = analyze(RECORDS, delta=0.5)
    assert out_d["score"]["confidence"] < out["score"]["confidence"]
