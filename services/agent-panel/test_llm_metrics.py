"""Тесты наблюдаемости инференса модели (LLMOps). Собираемый вид pytest.

Запуск: cd services/agent-panel && python3 -m pytest -q test_llm_metrics.py
"""
import llm_metrics


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIL_LLM_METRICS", str(tmp_path / "m.jsonl"))
    monkeypatch.delenv("AEGIL_LLM_COST_PROMPT", raising=False)
    monkeypatch.delenv("AEGIL_LLM_COST_COMPLETION", raising=False)
    llm_metrics.reset()


def test_records_and_summarizes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    for i, lat in enumerate((100, 200, 300, 400)):
        llm_metrics.record("gemma", lat, prompt_tokens=10, completion_tokens=5, ok=True, now=1000 + i)
    s = llm_metrics.summary(now=1004)
    assert s["calls"] == 4
    assert s["error_rate"] == 0.0
    assert s["latency_p95_ms"] == 400
    assert s["prompt_tokens"] == 40 and s["completion_tokens"] == 20


def test_error_rate_counts_failures(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    llm_metrics.record("gemma", 100, ok=True, now=1)
    llm_metrics.record("gemma", 120, ok=False, error="400 tool choice", now=2)
    s = llm_metrics.summary(now=3)
    assert s["calls"] == 2
    assert s["error_rate"] == 0.5


def test_cost_from_token_prices(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("AEGIL_LLM_COST_COMPLETION", "2.0")  # 2 у.е. за тысячу токенов ответа
    llm_metrics.record("m", 50, prompt_tokens=1000, completion_tokens=1000, ok=True, now=1)
    s = llm_metrics.summary(now=2)
    assert s["cost_total"] == 2.0


def test_latency_drift_positive_when_slowing(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    for i, lat in enumerate((100, 100, 300, 300)):
        llm_metrics.record("m", lat, ok=True, now=1 + i)
    s = llm_metrics.summary(now=10)
    assert s["latency_drift"] == 200.0   # свежая половина медленнее предыдущей на 200 мс


def test_empty_summary_is_zeroed(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    s = llm_metrics.summary(now=1)
    assert s["calls"] == 0 and s["cost_total"] == 0.0
