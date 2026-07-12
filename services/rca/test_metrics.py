"""Тесты читателя метрик золотых сигналов. Собираемый вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_metrics.py
"""
import metrics


def _range(series):
    """Строит ответ query_range из списка серий, каждая это список пар (метка_времени, значение)."""
    return {"status": "success", "data": {"resultType": "matrix", "result": [
        {"metric": {}, "values": [[ts, str(v)] for ts, v in s]} for s in series]}}


def test_parse_matrix_skips_nonnumeric():
    j = {"data": {"result": [{"values": [[1000, "0.2"], [1015, "нечисло"], [1030, "0.5"]]}]}}
    series = metrics.parse_matrix(j)
    assert series == [[(1000, 0.2), (1030, 0.5)]]


def test_reduce_signal_last_max_mean():
    # Последнее значение это максимум среди серий на самой поздней метке времени.
    series = [[(1000, 0.2), (1015, 0.5)], [(1015, 0.9)]]
    r = metrics.reduce_signal(series)
    assert r["last"] == 0.9
    assert r["max"] == 0.9
    assert r["mean"] == round((0.2 + 0.5 + 0.9) / 3, 6)
    assert r["count"] == 3


def test_reduce_empty_is_none():
    assert metrics.reduce_signal([]) is None


def test_build_facts_exposes_top_level_signals():
    named = {
        "latency_p95_ms": _range([[(1000, 800.0), (1015, 1200.0)]]),
        "cpu_saturation": _range([[(1015, 0.95)]]),
        "error_rate": _range([[(1015, 0.2)]]),
    }
    f = metrics.build_facts(named)
    assert f["present"] is True
    assert f["latency_p95_ms"] == 1200.0
    assert f["cpu_saturation"] == 0.95
    assert f["error_rate"] == 0.2
    assert f["mem_saturation"] is None       # сигнал не пришёл, честно None
    assert "latency_p95_ms" in f["signals"]


def test_build_facts_empty_is_not_present():
    assert metrics.build_facts({})["present"] is False
    assert metrics.build_facts({"error_rate": {"data": {"result": []}}})["present"] is False


def test_fetch_without_url_degrades():
    # Без адреса хранилища слой честно пуст, а не падает.
    assert metrics.fetch(prom_url="")["present"] is False
