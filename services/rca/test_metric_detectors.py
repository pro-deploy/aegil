"""Тесты детекторов по метрикам золотых сигналов и их встраивания в конвейер. Вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_metric_detectors.py
"""
from metric_detectors import detect_metrics
from pipeline import analyze
from scoring import score


def _fired(dets):
    return {d["id"] for d in dets if d["fired"]}


def test_no_metrics_no_detectors():
    assert detect_metrics({"present": False}) == []
    assert detect_metrics({}) == []


def test_latency_spike_fires_above_threshold():
    mf = {"present": True, "latency_p95_ms": 1500.0}
    d = detect_metrics(mf)
    assert "ML1" in _fired(d)
    ml1 = [x for x in d if x["id"] == "ML1"][0]
    assert ml1["applicable"] is True and "lr_absent" in ml1


def test_latency_normal_does_not_fire():
    assert "ML1" not in _fired(detect_metrics({"present": True, "latency_p95_ms": 120.0}))


def test_saturation_group_shared():
    # Насыщение процессора и памяти делят группу m_saturation: скоринг берёт максимум один раз.
    mf = {"present": True, "cpu_saturation": 0.95, "mem_saturation": 0.97}
    d = detect_metrics(mf)
    assert _fired(d) == {"ML2", "ML3"}
    s = score(d)
    assert s["group_max"] == {"m_saturation": 5.0}


def test_metric_error_ratio_fires():
    assert "ML4" in _fired(detect_metrics({"present": True, "error_rate": 0.2}))


def test_traffic_drop_needs_baseline():
    mf = {"present": True, "req_rate": 1.0}
    assert "ML5" not in _fired(detect_metrics(mf))                       # без базовой линии не судим
    d = detect_metrics(mf, baseline={"req_rate": 100.0})
    assert "ML5" in _fired(d)                                            # обвал 100 -> 1


def test_infrastructure_signals_fire():
    # Полный набор инфраструктурных сигналов, что обычно на дашбордах узла в графане.
    mf = {"present": True, "cpu_throttling": 0.6, "disk_usage": 0.95, "pvc_usage": 0.5,
          "node_not_ready": 1, "node_disk_pressure": 1, "node_mem_pressure": 0,
          "oom_events": 3, "pod_pending": 4, "net_errors": 12.0}
    ids = _fired(detect_metrics(mf))
    assert {"ML6", "ML7", "ML9", "ML10", "ML11", "ML12", "ML13"} <= ids
    assert "ML8" not in ids   # том заполнен лишь наполовину, не тревога


def test_throttling_shares_saturation_group():
    # Троттлинг процессора считается вместе с насыщением процессора одной волной.
    mf = {"present": True, "cpu_saturation": 0.95, "cpu_throttling": 0.6}
    s = score(detect_metrics(mf))
    assert s["group_max"] == {"m_saturation": 5.0}


def test_node_down_is_strong_signal():
    # Неготовность узла это сильный сигнал уровня железа, вес выше прикладных детекторов.
    d = [x for x in detect_metrics({"present": True, "node_not_ready": 2}) if x["id"] == "ML9"][0]
    assert d["fired"] is True and d["lr"] == 7.0


def test_healthy_infra_does_not_fire():
    mf = {"present": True, "cpu_throttling": 0.02, "disk_usage": 0.4, "node_not_ready": 0,
          "node_disk_pressure": 0, "node_mem_pressure": 0, "oom_events": 0, "pod_pending": 0,
          "net_errors": 0.0}
    assert _fired(detect_metrics(mf)) == set()


def test_pipeline_merges_metric_detectors():
    # Логи чистые (здоровое окно), но метрики показывают насыщение и задержку: детекторы метрик
    # добавляются к логовым, поднимают уверенность и попадают в вывод.
    healthy = [{"level": "info", "service": "api", "msg": "ok", "_ts_ns": i} for i in range(20)]
    mf = {"present": True, "latency_p95_ms": 2000.0, "cpu_saturation": 0.96}
    out = analyze(healthy, metric_facts=mf)
    ids = {d["id"] for d in out["detectors"] if d["fired"]}
    assert "ML1" in ids and "ML2" in ids
    assert out["metric_facts"]["present"] is True
    # Без метрик те же логи не дают этих сигналов.
    assert not {d["id"] for d in analyze(healthy)["detectors"] if d["fired"]} & {"ML1", "ML2"}
