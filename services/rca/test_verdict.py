"""Тесты сборки вердикта первопричины и гардов. Собираемый вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_verdict.py
"""
from aggregator import aggregate
from detectors import detect
from scoring import score
from verdict import build, guard
from test_aggregator import RECORDS


def _run(recs, baseline=None):
    f = aggregate(recs)
    bf = aggregate(baseline) if baseline else None
    d = detect(f, bf)
    s = score(d)
    return build(f, d, s, recs)


def test_guard_requires_evidence():
    assert guard("причина", []) is None
    assert guard("причина", [{"x": 1}]) == "причина"


def test_five_field_schema():
    v = _run(RECORDS)
    for field in ("status", "confidence", "root_cause", "evidence", "action"):
        assert field in v


def test_records_root_is_primary_call_failure():
    v = _run(RECORDS)
    assert v["status"] == "degraded"
    assert v["confidence"]["band"] == "uncertain"
    # Корень это первичный физический отказ у вызываемой цели, а не вторичная отмена.
    assert v["root_cause"] == "Первичный отказ «connection_refused» у цели billing"
    assert v["action"]
    for e in v["evidence"]:
        assert e["kind"] == "log"
        assert e["grounded"] is True
        assert e["source"].startswith("log:")
        assert e["snippet"]


def test_healthy_window_drops_claims():
    healthy = [{"level": "info", "service": "api", "msg": "ok", "_ts_ns": i} for i in range(5)]
    hv = _run(healthy)
    assert hv["status"] == "healthy"
    assert hv["root_cause"] is None
    assert hv["action"] is None
    assert hv["evidence"] == []


def test_not_healthy_on_real_spike():
    # Негативная проверка парадокса «здоровье при реальном всплеске»: явная волна
    # ошибок с сетевым симптомом не может быть объявлена здоровой из-за недобора полосы.
    wave = [{"level": "info", "service": "api", "msg": "ok", "_ts_ns": i} for i in range(6)]
    wave += [{"level": "error", "service": "api", "msg": "connection refused",
              "pod": f"api-{i}", "namespace": "prod", "_ts_ns": 100 + i} for i in range(4)]
    v = _run(wave)
    assert v["status"] in ("degraded", "incident")
    assert v["status"] != "healthy"
    assert v["root_cause"]


def test_root_chosen_by_dominance_not_order():
    # Негативная проверка выбора «первый встреченный»: единичный редкий сигнал в начале
    # окна не должен перебивать массовую доминирующую причину.
    recs = [{"level": "error", "service": "db", "msg": "out of memory", "pod": "db-0",
             "namespace": "prod", "_ts_ns": -1}]
    recs += [{"level": "error", "service": "api", "msg": "connection refused", "pod": f"a{i}",
              "namespace": "prod", "_ts_ns": i} for i in range(8)]
    v = _run(recs)
    assert "connection_refused" in v["root_cause"]
    assert "oom" not in v["root_cause"]


def test_self_locus_oom_attributed_to_service():
    oom = [{"level": "error", "service": "llm", "msg": "fatal: out of memory (oom killed)",
            "pod": f"llm-{i}", "namespace": "prod", "_ts_ns": i} for i in range(10)]
    assert _run(oom)["root_cause"] == "Первичный отказ «oom» у сервиса llm"


def test_secondary_only_is_legitimate_cascade():
    sec = [{"level": "error", "service": "worker", "msg": "context deadline exceeded",
            "pod": f"w{i}", "namespace": "prod", "_ts_ns": i} for i in range(10)]
    assert "Каскад отмен" in _run(sec)["root_cause"]


def test_application_errors_without_network_signal():
    app = [{"level": "info", "service": "embed", "msg": "ok", "_ts_ns": i} for i in range(30)]
    app += [{"level": "error", "service": "embed", "msg": "vector dimension mismatch",
             "pod": f"e{i}", "namespace": "prod", "_ts_ns": 100 + i} for i in range(20)]
    v = _run(app)
    assert "Прикладные ошибки сервиса embed" in v["root_cause"]
    assert "каскад" not in v["root_cause"].lower()


def test_metric_only_incident_is_reported():
    # Логи окна чистые, но метрики золотых сигналов бьют по железу (узел отвалился, диск полон).
    # Вердикт ОБЯЗАН заявить инцидент с инфраструктурной первопричиной, а не объявить здоровье.
    from metric_detectors import detect_metrics
    healthy = [{"level": "info", "service": "api", "msg": "ok", "_ts_ns": i} for i in range(20)]
    f = aggregate(healthy)
    d = detect(f) + detect_metrics({"present": True, "node_not_ready": 1, "disk_usage": 0.96})
    v = build(f, d, score(d), healthy)
    assert v["status"] in ("incident", "degraded")   # заявлен инцидент, а не здоровье
    assert v["status"] != "healthy"
    assert "узла" in v["root_cause"]           # приоритет отказа узла над диском
    assert v["action"]
    assert v["evidence"] and v["evidence"][0]["kind"] == "metric" and v["evidence"][0]["grounded"] is True


def test_symptoms_read_from_plain_text_logs():
    # Негативная проверка слепоты: вердикт по ПРОСТЫМ текстовым логам подов (без
    # структурного поля error_signal) всё равно опознаёт сетевую первопричину.
    text = [{"msg": f"i={i}", "level": "info", "_ts_ns": i} for i in range(6)]
    text += [{"msg": "dial tcp 10.0.0.5:5432: connect: connection refused",
              "level": "error", "service": "api", "pod": f"api-{i}", "namespace": "prod",
              "_ts_ns": 100 + i} for i in range(5)]
    v = _run(text)
    assert v["status"] != "healthy"
    assert "connection_refused" in v["root_cause"]
