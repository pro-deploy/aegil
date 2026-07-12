"""Тесты агрегатора фактов. Собираемый вид pytest (функции test_*).

Запуск: cd services/rca && python3 -m pytest -q test_aggregator.py
"""
from aggregator import aggregate, trace_key


# Структурное окно логов с универсальными полями Kubernetes (pod, namespace).
# Каждая строка несёт метку времени Loki в поле _ts_ns.
RECORDS = [
    {"_ts_ns": 1, "level": "info", "service": "api", "msg": "http request",
     "event": "http.request", "http.status": 200, "trace_id": "t1", "latency_ms": 5, "target": "worker"},
    {"_ts_ns": 2, "level": "info", "service": "worker", "msg": "call downstream",
     "event": "call", "http.status": 200, "trace_id": "t1", "latency_ms": 1200, "target": "billing"},
    {"_ts_ns": 3, "level": "error", "service": "worker", "msg": "dial tcp: connection refused",
     "event": "call", "http.status": 500, "trace_id": "t1", "target": "billing", "latency_ms": 30,
     "pod": "worker-1", "namespace": "prod", "container": "worker"},
    {"_ts_ns": 4, "level": "info", "service": "api", "msg": "http request",
     "event": "http.request", "http.status": 200, "trace_id": "t2", "latency_ms": 8, "target": "worker"},
    {"_ts_ns": 5, "level": "warn", "service": "billing", "msg": "slow response", "trace_id": "t2"},
    {"_ts_ns": 6, "level": "error", "service": "api", "msg": "upstream returned 503",
     "event": "http.request", "http.status": 503, "trace_id": "t2",
     "pod": "api-1", "namespace": "prod", "container": "api"},
]


def test_trace_key_first_present_field():
    assert trace_key({"trace_id": "abc"}) == "abc"
    assert trace_key({"traceparent": "xyz"}) == "xyz"
    assert trace_key({"foo": "bar"}) == ""


def test_basic_counts():
    f = aggregate(RECORDS)
    assert f["total_lines"] == 6
    assert f["level_counts"] == {"info": 3, "error": 2, "warn": 1}
    assert f["error_rate"] == round(2 / 6, 4)
    assert f["by_service"] == {"api": 3, "worker": 2, "billing": 1}
    assert f["by_service_errors"] == {"worker": 1, "api": 1}


def test_symptoms_extracted_from_text_not_canon():
    # Симптом connection_refused извлекается из ТЕКСТА, а не из чужого поля error_signal.
    f = aggregate(RECORDS)
    assert f["symptom_counts"].get("connection_refused") == 1


def test_status_and_events():
    f = aggregate(RECORDS)
    assert f["status_classes"] == {"2xx": 3, "5xx": 2}
    assert f["event_counts"] == {"http.request": 3, "call": 2}


def test_templates_and_dominant_share():
    f = aggregate(RECORDS)
    assert f["top_templates"][0] == ("http request", 2)
    assert f["dominant_template_share"] == round(2 / 6, 4)


def test_edges_and_latency():
    f = aggregate(RECORDS)
    assert f["edges"] == {"api->worker": 2, "worker->billing": 2}
    assert f["latency_by_target"]["worker"]["count"] == 2
    assert f["latency_by_target"]["worker"]["mean_ms"] == 6.5


def test_traces():
    f = aggregate(RECORDS)
    assert f["distinct_traces"] == 2
    assert f["errored_traces"] == 2


def test_blast_radius_is_k8s_not_legacy():
    # Радиус поражения по универсальным сущностям Kubernetes, а не по тенантам и заданиям.
    f = aggregate(RECORDS)
    assert f["blast_radius"] == {"pods": 2, "namespaces": 1, "containers": 2}


def test_time_span_uses_loki_timestamps():
    f = aggregate(RECORDS)
    assert f["time_span"] == {"from_ns": 1, "to_ns": 6}


def test_plain_text_logs_are_visible():
    # Негативная проверка слепоты к текстовым логам: строка без структуры (panic пода)
    # всё равно даёт уровень fatal и учитывается как ошибка.
    text_only = [
        {"msg": "panic: runtime error: invalid memory address", "level": "fatal", "_ts_ns": 1},
        {"msg": "goroutine 1 [running]", "level": "info", "_ts_ns": 2},
    ]
    f = aggregate(text_only)
    assert f["level_counts"].get("fatal") == 1
    assert f["error_rate"] > 0


def test_latency_target_cardinality_capped(monkeypatch):
    # Взрыв кардинальности целей латентности обуздан: множество уникальных целей
    # сворачивается, число ключей статистики не превышает лимит плюс корзину __other__.
    import aggregator
    monkeypatch.setattr(aggregator, "MAX_LATENCY_TARGETS", 3)
    recs = [{"service": "s", "target": f"addr-{i}", "latency_ms": float(i), "_ts_ns": i}
            for i in range(50)]
    f = aggregate(recs)
    assert len(f["latency_by_target"]) <= 3 + 1
    assert "__other__" in f["latency_by_target"]
