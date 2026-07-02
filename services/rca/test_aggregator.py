"""Модульный тест агрегатора (ADR-0032, Часть B). Запуск без зависимостей:
python3 services/rca/test_aggregator.py
"""
from aggregator import aggregate, trace_key


RECORDS = [
    {"ts": "2026-07-01T12:00:01Z", "level": "info", "service": "api", "msg": "http request",
     "event": "http.request", "http.status": 200, "trace_id": "t1", "latency_ms": 5, "target": "worker"},
    {"ts": "2026-07-01T12:00:02Z", "level": "info", "service": "worker", "msg": "ml call",
     "event": "ml.call", "http.status": 200, "trace_id": "t1", "latency_ms": 1200, "target": "asr"},
    {"ts": "2026-07-01T12:00:03Z", "level": "error", "service": "worker", "msg": "ml call failed",
     "event": "ml.call", "http.status": 500, "trace_id": "t1", "target": "llm", "latency_ms": 30,
     "error_signal": "connection_refused", "tenant_id": "T1", "job_id": "J1"},
    {"ts": "2026-07-01T12:00:04Z", "level": "info", "service": "api", "msg": "http request",
     "event": "http.request", "http.status": 200, "trace_id": "t2", "latency_ms": 8, "target": "worker"},
    {"ts": "2026-07-01T12:00:05Z", "level": "warn", "service": "llm", "msg": "model slow", "trace_id": "t2"},
    {"ts": "2026-07-01T12:00:06Z", "level": "error", "service": "api", "msg": "http request",
     "event": "http.request", "http.status": 503, "trace_id": "t2", "error_signal": "http_5xx",
     "tenant_id": "T2", "job_id": "J2"},
]


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def main() -> None:
    # Извлечение номера по первому корреляционному полю (в т.ч. синонимы).
    _eq("trace_key trace_id", trace_key({"trace_id": "abc"}), "abc")
    _eq("trace_key traceparent", trace_key({"traceparent": "xyz"}), "xyz")
    _eq("trace_key none", trace_key({"foo": "bar"}), "")

    f = aggregate(RECORDS)
    _eq("total_lines", f["total_lines"], 6)
    _eq("level_counts", f["level_counts"], {"info": 3, "error": 2, "warn": 1})
    _eq("error_rate", f["error_rate"], round(2 / 6, 4))
    _eq("by_service", f["by_service"], {"api": 3, "worker": 2, "llm": 1})
    _eq("by_service_errors", f["by_service_errors"], {"worker": 1, "api": 1})
    _eq("error_signals", f["error_signals"], {"connection_refused": 1, "http_5xx": 1})
    _eq("status_classes", f["status_classes"], {"2xx": 3, "5xx": 2})
    _eq("event_counts", f["event_counts"], {"http.request": 3, "ml.call": 2})
    _eq("dominant_template_share", f["dominant_template_share"], 0.5)
    _eq("top_template_head", f["top_templates"][0], ("http request", 3))
    _eq("edges", f["edges"], {"api->worker": 2, "worker->asr": 1, "worker->llm": 1})
    _eq("latency worker count", f["latency_by_target"]["worker"]["count"], 2)
    _eq("latency worker mean", f["latency_by_target"]["worker"]["mean_ms"], 6.5)
    _eq("distinct_traces", f["distinct_traces"], 2)
    _eq("errored_traces", f["errored_traces"], 2)
    _eq("blast_radius", f["blast_radius"], {"tenants": 2, "jobs": 2})
    _eq("time_span", f["time_span"], {"from": "2026-07-01T12:00:01Z", "to": "2026-07-01T12:00:06Z"})
    _eq("fact_block_count", len(f), 16)
    print("aggregator: all asserts passed (16 fact blocks)")


if __name__ == "__main__":
    main()
