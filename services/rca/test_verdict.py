"""Модульный тест сборки вердикта RCA и гардов (ADR-0032, Часть B).
Запуск без зависимостей: python3 services/rca/test_verdict.py
"""
from aggregator import aggregate
from detectors import detect
from scoring import score
from verdict import build, guard
from test_aggregator import RECORDS

HEALTHY = [
    {"ts": "2026-07-01T09:00:01Z", "level": "info", "service": "api", "msg": "http request",
     "event": "http.request", "http.status": 200, "trace_id": "h1"},
    {"ts": "2026-07-01T09:00:02Z", "level": "info", "service": "worker", "msg": "job done",
     "event": "job.done", "trace_id": "h1"},
]


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def main() -> None:
    # Гард: без свидетельств утверждение отбрасывается.
    _eq("guard drops", guard("причина", []), None)
    _eq("guard keeps", guard("причина", [{"x": 1}]), "причина")

    facts = aggregate(RECORDS)
    dets = detect(facts)
    s = score(dets)
    v = build(facts, dets, s, RECORDS)

    # Пятиполевая схема присутствует.
    for field in ("status", "confidence", "root_cause", "evidence", "action"):
        assert field in v, f"нет поля {field}"

    # Маленькое окно с двумя ошибками честно даёт degraded/uncertain, а не incident.
    _eq("status", v["status"], "degraded")
    _eq("band", v["confidence"]["band"], "uncertain")
    # Корень это первичный физический отказ у цели llm (не вторичная отмена).
    _eq("root_cause", v["root_cause"], "Первичный отказ «connection_refused» у цели llm")
    assert v["action"], "действие должно быть заполнено при наличии свидетельств"
    # Реестр свидетельств: две подтверждающие ошибки (connection_refused и 5xx).
    _eq("evidence count", len(v["evidence"]), 2)
    for e in v["evidence"]:
        _eq("kind", e["kind"], "log")
        _eq("grounded", e["grounded"], True)
        assert e["source"].startswith("log:"), e["source"]
        assert e["snippet"], "сниппет не должен быть пустым (дословная цитата)"

    # Здоровое окно: статус healthy, первопричина и действие отброшены гардом.
    hf = aggregate(HEALTHY)
    hv = build(hf, detect(hf), score(detect(hf)), HEALTHY)
    _eq("healthy status", hv["status"], "healthy")
    _eq("healthy root_cause", hv["root_cause"], None)
    _eq("healthy action", hv["action"], None)
    _eq("healthy evidence", hv["evidence"], [])

    # Прикладные ошибки без сетевого сигнала: причина заземлена в окне (сервис и
    # доминирующий шаблон), а не выдуманный каскад вверх по графу.
    app = [{"level": "info", "service": "embed", "msg": "ok", "trace_id": f"a{i}"} for i in range(30)]
    app += [{"level": "error", "service": "embed", "msg": "pgvector dim mismatch",
             "trace_id": f"ae{i}", "error_signal": "unknown", "tenant_id": f"T{i}", "job_id": f"J{i}"}
            for i in range(20)]
    af = aggregate(app)
    av = build(af, detect(af), score(detect(af)), app)
    assert "Прикладные ошибки сервиса embed" in av["root_cause"], av["root_cause"]
    assert "каскад" not in av["root_cause"].lower(), "не должно быть выдуманного каскада"

    # Первичный отказ самого сервиса (oom) атрибутируется сервису, а не цели unknown.
    oom = [{"level": "error", "service": "llm", "msg": "cuda oom", "trace_id": f"o{i}",
            "error_signal": "oom", "tenant_id": f"T{i}", "job_id": f"J{i}"} for i in range(10)]
    of = aggregate(oom)
    ov = build(of, detect(of), score(detect(of)), oom)
    _eq("oom locus", ov["root_cause"], "Первичный отказ «oom» у сервиса llm")

    # Законный каскад: только вторичные отмены, первичного в окне нет.
    sec = [{"level": "error", "service": "worker", "msg": "deadline", "trace_id": f"s{i}",
            "error_signal": "deadline_exceeded", "tenant_id": f"T{i}", "job_id": f"J{i}"} for i in range(10)]
    sf = aggregate(sec)
    sv = build(sf, detect(sf), score(detect(sf)), sec)
    assert "Каскад отмен" in sv["root_cause"], sv["root_cause"]

    print("verdict: all asserts passed")


if __name__ == "__main__":
    main()
