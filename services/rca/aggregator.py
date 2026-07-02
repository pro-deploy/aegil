"""Детерминированный агрегатор за один проход O(N) (ADR-0032, Часть B.2; книга
Биркина, глава 4). Считает по окну лог-строк шестнадцать блоков фактов чистой
математикой, без языковой модели, и группирует строки по сквозному номеру по
десяти корреляционным полям. Вход это разобранные из JSON канонические лог-записи
(словари с полями ts, level, service, msg, trace_id, event, error_signal, target,
http.status, latency_ms, tenant_id, job_id и прочими). Стоимость линейна по входу;
перцентиль латентности считается на финализации по собранным значениям.

Модуль намеренно без внешних зависимостей, чтобы его логику можно было проверять
модульно и запускать на центральном процессоре без ускорителя.
"""
from __future__ import annotations

from normalize import template as _template

# Десять корреляционных полей (глава 4.8): первое присутствующее и есть номер.
CORRELATION_FIELDS = (
    "trace_id", "traceId", "x-request-id", "request_id", "req_id",
    "correlation_id", "traceparent", "x-correlation-id", "span_id", "txn_id",
)

# Поля цели межсервисного вызова (глава 8.4): источник рёбер топологии.
TARGET_FIELDS = (
    "target", "upstream", "peer", "remote_addr", "dest", "host",
    "downstream", "addr", "server",
)


def trace_key(rec: dict) -> str:
    """Извлекает сквозной номер по первому присутствующему корреляционному полю."""
    for f in CORRELATION_FIELDS:
        v = rec.get(f)
        if v:
            return str(v)
    return ""


def _target(rec: dict) -> str:
    for f in TARGET_FIELDS:
        v = rec.get(f)
        if v:
            return str(v)
    return ""


def _status_class(status) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return ""
    return f"{code // 100}xx"


def _pct(values: list[float], q: float) -> float:
    """Перцентиль q (0..1) методом ближайшего ранга. Values не пусты."""
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    idx = int(round(q * (len(s) - 1)))
    return s[idx]


def aggregate(records) -> dict:
    """Один проход по записям окна. Возвращает шестнадцать блоков фактов."""
    total = 0
    level_counts: dict[str, int] = {}
    by_service: dict[str, int] = {}
    by_service_errors: dict[str, int] = {}
    error_signals: dict[str, int] = {}
    status_classes: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    template_counts: dict[str, int] = {}
    edges: dict[str, int] = {}
    latencies_by_target: dict[str, list] = {}
    traces: set = set()
    errored_traces: set = set()
    affected_tenants: set = set()
    affected_jobs: set = set()
    ts_min: str | None = None
    ts_max: str | None = None

    for rec in records:
        total += 1
        level = str(rec.get("level", "")).lower()
        service = str(rec.get("service", "")) or "unknown"
        is_error = level in ("error", "fatal")

        level_counts[level] = level_counts.get(level, 0) + 1
        by_service[service] = by_service.get(service, 0) + 1
        if is_error:
            by_service_errors[service] = by_service_errors.get(service, 0) + 1

        sig = rec.get("error_signal")
        if sig:
            error_signals[str(sig)] = error_signals.get(str(sig), 0) + 1

        sc = _status_class(rec.get("http.status", rec.get("status")))
        if sc:
            status_classes[sc] = status_classes.get(sc, 0) + 1

        ev = rec.get("event")
        if ev:
            event_counts[str(ev)] = event_counts.get(str(ev), 0) + 1

        msg = str(rec.get("msg", ""))
        if msg:
            tmpl = _template(msg)  # нормализация Drain3-стиля: переменные в маски
            template_counts[tmpl] = template_counts.get(tmpl, 0) + 1

        tgt = _target(rec)
        if tgt:
            edge = f"{service}->{tgt}"
            edges[edge] = edges.get(edge, 0) + 1
            lat = rec.get("latency_ms", rec.get("model_latency_ms"))
            if isinstance(lat, (int, float)):
                latencies_by_target.setdefault(tgt, []).append(float(lat))

        tk = trace_key(rec)
        if tk:
            traces.add(tk)
            if is_error:
                errored_traces.add(tk)

        if is_error:
            if rec.get("tenant_id"):
                affected_tenants.add(str(rec["tenant_id"]))
            if rec.get("job_id"):
                affected_jobs.add(str(rec["job_id"]))

        ts = rec.get("ts")
        if ts:
            ts = str(ts)
            if ts_min is None or ts < ts_min:
                ts_min = ts
            if ts_max is None or ts > ts_max:
                ts_max = ts

    errors = level_counts.get("error", 0) + level_counts.get("fatal", 0)
    top_templates = sorted(template_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    dominant_share = (top_templates[0][1] / total) if (total and top_templates) else 0.0

    latency_stats = {}
    for tgt, vals in latencies_by_target.items():
        latency_stats[tgt] = {
            "count": len(vals),
            "mean_ms": round(sum(vals) / len(vals), 1),
            "max_ms": max(vals),
            "p95_ms": _pct(vals, 0.95),
        }

    # Шестнадцать блоков фактов.
    return {
        "total_lines": total,                                    # 1
        "level_counts": level_counts,                            # 2
        "error_rate": round(errors / total, 4) if total else 0.0,  # 3
        "by_service": by_service,                                # 4
        "by_service_errors": by_service_errors,                  # 5
        "error_signals": error_signals,                          # 6
        "status_classes": status_classes,                        # 7
        "event_counts": event_counts,                            # 8
        "top_templates": top_templates,                          # 9
        "dominant_template_share": round(dominant_share, 4),     # 10
        "edges": edges,                                          # 11
        "latency_by_target": latency_stats,                      # 12
        "distinct_traces": len(traces),                          # 13
        "errored_traces": len(errored_traces),                   # 14
        "blast_radius": {                                        # 15
            "tenants": len(affected_tenants),
            "jobs": len(affected_jobs),
        },
        "time_span": {"from": ts_min, "to": ts_max},             # 16
    }
