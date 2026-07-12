"""Детерминированный агрегатор фактов окна логов за один проход O(N).

Модуль считает по окну лог-строк набор блоков фактов чистой математикой, без
языковой модели, и группирует коррелированные строки по сквозному номеру трассы.
Вход это разобранные лог-записи (словари). Запись может прийти как из структурного
лога приложения (поля level, service, msg, trace_id, status и прочие), так и из
произвольной текстовой строки лога пода Kubernetes, у которой из полей есть только
сообщение и выведенный уровень. Поэтому агрегатор не полагается на поля конкретного
логирующего канона: сетевые и инфраструктурные симптомы он извлекает из текста
сообщения универсальным каталогом (модуль normalize), а не из чужого поля.

Единицы поражения универсальны для Kubernetes: под, пространство имён, контейнер.
Наследные поля тенанта и задания убраны как доменно-специфичные.

Модуль намеренно без внешних зависимостей, чтобы его логику можно было проверять
модульно и запускать на центральном процессоре без ускорителя.
"""
from __future__ import annotations

import os

from normalize import extract_symptoms, template as _template

# Сквозной номер трассы: первое присутствующее из корреляционных полей и есть номер.
CORRELATION_FIELDS = (
    "trace_id", "traceId", "x-request-id", "request_id", "req_id",
    "correlation_id", "traceparent", "x-correlation-id", "span_id", "txn_id",
)

# Поля цели межсервисного вызова: источник рёбер топологии. В свободном тексте лога
# этих полей обычно нет, поэтому список рёбер строится только при структурном логе.
TARGET_FIELDS = (
    "target", "upstream", "peer", "dest", "downstream", "server",
)

# Поля идентичности рабочей нагрузки Kubernetes. Имя сервиса выводится из них, а при
# их отсутствии из поля service структурного лога.
POD_FIELDS = ("pod", "pod_name", "kubernetes.pod_name", "k8s_pod")
NAMESPACE_FIELDS = ("namespace", "ns", "kubernetes.namespace_name", "k8s_namespace")
CONTAINER_FIELDS = ("container", "container_name", "kubernetes.container_name", "k8s_container")
SERVICE_FIELDS = ("service", "app", "app_kubernetes_io_name", "component") + CONTAINER_FIELDS

# Ограничитель кардинальности целей латентности. Свободные сетевые поля (адреса, хосты,
# удалённые узлы) порождают неограниченное число уникальных значений, поэтому статистику
# латентности собираем лишь по ограниченному числу самых нагруженных целей, а остальные
# сворачиваем в служебную корзину «__other__». Порог настраивается окружением.
MAX_LATENCY_TARGETS = int(os.getenv("SENTINEL_RCA_MAX_LATENCY_TARGETS", "50"))
TOP_TEMPLATES = int(os.getenv("SENTINEL_RCA_TOP_TEMPLATES", "10"))


def _first(rec: dict, fields) -> str:
    for f in fields:
        v = rec.get(f)
        if v:
            return str(v)
    return ""


def trace_key(rec: dict) -> str:
    """Извлекает сквозной номер по первому присутствующему корреляционному полю."""
    return _first(rec, CORRELATION_FIELDS)


def _service(rec: dict) -> str:
    return _first(rec, SERVICE_FIELDS) or "unknown"


def _target(rec: dict) -> str:
    return _first(rec, TARGET_FIELDS)


def _status_class(status) -> str:
    try:
        code = int(status)
    except (TypeError, ValueError):
        return ""
    return f"{code // 100}xx"


def _symptoms(rec: dict) -> set:
    """Симптомы записи: извлечённые из текста сообщения плюс, если структурный лог
    честно нёс поле-симптом, оно тоже учитывается. Опора на текст делает извлечение
    домен-агностичным и не зависящим от наличия чужого структурного поля."""
    syms = extract_symptoms(str(rec.get("msg", "")) or str(rec.get("_raw", "")))
    sig = rec.get("error_signal")
    if sig:
        syms.add(str(sig))
    return syms


def _pct(values: list, q: float) -> float:
    """Перцентиль q (0..1) методом ближайшего ранга. Values не пусты."""
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    idx = int(round(q * (len(s) - 1)))
    return s[idx]


def aggregate(records) -> dict:
    """Один проход по записям окна. Возвращает блоки фактов детерминированно."""
    total = 0
    level_counts: dict = {}
    by_service: dict = {}
    by_service_errors: dict = {}
    symptom_counts: dict = {}
    status_classes: dict = {}
    event_counts: dict = {}
    template_counts: dict = {}
    edges: dict = {}
    latencies_by_target: dict = {}
    traces: set = set()
    errored_traces: set = set()
    affected_pods: set = set()
    affected_namespaces: set = set()
    affected_containers: set = set()
    ts_min = None
    ts_max = None
    # Временная канва окна: события с меткой времени и активность каждого источника
    # по времени. Отсюда строится временной ряд, который питает детекторы перерыва в
    # логах, молчания источника и демпфера восстановления. Строится только из реальных
    # меток _ts_ns, поэтому при их отсутствии ряд честно пуст, а детекторы неприменимы.
    ts_events: list = []          # (метка_времени, признак_ошибки) по записям с временем
    service_first: dict = {}      # сервис -> самая ранняя метка времени
    service_last: dict = {}       # сервис -> самая поздняя метка времени
    service_ts_count: dict = {}   # сервис -> число записей с временем
    service_ts_errors: dict = {}  # сервис -> число ошибочных записей с временем

    for rec in records:
        total += 1
        level = str(rec.get("level", "")).lower()
        service = _service(rec)
        is_error = level in ("error", "fatal")

        level_counts[level] = level_counts.get(level, 0) + 1
        by_service[service] = by_service.get(service, 0) + 1
        if is_error:
            by_service_errors[service] = by_service_errors.get(service, 0) + 1

        for sym in _symptoms(rec):
            symptom_counts[sym] = symptom_counts.get(sym, 0) + 1

        sc = _status_class(rec.get("http.status", rec.get("status")))
        if sc:
            status_classes[sc] = status_classes.get(sc, 0) + 1

        ev = rec.get("event")
        if ev:
            event_counts[str(ev)] = event_counts.get(str(ev), 0) + 1

        msg = str(rec.get("msg", ""))
        if msg:
            tmpl = _template(msg)
            template_counts[tmpl] = template_counts.get(tmpl, 0) + 1

        tgt = _target(rec)
        if tgt:
            edges[f"{service}->{tgt}"] = edges.get(f"{service}->{tgt}", 0) + 1
            lat = rec.get("latency_ms", rec.get("duration_ms"))
            if isinstance(lat, (int, float)):
                latencies_by_target.setdefault(tgt, []).append(float(lat))

        tk = trace_key(rec)
        if tk:
            traces.add(tk)
            if is_error:
                errored_traces.add(tk)

        if is_error:
            pod = _first(rec, POD_FIELDS)
            if pod:
                affected_pods.add(pod)
            ns = _first(rec, NAMESPACE_FIELDS)
            if ns:
                affected_namespaces.add(ns)
            cont = _first(rec, CONTAINER_FIELDS)
            if cont:
                affected_containers.add(cont)

        ts = rec.get("_ts_ns")
        if isinstance(ts, (int, float)):
            if ts_min is None or ts < ts_min:
                ts_min = ts
            if ts_max is None or ts > ts_max:
                ts_max = ts
            ts_events.append((ts, is_error))
            if service not in service_first or ts < service_first[service]:
                service_first[service] = ts
            if service not in service_last or ts > service_last[service]:
                service_last[service] = ts
            service_ts_count[service] = service_ts_count.get(service, 0) + 1
            if is_error:
                service_ts_errors[service] = service_ts_errors.get(service, 0) + 1

    errors = level_counts.get("error", 0) + level_counts.get("fatal", 0)
    top_templates = sorted(template_counts.items(), key=lambda kv: kv[1], reverse=True)[:TOP_TEMPLATES]
    dominant_share = (top_templates[0][1] / total) if (total and top_templates) else 0.0

    # Ограничение кардинальности целей латентности: считаем статистику только по
    # самым нагруженным целям, остальные сворачиваем в корзину __other__, чтобы
    # свободные сетевые поля не порождали неограниченный список.
    ranked = sorted(latencies_by_target.items(), key=lambda kv: len(kv[1]), reverse=True)
    latency_stats: dict = {}
    other: list = []
    for i, (tgt, vals) in enumerate(ranked):
        if i < MAX_LATENCY_TARGETS:
            latency_stats[tgt] = {
                "count": len(vals),
                "mean_ms": round(sum(vals) / len(vals), 1),
                "max_ms": max(vals),
                "p95_ms": _pct(vals, 0.95),
            }
        else:
            other.extend(vals)
    if other:
        latency_stats["__other__"] = {
            "count": len(other),
            "mean_ms": round(sum(other) / len(other), 1),
            "max_ms": max(other),
            "p95_ms": _pct(other, 0.95),
        }

    # Временной ряд окна. Он присутствует только тогда, когда записи несли реальные
    # метки времени и окно имеет ненулевую протяжённость (есть хотя бы две различные
    # метки). Из отсортированной канвы времени считаются интервалы между соседними
    # событиями (для поиска перерыва в потоке логов), а также разбиение окна на раннюю
    # и позднюю половины по срединной метке (для оценки затухания или нарастания потока
    # ошибок). При отсутствии меток времени ряд честно помечен как отсутствующий, и
    # опирающиеся на него детекторы остаются неприменимыми.
    timeseries: dict = {"present": False}
    if ts_events and ts_min is not None and ts_max is not None and ts_max > ts_min:
        ordered = sorted(t for t, _ in ts_events)
        span = ts_max - ts_min
        interarrivals = [ordered[i + 1] - ordered[i] for i in range(len(ordered) - 1)]
        max_gap = max(interarrivals) if interarrivals else 0
        median_gap = _pct(interarrivals, 0.5) if interarrivals else 0
        midpoint = ts_min + span / 2.0
        early_lines = sum(1 for t in ordered if t < midpoint)
        early_errors = sum(1 for t, e in ts_events if e and t < midpoint)
        late_errors = sum(1 for _, e in ts_events if e) - early_errors
        timeseries = {
            "present": True,
            "from_ns": ts_min,
            "to_ns": ts_max,
            "span_ns": span,
            "lines": len(ordered),
            "distinct": len(set(ordered)),
            "max_gap_ns": max_gap,
            "median_gap_ns": median_gap,
            "early_lines": early_lines,
            "late_lines": len(ordered) - early_lines,
            "early_errors": early_errors,
            "late_errors": late_errors,
        }

    # Активность источников во времени: по каждому сервису самая ранняя и самая поздняя
    # метка, число записей и ошибок. Служит входом детектора молчания источника (сервис,
    # который эмитировал существенный объём в начале окна и полностью замолчал к концу).
    service_activity = {
        svc: {
            "first_ns": service_first[svc],
            "last_ns": service_last[svc],
            "count": service_ts_count.get(svc, 0),
            "errors": service_ts_errors.get(svc, 0),
        }
        for svc in service_first
    }

    return {
        "total_lines": total,
        "level_counts": level_counts,
        "error_rate": round(errors / total, 4) if total else 0.0,
        "by_service": by_service,
        "by_service_errors": by_service_errors,
        "symptom_counts": symptom_counts,
        "status_classes": status_classes,
        "event_counts": event_counts,
        "top_templates": top_templates,
        "dominant_template_share": round(dominant_share, 4),
        "edges": edges,
        "latency_by_target": latency_stats,
        "distinct_traces": len(traces),
        "errored_traces": len(errored_traces),
        "blast_radius": {
            "pods": len(affected_pods),
            "namespaces": len(affected_namespaces),
            "containers": len(affected_containers),
        },
        "time_span": {"from_ns": ts_min, "to_ns": ts_max},
        "timeseries": timeseries,
        "service_activity": service_activity,
    }
