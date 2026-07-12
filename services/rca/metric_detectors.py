"""Каталог детекторов по метрикам золотых сигналов.

Дополняет логовые детекторы (модуль detectors) сигналами, которых в тексте логов нет:
задержка, насыщение процессора и памяти, обвал трафика, доля ошибок по метрикам. Каждый
детектор потребляет свёрнутые факты метрик окна (модуль metrics) и, срабатывая, даёт вес в
виде отношения правдоподобия в том же формате, что и логовые детекторы, поэтому байесовский
скоринг обрабатывает их единообразно, а группировка не даёт коррелированным сигналам
(насыщение процессора и памяти это одна волна) считаться дважды.

Честность применимости сохранена: детектор применим только тогда, когда соответствующий
сигнал реально пришёл из хранилища метрик. Если метрик нет (present=False) или конкретный
сигнал отсутствует, детектор не выдаётся за рабочий и в скоринге не участвует. Пороги
некалиброванные, нейтральные, настраиваются окружением с префиксом AEGIL_.
"""
from __future__ import annotations

import os


def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


# Пороги.
LATENCY_P95_MS = _f("AEGIL_RCA_M_LATENCY_P95_MS", 1000.0)
SATURATION = _f("AEGIL_RCA_M_SATURATION", 0.9)
METRIC_ERROR_RATE = _f("AEGIL_RCA_M_ERROR_RATE", 0.05)
TRAFFIC_DROP_RATIO = _f("AEGIL_RCA_M_TRAFFIC_DROP_RATIO", 0.3)
THROTTLING = _f("AEGIL_RCA_M_THROTTLING", 0.25)      # доля придушенных периодов процессора
DISK_USAGE = _f("AEGIL_RCA_M_DISK_USAGE", 0.9)       # доля заполнения файловой системы или тома
PENDING_MIN = _f("AEGIL_RCA_M_PENDING_MIN", 1.0)     # число подов в Pending, с которого тревога
NET_ERRORS = _f("AEGIL_RCA_M_NET_ERRORS", 1.0)       # темп сетевых ошибок в секунду

# Веса как отношения правдоподобия при срабатывании.
W_LATENCY = _f("AEGIL_RCA_M_W_LATENCY", 5.0)
W_SATURATION = _f("AEGIL_RCA_M_W_SATURATION", 5.0)
W_METRIC_ERROR = _f("AEGIL_RCA_M_W_ERROR", 6.0)
W_TRAFFIC = _f("AEGIL_RCA_M_W_TRAFFIC", 4.0)
W_DISK = _f("AEGIL_RCA_M_W_DISK", 6.0)
W_NODE = _f("AEGIL_RCA_M_W_NODE", 7.0)
W_SCHEDULE = _f("AEGIL_RCA_M_W_SCHEDULE", 4.0)
W_OOM = _f("AEGIL_RCA_M_W_OOM", 6.0)
W_NETWORK = _f("AEGIL_RCA_M_W_NETWORK", 4.0)
LR_ABSENT = _f("AEGIL_RCA_M_LR_ABSENT", 0.7)


def _m(mid, name, fired, lr, group, evidence="", applicable=True, lr_absent=None):
    d = {"id": mid, "name": name, "fired": bool(fired), "lr": float(lr),
         "group": group, "evidence": evidence, "applicable": bool(applicable)}
    if lr_absent is not None:
        d["lr_absent"] = float(lr_absent)
    return d


def detect_metrics(metric_facts: dict, baseline: dict | None = None) -> list:
    """Прогоняет каталог детекторов метрик по фактам окна. baseline это факты метрик за прошлый
    период (для детектора обвала трафика). Возвращает список детекторов в формате скоринга. Пустой
    список, если метрик нет."""
    out: list = []
    mf = metric_facts or {}
    if not mf.get("present"):
        return out

    # ML1 всплеск задержки (группа m_latency). Двусторонний: применим при наличии сигнала, поэтому
    # нормальная задержка при живом сигнале слегка понижает шансы, а не игнорируется.
    p95 = mf.get("latency_p95_ms")
    if p95 is not None:
        out.append(_m("ML1", "latency_spike", p95 >= LATENCY_P95_MS, W_LATENCY, "m_latency",
                      f"p95={round(p95, 1)}ms", lr_absent=LR_ABSENT))

    # ML2 и ML3 насыщение процессора и памяти делят группу m_saturation: голос группы это максимум,
    # чтобы одновременное насыщение обоих не считалось двумя независимыми свидетельствами.
    cpu = mf.get("cpu_saturation")
    if cpu is not None:
        out.append(_m("ML2", "cpu_saturation", cpu >= SATURATION, W_SATURATION, "m_saturation",
                      f"cpu={round(cpu, 3)}"))
    mem = mf.get("mem_saturation")
    if mem is not None:
        out.append(_m("ML3", "mem_saturation", mem >= SATURATION, W_SATURATION, "m_saturation",
                      f"mem={round(mem, 3)}"))

    # ML4 доля ошибок по метрикам (группа m_http). Независимый от логов сигнал RED.
    er = mf.get("error_rate")
    if er is not None:
        out.append(_m("ML4", "metric_error_ratio", er >= METRIC_ERROR_RATE, W_METRIC_ERROR,
                      "m_http", f"error_rate={round(er, 4)}", lr_absent=LR_ABSENT))

    # ML5 обвал трафика (группа m_traffic): частота запросов резко упала против базовой линии.
    # Применим только при наличии базовой линии с ненулевым трафиком.
    req = mf.get("req_rate")
    base_req = (baseline or {}).get("req_rate")
    if req is not None and base_req:
        out.append(_m("ML5", "traffic_drop", req <= TRAFFIC_DROP_RATIO * base_req, W_TRAFFIC,
                      "m_traffic", f"req {round(base_req, 3)}->{round(req, 3)}", applicable=True))

    # ML6 троттлинг процессора (группа m_saturation, делит голос с насыщением процессора как одна
    # волна нехватки процессора): контейнер придушен по лимиту, доля придушенных периодов велика.
    thr = mf.get("cpu_throttling")
    if thr is not None:
        out.append(_m("ML6", "cpu_throttling", thr >= THROTTLING, W_SATURATION, "m_saturation",
                      f"throttled={round(thr, 3)}"))

    # ML7 и ML8 заполнение диска и постоянного тома делят группу m_disk (максимум один раз).
    disk = mf.get("disk_usage")
    if disk is not None:
        out.append(_m("ML7", "disk_saturation", disk >= DISK_USAGE, W_DISK, "m_disk",
                      f"disk_usage={round(disk, 3)}"))
    pvc = mf.get("pvc_usage")
    if pvc is not None:
        out.append(_m("ML8", "pvc_saturation", pvc >= DISK_USAGE, W_DISK, "m_disk",
                      f"pvc_usage={round(pvc, 3)}"))

    # ML9 и ML10 состояния узла (группа m_node): узел неготов либо под давлением ресурсов. Это
    # сильный сигнал «что-то отвалилось» на уровне железа или узла, поэтому вес выше прикладных.
    not_ready = mf.get("node_not_ready")
    if not_ready is not None:
        out.append(_m("ML9", "node_not_ready", not_ready >= 1, W_NODE, "m_node",
                      f"not_ready_nodes={not_ready}"))
    pressure = None
    for key in ("node_disk_pressure", "node_mem_pressure"):
        v = mf.get(key)
        if v is not None:
            pressure = (pressure or 0) + v
    if pressure is not None:
        out.append(_m("ML10", "node_pressure", pressure >= 1, W_NODE, "m_node",
                      f"pressured_conditions={pressure}"))

    # ML11 события нехватки памяти (группа m_oom): счётчик OOM за окно вырос.
    oom = mf.get("oom_events")
    if oom is not None:
        out.append(_m("ML11", "oom_events", oom >= 1, W_OOM, "m_oom", f"oom_events={round(oom, 2)}"))

    # ML12 поды в ожидании планирования (группа m_schedule): нехватка ресурсов или узлов.
    pending = mf.get("pod_pending")
    if pending is not None:
        out.append(_m("ML12", "pods_pending", pending >= PENDING_MIN, W_SCHEDULE, "m_schedule",
                      f"pending_pods={round(pending, 1)}"))

    # ML13 сетевые ошибки на узле (группа m_network): рост ошибок приёма и передачи.
    net = mf.get("net_errors")
    if net is not None:
        out.append(_m("ML13", "net_errors", net >= NET_ERRORS, W_NETWORK, "m_network",
                      f"net_err_rate={round(net, 3)}"))

    return out
