"""Читатель метрик золотых сигналов для анализатора первопричин.

Раньше движок опирался только на текст логов. Полнота телеметрии требует ещё метрик:
доля ошибок, частота запросов, задержка, насыщение процессора и памяти, темп рестартов.
Эти сигналы приходят по стандарту OpenTelemetry и оседают в Prometheus-совместимом
хранилище (Prometheus, Mimir, VictoriaMetrics), которое отвечает на запрос диапазона
query_range матрицей рядов. Модуль забирает заданный набор запросов золотых сигналов и
детерминированно сворачивает каждую матрицу в компактные факты окна, симметрично тому,
как агрегатор сворачивает логи.

Конкретные запросы PromQL зависят от развёртывания (имена метрик у всех разные),
поэтому набор запросов задаётся владельцем через окружение единым JSON
(SENTINEL_RCA_PROM_QUERIES: имя_сигнала в строку PromQL), а разумные значения по
умолчанию покрывают распространённые метрики HTTP и контейнеров. Адрес хранилища берётся
из SENTINEL_RCA_PROM_URL; при его отсутствии или недоступности слой метрик честно пуст
(present=False) и в анализе не участвует, как и прочие читатели с мягкой деградацией.

Сворачивание ряда чистое и детерминированное (последнее значение, максимум, среднее по
всем сериям сигнала), поэтому его можно проверять модульно без сети и без ускорителя.
"""
from __future__ import annotations

import json
import os

import httpx

PROM_URL = os.getenv("SENTINEL_RCA_PROM_URL", "").rstrip("/")
CONNECT_TIMEOUT = float(os.getenv("SENTINEL_RCA_PROM_CONNECT_TIMEOUT", "5"))
READ_TIMEOUT = float(os.getenv("SENTINEL_RCA_PROM_READ_TIMEOUT", "20"))

# Запросы золотых сигналов по умолчанию. Имя сигнала это ключ, по которому детекторы и факты
# обращаются к свёрнутому значению. Значения PromQL подобраны под распространённые метрики и
# переопределяются целиком через SENTINEL_RCA_PROM_QUERIES (JSON вида {"имя": "PromQL"}).
_DEFAULT_QUERIES = {
    # Сигналы уровня приложения (RED): ошибки, трафик, задержка.
    "error_rate": 'sum(rate(http_requests_total{code=~"5.."}[5m])) / clamp_min(sum(rate(http_requests_total[5m])), 1)',
    "req_rate": "sum(rate(http_requests_total[5m]))",
    "latency_p95_ms": "histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le)) * 1000",
    # Насыщение ресурсов контейнера (USE): процессор, память и троттлинг по лимиту процессора.
    "cpu_saturation": 'max(rate(container_cpu_usage_seconds_total[5m])) / clamp_min(max(kube_pod_container_resource_limits{resource="cpu"}), 1)',
    "mem_saturation": 'max(container_memory_working_set_bytes) / clamp_min(max(kube_pod_container_resource_limits{resource="memory"}), 1)',
    "cpu_throttling": "sum(rate(container_cpu_cfs_throttled_periods_total[5m])) / clamp_min(sum(rate(container_cpu_cfs_periods_total[5m])), 1)",
    # Диск: заполнение файловых систем узла и постоянных томов.
    "disk_usage": 'max(1 - node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs"} / clamp_min(node_filesystem_size_bytes, 1))',
    "pvc_usage": "max(1 - kubelet_volume_stats_available_bytes / clamp_min(kubelet_volume_stats_capacity_bytes, 1))",
    # Состояния узлов (что-то отвалилось): неготовность и давление ресурсов.
    "node_not_ready": 'sum(kube_node_status_condition{condition="Ready",status="true"} == 0)',
    "node_disk_pressure": 'sum(kube_node_status_condition{condition="DiskPressure",status="true"})',
    "node_mem_pressure": 'sum(kube_node_status_condition{condition="MemoryPressure",status="true"})',
    # Планирование, перезапуски, события нехватки памяти и сетевые ошибки.
    "pod_pending": 'sum(kube_pod_status_phase{phase="Pending"})',
    "restarts": "max(kube_pod_container_status_restarts_total)",
    "oom_events": "sum(increase(container_oom_events_total[15m]))",
    "net_errors": "sum(rate(node_network_receive_errs_total[5m]) + rate(node_network_transmit_errs_total[5m]))",
}


class MetricsError(RuntimeError):
    """Ошибка обращения к хранилищу метрик."""


def queries() -> dict:
    """Набор запросов золотых сигналов: переопределение из окружения либо значения по умолчанию."""
    raw = os.getenv("SENTINEL_RCA_PROM_QUERIES", "").strip()
    if raw:
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict) and obj:
                return {str(k): str(v) for k, v in obj.items()}
        except ValueError:
            pass
    return dict(_DEFAULT_QUERIES)


def parse_matrix(prom_json: dict) -> list:
    """Разбирает ответ query_range в список серий, каждая это список пар (метка_времени, значение).
    Нечисловые точки пропускаются. Пустой либо неуспешный ответ даёт пустой список."""
    series: list = []
    for res in ((prom_json or {}).get("data", {}) or {}).get("result", []) or []:
        pts = []
        for pair in res.get("values", []) or []:
            try:
                ts, val = int(float(pair[0])), float(pair[1])
            except (IndexError, ValueError, TypeError):
                continue
            pts.append((ts, val))
        if pts:
            series.append(pts)
    return series


def reduce_signal(series: list):
    """Сворачивает серии одного сигнала в число фактов окна: последнее значение (по самой поздней
    метке времени, максимум среди серий на этой метке), максимум и среднее по всем точкам. None,
    если данных нет."""
    all_points = [p for s in series for p in s]
    if not all_points:
        return None
    latest_ts = max(ts for ts, _ in all_points)
    last = max(v for ts, v in all_points if ts == latest_ts)
    vals = [v for _, v in all_points]
    return {"last": round(last, 6), "max": round(max(vals), 6),
            "mean": round(sum(vals) / len(vals), 6), "count": len(vals)}


def build_facts(named_results: dict) -> dict:
    """Сворачивает сырьё запросов (имя_сигнала в ответ query_range) в компактные факты метрик окна.
    Для удобства детекторов ключевые сигналы выносятся ещё и на верхний уровень по последнему
    значению. Пустой вход даёт present=False."""
    signals: dict = {}
    for name, prom_json in (named_results or {}).items():
        reduced = reduce_signal(parse_matrix(prom_json))
        if reduced is not None:
            signals[name] = reduced
    facts: dict = {"present": bool(signals), "signals": signals}
    top = ("error_rate", "req_rate", "latency_p95_ms", "cpu_saturation", "mem_saturation",
           "cpu_throttling", "disk_usage", "pvc_usage", "node_not_ready", "node_disk_pressure",
           "node_mem_pressure", "pod_pending", "restarts", "oom_events", "net_errors")
    for key in top:
        facts[key] = signals[key]["last"] if key in signals else None
    return facts


def fetch(minutes: int = 15, end: float | None = None, prom_url: str | None = None) -> dict:
    """Забирает окно метрик из Prometheus-совместимого хранилища и возвращает свёрнутые факты.
    При отсутствии адреса или недоступности хранилища возвращает present=False (мягкая деградация),
    чтобы анализ логов продолжался без метрик, а не падал."""
    import time
    base = (prom_url if prom_url is not None else PROM_URL).rstrip("/")
    if not base:
        return {"present": False, "signals": {}}
    end_s = end if end is not None else time.time()
    start_s = end_s - minutes * 60
    step = max(15, minutes * 60 // 60)
    timeout = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)
    named: dict = {}
    try:
        with httpx.Client(timeout=timeout) as client:
            for name, promql in queries().items():
                try:
                    r = client.get(f"{base}/api/v1/query_range", params={
                        "query": promql, "start": str(start_s), "end": str(end_s), "step": str(step)})
                    r.raise_for_status()
                    named[name] = r.json()
                except (httpx.HTTPError, ValueError):
                    continue
    except httpx.HTTPError:
        return {"present": False, "signals": {}}
    return build_facts(named)
