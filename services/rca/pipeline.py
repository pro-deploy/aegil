"""Оркестрация детерминированного анализа первопричин. Связывает ядро
в один проход: агрегатор фактов за один проход, каталог детекторов D1-D12,
байесовский скоринг уверенности и сборку вердикта с гардами. Языковая модель здесь
не участвует: она подключается только на краях (разбор запроса инженера и
формулировка отчёта по уже посчитанным фактам). Функция чистая и детерминированная,
пригодна для модульной проверки и запуска на центральном процессоре.
"""
from __future__ import annotations

from aggregator import aggregate
from detectors import detect
from metric_detectors import detect_metrics
from scoring import score
from verdict import build


def analyze(records, baseline=None, delta: float = 1.0,
            metric_facts=None, baseline_metric_facts=None) -> dict:
    """Полный проход анализа окна. records и baseline это итерируемые канонические
    лог-записи (словари). metric_facts это свёрнутые факты метрик золотых сигналов окна
    (модуль metrics), необязательные: при их наличии детекторы метрик добавляются к логовым
    и участвуют в общем байесовском скоринге единообразно. Возвращает факты, факты метрик,
    сработавшие детекторы, скоринг и вердикт RCA."""
    records = list(records)
    facts = aggregate(records)
    base_facts = aggregate(list(baseline)) if baseline else None
    dets = detect(facts, base_facts)
    if metric_facts and metric_facts.get("present"):
        dets = dets + detect_metrics(metric_facts, baseline_metric_facts)
    s = score(dets, delta=delta)
    v = build(facts, dets, s, records)
    return {"facts": facts, "metric_facts": metric_facts or {"present": False},
            "detectors": dets, "score": s, "verdict": v}
