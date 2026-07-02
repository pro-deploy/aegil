"""Оркестрация детерминированного анализа RCA (ADR-0032, Часть B). Связывает ядро
в один проход: агрегатор фактов за один проход, каталог детекторов D1-D12,
байесовский скоринг уверенности и сборку вердикта с гардами. Языковая модель здесь
не участвует: она подключается только на краях (разбор запроса инженера и
формулировка отчёта по уже посчитанным фактам). Функция чистая и детерминированная,
пригодна для модульной проверки и запуска на центральном процессоре.
"""
from __future__ import annotations

from aggregator import aggregate
from detectors import detect
from scoring import score
from verdict import build


def analyze(records, baseline=None, delta: float = 1.0) -> dict:
    """Полный проход анализа окна логов. records и baseline — итерируемые
    канонические лог-записи (словари). Возвращает факты, сработавшие детекторы,
    скоринг и вердикт RCA."""
    records = list(records)
    facts = aggregate(records)
    base_facts = aggregate(list(baseline)) if baseline else None
    dets = detect(facts, base_facts)
    s = score(dets, delta=delta)
    v = build(facts, dets, s, records)
    return {"facts": facts, "detectors": dets, "score": s, "verdict": v}
