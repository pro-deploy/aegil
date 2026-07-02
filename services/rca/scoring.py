"""Байесовский скоринг уверенности (ADR-0032, Часть B.4; книга Биркина, глава 6).
Апостериорные шансы это произведение априорных на отношения правдоподобия по
групповым максимумам (один голос от группы коррелированных детекторов). Жёсткий
потолок в тысячу крат держит уверенность не выше 99,9 процента. Демпфер
восстановления (D12) понижает шансы. Коэффициент полноты δ понижает итог
пропорционально доле недоступных подтверждающих полей. Итог раскладывается по трём
полосам доверия с порогами 0,5 и 0,85.
"""
from __future__ import annotations

PRIOR_ODDS = 0.1          # априорные шансы (доинцидентная база)
ODDS_CEILING = 999.0      # потолок: confidence = odds/(1+odds) не выше 0,999
BAND_LOW = 0.5
BAND_HIGH = 0.85


def band(confidence: float) -> str:
    if confidence < BAND_LOW:
        return "low"
    if confidence < BAND_HIGH:
        return "uncertain"
    return "high"


def score(detectors: list[dict], delta: float = 1.0) -> dict:
    """Считает уверенность по сработавшим детекторам. delta — коэффициент полноты
    данных (0..1), понижающий итог за недоступные подтверждающие поля."""
    # Группировка по максимуму: один голос (макс LR) от группы коррелированных.
    group_max: dict[str, float] = {}
    damper = 1.0
    votes = []
    for d in detectors:
        if not d.get("fired"):
            continue
        grp = d.get("group", "")
        if grp == "damper":
            damper *= 0.5   # признаки восстановления понижают уверенность
            votes.append(d)
            continue
        if grp in ("structural",):
            continue        # структурные не голосуют напрямую
        lr = float(d.get("lr", 1.0))
        if lr > group_max.get(grp, 0.0):
            group_max[grp] = lr
        votes.append(d)

    odds = PRIOR_ODDS
    for lr in group_max.values():
        odds *= lr
    odds *= damper
    odds = min(odds, ODDS_CEILING)

    confidence = odds / (1.0 + odds)
    delta = max(0.0, min(1.0, delta))
    confidence *= delta

    return {
        "confidence": round(confidence, 4),
        "band": band(confidence),
        "odds": round(odds, 4),
        "group_max": group_max,
        "damper": damper,
        "delta": delta,
        "fired": [d["id"] for d in votes],
    }
