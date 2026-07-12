"""Байесовский скоринг уверенности по каталогу детекторов.

Апостериорные шансы это произведение априорных шансов на отношения правдоподобия.
Обновление ДВУСТОРОННЕЕ: сработавший детектор повышает шансы своим отношением
правдоподобия при наличии сигнала (lr, значение больше единицы), а применимый, но
несработавший детектор ПОНИЖАЕТ шансы отношением правдоподобия при отсутствии
сигнала (lr_absent, значение меньше единицы). Раньше несработавший детектор давал
множитель ровно единица, то есть отсутствие ожидаемого симптома не влияло на вывод
вовсе, что систематически завышало уверенность. Детектор, для которого нужный вход
не подан (структурный или требующий временного ряда), в обновлении не участвует ни
в одну сторону, чтобы отсутствие данных не путалось с отсутствием симптома.

Коррелированные детекторы объединены в группы и подают один голос от группы по
правилу взятия максимума, чтобы одна волна ошибок, породившая несколько связанных
детекторов, не считалась несколькими независимыми свидетельствами. Жёсткий потолок
шансов держит уверенность не выше предела. Демпфер восстановления понижает шансы.
Коэффициент полноты понижает итог пропорционально доле недоступных подтверждающих
полей. Итог раскладывается по трём полосам доверия.
"""
from __future__ import annotations

import os

PRIOR_ODDS = float(os.getenv("AEGIL_RCA_PRIOR_ODDS", "0.1"))
ODDS_CEILING = float(os.getenv("AEGIL_RCA_ODDS_CEILING", "999.0"))
BAND_LOW = float(os.getenv("AEGIL_RCA_BAND_LOW", "0.5"))
BAND_HIGH = float(os.getenv("AEGIL_RCA_BAND_HIGH", "0.85"))
# Множитель демпфера восстановления (значение меньше единицы понижает уверенность).
DAMPER_FACTOR = float(os.getenv("AEGIL_RCA_DAMPER_FACTOR", "0.5"))


def band(confidence: float) -> str:
    if confidence < BAND_LOW:
        return "low"
    if confidence < BAND_HIGH:
        return "uncertain"
    return "high"


def score(detectors: list, delta: float = 1.0) -> dict:
    """Считает уверенность по каталогу детекторов. delta это коэффициент полноты
    данных (0..1), понижающий итог за недоступные подтверждающие поля.

    Каждый детектор ожидается в виде словаря с полями fired (сработал ли), lr
    (отношение правдоподобия при наличии сигнала), group (группа корреляции),
    applicable (подан ли нужный вход; по умолчанию True) и необязательного lr_absent
    (отношение правдоподобия при отсутствии сигнала для применимого детектора). Голос
    группы это максимум по сработавшим членам, либо, если в группе никто не сработал,
    минимальный из lr_absent применимых членов (самое сильное свидетельство против)."""
    fired_lr: dict = {}          # group -> максимум lr среди сработавших
    absent_lr: dict = {}         # group -> минимум lr_absent среди применимых несработавших
    damper = 1.0
    votes = []

    for d in detectors:
        grp = d.get("group", "")
        applicable = d.get("applicable", True)
        if grp == "damper":
            if d.get("fired"):
                damper *= DAMPER_FACTOR
                votes.append(d)
            continue
        if grp == "structural":
            continue             # структурные не голосуют напрямую
        if d.get("fired"):
            lr = float(d.get("lr", 1.0))
            if lr > fired_lr.get(grp, 0.0):
                fired_lr[grp] = lr
            votes.append(d)
        elif applicable and "lr_absent" in d:
            la = float(d["lr_absent"])
            cur = absent_lr.get(grp)
            if cur is None or la < cur:
                absent_lr[grp] = la

    odds = PRIOR_ODDS
    group_max: dict = {}
    for grp, lr in fired_lr.items():
        odds *= lr
        group_max[grp] = lr
    # Группы, где никто не сработал, но детекторы были применимы, тянут шансы вниз.
    for grp, la in absent_lr.items():
        if grp not in fired_lr:
            odds *= la
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
        "absent": absent_lr,
        "damper": damper,
        "delta": delta,
        "fired": [d["id"] for d in votes],
    }
