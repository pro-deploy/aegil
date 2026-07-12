"""Цели уровня обслуживания (SLO), индикаторы (SLI) и бюджет ошибок как детерминированный
гейт автономии aegil.

Зрелые команды эксплуатации думают не абстрактной уверенностью модели, а нарушением
бизнес-порога. Этот модуль переводит наблюдаемую долю ошибок окна в язык надёжности:
индикатор уровня обслуживания (доля успешных запросов), цель уровня обслуживания (целевая
доступность, например 0,99), бюджет ошибок (единица минус цель) и скорость его прожигания
(burn rate). Скорость прожигания это отношение фактической доли ошибок к бюджету ошибок:
единица означает расход бюджета ровно с той скоростью, что исчерпает его за окно, а значение
выше единицы означает ускоренный расход. По многооконному правилу инженерии надёжности Google
быстрый прожиг (порог по умолчанию 14,4) требует немедленного вмешательства, умеренный (порог
6) требует планового.

Ключевая идея: автономный ремонт запускается не потому, что модель уверена, а потому, что
прожигается бюджет ошибок, то есть страдает пользователь. Функция gate возвращает решение,
которым слой исполнения понижает автономное действие до предложения, пока нарушения нет.

Модуль детерминирован, без сети и без внешних зависимостей, пороги настраиваются окружением
с префиксом AEGIL_. При незаданной цели (AEGIL_SLO_TARGET пусто) слой выключен и гейт
никого не сдерживает, поэтому поведение развёртываний без объявленных SLO не меняется.
"""
from __future__ import annotations

import os

# Уровни серьёзности нарушения бюджета ошибок по скорости прожигания.
OK = "ok"                # бюджет прожигается медленнее умеренного порога
AT_RISK = "at_risk"      # умеренный прожиг: плановое вмешательство
CRITICAL = "critical"    # быстрый прожиг: немедленное вмешательство

# Режимы гейта автономии по SLO. off: SLO не сдерживает автономию (поведение по умолчанию).
# at_risk: автономный ремонт разрешён при умеренном и быстром прожиге. critical: только при
# быстром прожиге. Гейт лишь ПОНИЖАЕТ автономию до предложения, повысить её он не может.
GATE_OFF = "off"
GATE_AT_RISK = "at_risk"
GATE_CRITICAL = "critical"


def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def target() -> float | None:
    """Целевая доступность из окружения (доля успешных запросов, 0..1). None означает, что SLO
    не объявлены и слой выключен."""
    raw = os.getenv("AEGIL_SLO_TARGET", "").strip()
    if not raw:
        return None
    try:
        val = float(raw)
    except ValueError:
        return None
    if val <= 0.0 or val >= 1.0:
        return None
    return val


def fast_burn() -> float:
    return _f("AEGIL_SLO_FAST_BURN", 14.4)


def slow_burn() -> float:
    return _f("AEGIL_SLO_SLOW_BURN", 6.0)


def gate_mode() -> str:
    mode = os.getenv("AEGIL_SLO_GATE", GATE_OFF).strip().lower()
    return mode if mode in (GATE_OFF, GATE_AT_RISK, GATE_CRITICAL) else GATE_OFF


def evaluate(error_rate: float, tgt: float | None = None) -> dict:
    """Переводит долю ошибок окна в состояние надёжности. error_rate это доля ошибочных
    запросов (0..1). Возвращает индикатор, цель, бюджет ошибок, скорость прожигания и уровень
    серьёзности. При незаданной цели слой помечен выключенным и серьёзность OK."""
    tgt = target() if tgt is None else tgt
    er = max(0.0, min(1.0, float(error_rate or 0.0)))
    sli = round(1.0 - er, 6)
    if not tgt:
        return {"enabled": False, "sli": sli, "target": None, "error_budget": None,
                "burn_rate": None, "severity": OK, "breached": False}
    budget = 1.0 - tgt
    burn = (er / budget) if budget > 0 else 0.0
    if burn >= fast_burn():
        sev = CRITICAL
    elif burn >= slow_burn():
        sev = AT_RISK
    else:
        sev = OK
    return {"enabled": True, "sli": sli, "target": tgt, "error_budget": round(budget, 6),
            "burn_rate": round(burn, 3), "severity": sev, "breached": sli < tgt}


def gate(state: dict, mode: str | None = None) -> bool:
    """Разрешает ли SLO автономный ремонт при данном состоянии. Возвращает True (не сдерживать),
    если слой выключен, или режим гейта off, или прожиг достиг требуемого режимом уровня. Когда
    нарушения нет, автономию следует понизить до предложения, поэтому возвращается False."""
    mode = gate_mode() if mode is None else mode
    if not state.get("enabled") or mode == GATE_OFF:
        return True
    sev = state.get("severity", OK)
    if mode == GATE_CRITICAL:
        return sev == CRITICAL
    return sev in (AT_RISK, CRITICAL)


def summary(error_rate: float) -> dict:
    """Сводка состояния SLO для операторской консоли по текущей доле ошибок окна."""
    st = evaluate(error_rate)
    st["gate_mode"] = gate_mode()
    return st
