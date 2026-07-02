"""Каталог детекторов D1-D12 (ADR-0032, Часть B.3; книга Биркина, глава 5).
Каждый детектор потребляет факты агрегатора (и, где нужно, baseline за прошлые
сутки) и, срабатывая, даёт вес в виде отношения правдоподобия. Коррелированные
детекторы объединены в группы и подают один голос по правилу взятия максимума по
группе (глава 6): D1 (всплеск ошибок) и D5 (сетевой сбой) описывают один сетевой
каскад с двух сторон, поэтому лежат в одной группе.

Часть детекторов требует временного ряда, APM или baseline (D6 перерыв в логах,
D7 молчание источника, D8 структурный сосед, D12 демпфер восстановления). Пока
такие входы не поданы, эти детекторы честно не срабатывают и помечены как
структурные или требующие baseline; они включаются по мере обогащения входов.
"""
from __future__ import annotations

# Пороги (калибруются на размеченных инцидентах, глава 6).
ERROR_RATE_SPIKE = 0.2
STATUS_5XX_SHARE = 0.1
BLAST_MIN = 3
ERROR_GROWTH_RATIO = 1.5

# Порог значимости окна: единичный сбойный лог на фоне здорового потока это шум, а
# не инцидент. Детекторы, утверждающие инцидент по объёму ошибок (D1, D5, D10, D11),
# срабатывают только когда ошибок достаточно по абсолютному числу либо по доле.
# Это дешёвый детерминированный демпфер ложных срабатываний (глава 6, полосы доверия).
MIN_ERRORS = 3
MIN_ERROR_RATE = 0.05

NETWORK_SIGNALS = {"connection_refused", "deadline_exceeded", "dns_error", "timeout", "tls_error"}


def _fired(id, name, fired, lr, group, evidence=""):
    return {"id": id, "name": name, "fired": bool(fired), "lr": float(lr), "group": group, "evidence": evidence}


def detect(facts: dict, baseline: dict | None = None) -> list[dict]:
    """Прогоняет каталог D1-D12 по фактам окна. baseline — факты за прошлые сутки."""
    out: list[dict] = []
    total = facts.get("total_lines", 0) or 0
    error_rate = facts.get("error_rate", 0.0)
    signals = facts.get("error_signals", {}) or {}
    status = facts.get("status_classes", {}) or {}
    events = facts.get("event_counts", {}) or {}
    blast = facts.get("blast_radius", {}) or {}
    levels = facts.get("level_counts", {}) or {}
    errors = (levels.get("error", 0) or 0) + (levels.get("fatal", 0) or 0)

    # Гейт значимости: окно несёт инцидент, если ошибок достаточно по абсолютному
    # числу или по доле. Ниже гейта объёмные детекторы не голосуют (шумовой демпфер).
    significant = errors >= MIN_ERRORS or error_rate >= MIN_ERROR_RATE

    # D1 всплеск ошибок (группа spike; вес 8.0). Коррелирует с D5 (сетевой сбой) как
    # две стороны одного всплеска, поэтому делит группу с D5 и голосует по максимуму.
    out.append(_fired("D1", "error_spike", significant and total and error_rate >= ERROR_RATE_SPIKE,
                      8.0, "spike", f"error_rate={error_rate}"))

    # D2 новый паттерн (вес 3.0): шаблон, отсутствующий в baseline.
    d2 = False
    ev2 = "no_baseline"
    if baseline:
        known = {t for t, _ in baseline.get("top_templates", [])}
        for t, _ in facts.get("top_templates", []):
            if t not in known:
                d2, ev2 = True, f"new_template={t!r}"
                break
    out.append(_fired("D2", "new_pattern", d2, 3.0, "new", ev2))

    # D3 рост ошибок против baseline (вес 4.0).
    d3 = False
    ev3 = "no_baseline"
    if baseline:
        be = (baseline.get("level_counts", {}) or {}).get("error", 0)
        ne = (facts.get("level_counts", {}) or {}).get("error", 0)
        if ne >= ERROR_GROWTH_RATIO * max(be, 1) and ne > 0:
            d3, ev3 = True, f"errors {be}->{ne}"
    out.append(_fired("D3", "error_growth", d3, 4.0, "growth", ev3))

    # D4 алерт мониторинга (вес 5.0): внешний алерт в потоке.
    d4 = any("alert" in str(k).lower() for k in events)
    out.append(_fired("D4", "monitoring_alert", d4, 5.0, "alert", "alert_event" if d4 else ""))

    # D5 сетевой сбой (группа spike, вес 7.0): делит группу с D1, чтобы один сетевой
    # каскад не считался дважды. Под гейтом значимости, чтобы единичный сетевой флап
    # не поднимался в инцидент.
    net = sorted(s for s in signals if s in NETWORK_SIGNALS)
    out.append(_fired("D5", "network_failure", significant and bool(net), 7.0, "spike", ",".join(net)))

    # D6 перерыв в логах, D7 молчание источника (требуют временного ряда).
    out.append(_fired("D6", "log_gap", False, 5.0, "gap", "needs_timeseries"))
    out.append(_fired("D7", "source_silence", False, 5.0, "gap", "needs_timeseries"))

    # D8 структурный сосед по ФДМ (структурный, модифицирует, не голосует напрямую).
    out.append(_fired("D8", "structural_neighbor", False, 1.0, "structural", "needs_fdm"))

    # D9 недавний деплой (изменение, вес 3.8): сигнал релиза в окне.
    d9 = "deploy" in events
    out.append(_fired("D9", "recent_deploy", d9, 3.8, "change", "deploy_event" if d9 else ""))

    # D10 всплеск 5xx (http, вес 6.0). Под гейтом значимости.
    status_total = sum(status.values()) or 0
    share5 = (status.get("5xx", 0) / status_total) if status_total else 0.0
    out.append(_fired("D10", "http_5xx_spike",
                      significant and status.get("5xx", 0) > 0 and share5 >= STATUS_5XX_SHARE,
                      6.0, "http", f"5xx_share={round(share5, 3)}"))

    # D11 радиус влияния (вес 4.0): широта поражения по числу затронутых сущностей.
    # Берётся максимум по осям (тенанты, джобы), а не сумма, чтобы одна ошибка с полями
    # tenant_id и job_id не выглядела как поражение двух сущностей. Под гейтом значимости.
    reach = max(blast.get("tenants", 0) or 0, blast.get("jobs", 0) or 0)
    out.append(_fired("D11", "blast_radius", significant and reach >= BLAST_MIN, 4.0, "blast",
                      f"reach={reach}"))

    # D12 демпфер восстановления (понижающий, требует временного ряда).
    out.append(_fired("D12", "recovery", False, 1.0, "damper", "needs_timeseries"))

    return out
