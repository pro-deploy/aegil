"""Каталог детекторов признаков инцидента.

Каждый детектор потребляет факты агрегатора (и, где нужно, базовую линию за прошлые
сутки) и, срабатывая, даёт вес в виде отношения правдоподобия. Коррелированные
детекторы объединены в группы и подают один голос от группы по правилу максимума,
чтобы одна волна ошибок не считалась несколькими независимыми свидетельствами.

Обновление шансов двустороннее (см. модуль scoring): применимый детектор несёт не
только отношение правдоподобия при срабатывании (lr), но и отношение правдоподобия
при отсутствии сигнала (lr_absent, меньше единицы), поэтому отсутствие ожидаемого
симптома тоже влияет на вывод, а не игнорируется.

Честность статуса: часть детекторов опирается на временной ряд (перерыв в логах,
молчание источника, демпфер восстановления) или на граф зависимостей между сервисами
(структурный сосед). Эти входы теперь подаёт агрегатор: временной ряд строится из
реальных меток времени _ts_ns, а граф зависимостей из наблюдённых рёбер вызовов
между сервисами. Поэтому каждый такой детектор помечается applicable=True только
тогда, когда соответствующий вход фактически присутствует в фактах окна (временной
ряд построен либо есть хотя бы одно ребро топологии), и applicable=False, когда входа
нет (например, в записях не было меток времени или полей цели вызова). Так статус
применимости честно отражает наличие входа, а не выдаёт детектор за рабочий вслепую.

Пороги и веса объявлены калибруемыми, но размеченного набора инцидентов для
калибровки пока нет, поэтому значения по умолчанию нейтральные и заданы через
окружение с префиксом AEGIL_. Это честный факт: калибровки нет, значения не
подогнаны под данные.
"""
from __future__ import annotations

import os

from normalize import NETWORK_SIGNALS


def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _i(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


# Пороги (некалиброванные нейтральные значения, настраиваются окружением).
ERROR_RATE_SPIKE = _f("AEGIL_RCA_ERROR_RATE_SPIKE", 0.2)
STATUS_5XX_SHARE = _f("AEGIL_RCA_STATUS_5XX_SHARE", 0.1)
BLAST_MIN = _i("AEGIL_RCA_BLAST_MIN", 3)
ERROR_GROWTH_RATIO = _f("AEGIL_RCA_ERROR_GROWTH_RATIO", 1.5)
MIN_ERRORS = _i("AEGIL_RCA_MIN_ERRORS", 3)
MIN_ERROR_RATE = _f("AEGIL_RCA_MIN_ERROR_RATE", 0.05)

# Веса детекторов как отношения правдоподобия при срабатывании (lr) и при отсутствии
# сигнала у применимого детектора (lr_absent, меньше единицы).
W_SPIKE = _f("AEGIL_RCA_W_SPIKE", 8.0)
W_NETWORK = _f("AEGIL_RCA_W_NETWORK", 7.0)
W_NEW_PATTERN = _f("AEGIL_RCA_W_NEW_PATTERN", 3.0)
W_GROWTH = _f("AEGIL_RCA_W_GROWTH", 4.0)
W_ALERT = _f("AEGIL_RCA_W_ALERT", 5.0)
W_DEPLOY = _f("AEGIL_RCA_W_DEPLOY", 3.8)
W_5XX = _f("AEGIL_RCA_W_5XX", 6.0)
W_BLAST = _f("AEGIL_RCA_W_BLAST", 4.0)
W_GAP = _f("AEGIL_RCA_W_GAP", 5.0)
W_SILENCE = _f("AEGIL_RCA_W_SILENCE", 5.0)
LR_ABSENT = _f("AEGIL_RCA_LR_ABSENT", 0.6)

# Пороги временных детекторов. Перерыв в логах требует одновременно существенного
# объёма записей, крупного разрыва относительно всей протяжённости окна и относительно
# обычной частоты (медианного интервала между событиями), чтобы редкая выборка не
# принималась за обрыв потока. Молчание источника требует существенного объёма от
# сервиса и его тишины на протяжении заметной доли окна к его концу. Демпфер
# восстановления требует заметного числа ошибок в ранней половине окна и их резкого
# спада в поздней. Значения некалиброванные, консервативные, настраиваются окружением.
GAP_MIN_LINES = _i("AEGIL_RCA_GAP_MIN_LINES", 8)
GAP_SPAN_RATIO = _f("AEGIL_RCA_GAP_SPAN_RATIO", 0.3)
GAP_MEDIAN_MULT = _f("AEGIL_RCA_GAP_MEDIAN_MULT", 8.0)
SILENCE_MIN_LINES = _i("AEGIL_RCA_SILENCE_MIN_LINES", 5)
SILENCE_TAIL_FRAC = _f("AEGIL_RCA_SILENCE_TAIL_FRAC", 0.5)
RECOVERY_MIN_ERRORS = _i("AEGIL_RCA_RECOVERY_MIN_ERRORS", 3)
RECOVERY_DROP_RATIO = _f("AEGIL_RCA_RECOVERY_DROP_RATIO", 0.3)

# События, толкуемые как релиз или изменение (домен-агностично: любое из синонимов).
DEPLOY_EVENTS = ("deploy", "release", "rollout", "rollback", "apply", "helm", "upgrade")


def _fired(id, name, fired, lr, group, evidence="", applicable=True, lr_absent=None):
    d = {
        "id": id, "name": name, "fired": bool(fired), "lr": float(lr),
        "group": group, "evidence": evidence, "applicable": bool(applicable),
    }
    if lr_absent is not None:
        d["lr_absent"] = float(lr_absent)
    return d


def detect(facts: dict, baseline: dict | None = None) -> list:
    """Прогоняет каталог детекторов по фактам окна. baseline это факты за прошлые
    сутки (для детекторов новизны и роста)."""
    out: list = []
    total = facts.get("total_lines", 0) or 0
    error_rate = facts.get("error_rate", 0.0)
    symptoms = facts.get("symptom_counts", {}) or {}
    status = facts.get("status_classes", {}) or {}
    events = facts.get("event_counts", {}) or {}
    blast = facts.get("blast_radius", {}) or {}
    levels = facts.get("level_counts", {}) or {}
    errors = (levels.get("error", 0) or 0) + (levels.get("fatal", 0) or 0)

    # Гейт значимости: окно несёт инцидент, если ошибок достаточно по абсолютному
    # числу или по доле. Ниже гейта объёмные детекторы не голосуют (шумовой демпфер).
    significant = errors >= MIN_ERRORS or error_rate >= MIN_ERROR_RATE

    # D1 всплеск ошибок (группа spike). Делит группу с сетевым сбоем как две стороны
    # одной волны, чтобы каскад не считался дважды. Двусторонний: отсутствие всплеска
    # при живом окне понижает шансы.
    d1 = bool(significant and total and error_rate >= ERROR_RATE_SPIKE)
    out.append(_fired("D1", "error_spike", d1, W_SPIKE, "spike",
                      f"error_rate={error_rate}", applicable=total > 0, lr_absent=LR_ABSENT))

    # D2 новый паттерн: шаблон, отсутствующий в базовой линии. Применим только при
    # наличии базовой линии.
    d2 = False
    ev2 = "no_baseline"
    if baseline:
        known = {t for t, _ in baseline.get("top_templates", [])}
        for t, _ in facts.get("top_templates", []):
            if t not in known:
                d2, ev2 = True, f"new_template={t!r}"
                break
    out.append(_fired("D2", "new_pattern", d2, W_NEW_PATTERN, "new", ev2,
                      applicable=bool(baseline), lr_absent=LR_ABSENT if baseline else None))

    # D3 рост ошибок против базовой линии. Применим только при наличии базовой линии.
    d3 = False
    ev3 = "no_baseline"
    if baseline:
        be = (baseline.get("level_counts", {}) or {}).get("error", 0)
        ne = (facts.get("level_counts", {}) or {}).get("error", 0)
        if ne >= ERROR_GROWTH_RATIO * max(be, 1) and ne > 0:
            d3, ev3 = True, f"errors {be}->{ne}"
    out.append(_fired("D3", "error_growth", d3, W_GROWTH, "growth", ev3,
                      applicable=bool(baseline), lr_absent=LR_ABSENT if baseline else None))

    # D4 алерт мониторинга: внешний алерт в потоке событий.
    d4 = any("alert" in str(k).lower() for k in events)
    out.append(_fired("D4", "monitoring_alert", d4, W_ALERT, "alert",
                      "alert_event" if d4 else ""))

    # D5 сетевой сбой (группа spike): сетевые симптомы, извлечённые из текста лога.
    # Делит группу с D1. Под гейтом значимости, чтобы единичный флап не поднимался.
    net = sorted(s for s in symptoms if s in NETWORK_SIGNALS)
    d5 = bool(significant and net)
    out.append(_fired("D5", "network_failure", d5, W_NETWORK, "spike", ",".join(net),
                      applicable=total > 0, lr_absent=LR_ABSENT))

    # D6 перерыв в логах (группа gap): в отсортированной канве времени есть интервал
    # молчания, крупный и относительно всей протяжённости окна, и относительно обычной
    # частоты событий, при существенном общем объёме. Это признак того, что поток логов
    # источника оборвался и затем возобновился. Применим при наличии временного ряда.
    # Отсутствие перерыва не считается свидетельством здоровья, поэтому lr_absent нет.
    ts = facts.get("timeseries", {}) or {}
    ts_present = bool(ts.get("present"))
    d6 = False
    ev6 = "no_timeseries"
    if ts_present:
        span = ts.get("span_ns", 0) or 0
        max_gap = ts.get("max_gap_ns", 0) or 0
        median_gap = ts.get("median_gap_ns", 0) or 0
        lines = ts.get("lines", 0) or 0
        d6 = bool(lines >= GAP_MIN_LINES and span > 0
                  and max_gap >= GAP_SPAN_RATIO * span
                  and max_gap >= GAP_MEDIAN_MULT * max(median_gap, 1))
        ev6 = f"max_gap_ns={max_gap},span_ns={span}"
    out.append(_fired("D6", "log_gap", d6, W_GAP, "gap", ev6, applicable=ts_present))

    # Множество замолчавших источников: сервис, эмитировавший существенный объём в начале
    # окна и полностью замолчавший на заметной доле окна к его концу, тогда как окно в
    # целом продолжается. Служебный источник unknown (запись без поля сервиса) исключён,
    # чтобы бесхозные строки не считались замолчавшим сервисом. Это единый источник истины
    # для D7 (сам факт молчания) и для D8 (замолчавший нижестоящий сосед как признак корня).
    activity = facts.get("service_activity", {}) or {}
    silent: set = set()
    if ts_present and activity:
        span = ts.get("span_ns", 0) or 0
        to_ns = ts.get("to_ns")
        if span > 0 and to_ns is not None:
            for svc, a in activity.items():
                if svc == "unknown":
                    continue
                if a.get("count", 0) >= SILENCE_MIN_LINES:
                    quiet = to_ns - a.get("last_ns", to_ns)
                    if quiet >= SILENCE_TAIL_FRAC * span:
                        silent.add(svc)

    # D7 молчание источника (группа gap, делит голос с D6 как две стороны обрыва потока).
    d7 = bool(silent)
    silent_src = sorted(silent)[0] if silent else None
    if not (ts_present and activity):
        ev7 = "no_timeseries"
    else:
        ev7 = f"silent_source={silent_src}" if silent_src else "no_silence"
    out.append(_fired("D7", "source_silence", d7, W_SILENCE, "gap", ev7,
                      applicable=bool(ts_present and activity)))

    # D8 структурный сосед по графу зависимостей: ошибающийся сервис имеет наблюдённое
    # ребро вызова к нижестоящему сервису, который сам НЕЗДОРОВ, поэтому корень скорее
    # ниже по графу, а верхний сервис задет вторично. Нездоровье нижестоящего это либо
    # его собственные ошибки, либо его молчание: настоящий сквозной прогон показал, что
    # упавший корневой сервис часто не пишет ни одной строки ошибки, а просто замолкает,
    # поэтому условие «сосед тоже ошибается» пропускало главный реальный случай. Теперь
    # нездоровым считается и замолчавший сосед. Граф берётся из рёбер вызовов, наблюдённых
    # агрегатором в окне. Структурные детекторы в скоринге не голосуют напрямую (см. модуль
    # scoring): их роль в локализации корня, а не в весе уверенности.
    edges = facts.get("edges", {}) or {}
    erroring = set(facts.get("by_service_errors", {}) or {})
    unhealthy = erroring | silent
    d8 = False
    ev8 = "no_topology" if not edges else "no_failing_neighbor"
    for edge in sorted(edges):
        if "->" not in edge:
            continue
        src, dst = edge.split("->", 1)
        if src in erroring and dst in unhealthy and dst != src:
            state = "erroring" if dst in erroring else "silent"
            d8, ev8 = True, f"failing_downstream={dst}({state})<-{src}"
            break
    out.append(_fired("D8", "structural_neighbor", d8, 1.0, "structural", ev8,
                      applicable=bool(edges)))

    # D9 недавнее изменение (релиз, деплой, откат): любой из синонимов в потоке событий.
    hit = next((str(e) for e in events if any(k in str(e).lower() for k in DEPLOY_EVENTS)), "")
    out.append(_fired("D9", "recent_change", bool(hit), W_DEPLOY, "change",
                      f"change_event={hit}" if hit else ""))

    # D10 всплеск серверных ошибок 5xx (группа http). Под гейтом значимости.
    status_total = sum(status.values()) or 0
    share5 = (status.get("5xx", 0) / status_total) if status_total else 0.0
    d10 = bool(significant and status.get("5xx", 0) > 0 and share5 >= STATUS_5XX_SHARE)
    out.append(_fired("D10", "http_5xx_spike", d10, W_5XX, "http",
                      f"5xx_share={round(share5, 3)}",
                      applicable=status_total > 0, lr_absent=LR_ABSENT if status_total else None))

    # D11 радиус поражения по универсальным сущностям Kubernetes: под, пространство
    # имён, контейнер. Берётся максимум по осям, а не сумма, чтобы одна ошибка с
    # несколькими метками не выглядела как поражение нескольких сущностей. Под гейтом.
    reach = max(blast.get("pods", 0) or 0, blast.get("namespaces", 0) or 0,
                blast.get("containers", 0) or 0)
    d11 = bool(significant and reach >= BLAST_MIN)
    out.append(_fired("D11", "blast_radius", d11, W_BLAST, "blast", f"reach={reach}"))

    # D12 демпфер восстановления (группа damper): в ранней половине окна было заметное
    # число ошибок, а в поздней оно резко упало почти до нуля, то есть инцидент затухает.
    # Сработав, детектор понижает уверенность (см. демпфер в модуле scoring), чтобы уже
    # завершающийся инцидент не выдавался за разгорающийся. Применим при наличии
    # временного ряда. Отсутствие затухания не является свидетельством, lr_absent нет.
    d12 = False
    ev12 = "no_timeseries"
    if ts_present:
        early_errors = ts.get("early_errors", 0) or 0
        late_errors = ts.get("late_errors", 0) or 0
        d12 = bool(early_errors >= RECOVERY_MIN_ERRORS
                   and late_errors <= RECOVERY_DROP_RATIO * early_errors)
        ev12 = f"errors_early={early_errors},errors_late={late_errors}"
    out.append(_fired("D12", "recovery", d12, 1.0, "damper", ev12, applicable=ts_present))

    return out
