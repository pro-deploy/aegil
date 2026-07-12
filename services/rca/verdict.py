"""Сборка вердикта первопричины и анти-галлюцинационные гарды.

Вердикт по пятиполевой схеме: статус, уверенность, первопричина, свидетельства,
действие. Центральный гард сохранён: нет дословной цитаты, нет утверждения. Каждое
утверждение опирается на дословный фрагмент входного лога в поле evidence.snippet;
при отсутствии подтверждения поле не выдумывается, а цель обозначается unknown.

Симптомы извлекаются из ТЕКСТА строки лога универсальным каталогом (модуль
normalize), а не из поля чужого структурного канона, поэтому вердикт работает и по
обычным текстовым логам подов Kubernetes. Первичный физический отказ
(connection_refused, oom, disk_full и прочие) отделяется от вторичной волны отмен
(context_canceled, deadline_exceeded, timeout): корнем считается первичный сигнал.

Корневой сигнал выбирается по ДОМИНИРОВАНИЮ, то есть по числу подтверждающих строк,
а не по порядку появления в окне. Раньше корнем становился первый встреченный
первичный сигнал, из-за чего редкий шум мог перебить массовую причину.
"""
from __future__ import annotations

import json

from aggregator import _service, _status_class, _target
from normalize import (
    CALL_PRIMARY, PRIMARY_SIGNALS, SECONDARY_SIGNALS, SELF_PRIMARY,
    extract_symptoms,
)

# Предел числа представительных цитат в реестре свидетельств.
MAX_EVIDENCE = 6


def _rec_symptoms(rec: dict) -> set:
    """Симптомы записи из текста плюс честно переданное структурное поле-симптом."""
    syms = extract_symptoms(str(rec.get("msg", "")) or str(rec.get("_raw", "")))
    sig = rec.get("error_signal")
    if sig:
        syms.add(str(sig))
    return syms


def _entry(idx: int, rec: dict) -> dict:
    """Запись реестра свидетельств. snippet дословный: сырьё строки, если есть, иначе
    компактная реконструкция полей записи (без пересказа)."""
    raw = rec.get("_raw")
    if raw:
        snippet = str(raw)
    else:
        keys = ("level", "service", "msg", "target", "http.status", "status", "trace_id")
        snippet = json.dumps({k: rec[k] for k in keys if k in rec}, ensure_ascii=False)
    return {
        "source": f"log:{_service(rec)}:{idx}",
        "snippet": snippet,
        "kind": "log",
        "grounded": True,
    }


def guard(claim, evidence: list) -> object:
    """Гард «нет цитаты, нет утверждения»: возвращает утверждение только при наличии
    хотя бы одной подтверждающей записи, иначе None (утверждение отброшено)."""
    return claim if evidence else None


def build(facts: dict, detectors: list, score: dict, records) -> dict:
    """Собирает вердикт из фактов, детекторов, скоринга и записей. Все утверждения
    заземлены на дословные цитаты из records."""
    records = list(records)
    fired = sorted(d["id"] for d in detectors if d.get("fired"))

    ledger: list = []
    ev_keys: set = set()
    added: set = set()

    def _add(i, r, key):
        if i in added or key in ev_keys or len(ledger) >= MAX_EVIDENCE:
            return
        added.add(i)
        ev_keys.add(key)
        ledger.append(_entry(i, r))

    # Первый проход по ошибкам окна: считаем доминирование каждого первичного сигнала
    # (число подтверждающих строк), эпицентр по сервису, доминирующий сигнал 5xx, и
    # копим свидетельства. Корень выбираем по доминированию, а не по порядку.
    primary_votes: dict = {}          # сигнал -> число строк
    primary_target: dict = {}         # сигнал -> представительная цель или сервис
    primary_locus: dict = {}          # сигнал -> service | target
    five_by_service: dict = {}        # сервис -> число строк с 5xx
    err_signals: set = set()
    err_by_service: dict = {}

    for i, r in enumerate(records):
        if str(r.get("level", "")).lower() not in ("error", "fatal"):
            continue
        svc = _service(r)
        err_by_service[svc] = err_by_service.get(svc, 0) + 1
        syms = _rec_symptoms(r)
        is5xx = _status_class(r.get("http.status", r.get("status"))) == "5xx"
        for sig in syms:
            err_signals.add(sig)
        primary_here = [s for s in syms if s in PRIMARY_SIGNALS]
        for sig in primary_here:
            primary_votes[sig] = primary_votes.get(sig, 0) + 1
            if sig not in primary_target:
                if sig in SELF_PRIMARY:
                    primary_target[sig], primary_locus[sig] = svc, "service"
                else:
                    primary_target[sig], primary_locus[sig] = (_target(r) or svc), "target"
        # Свидетельство: по одной представительной цитате на пару (сервис, класс).
        if primary_here:
            _add(i, r, (svc, sorted(primary_here)[0]))
        elif is5xx:
            _add(i, r, (svc, "http_5xx"))
        elif syms:
            _add(i, r, (svc, sorted(syms)[0]))
        else:
            _add(i, r, (svc, "app_error"))
        if is5xx:
            five_by_service[svc] = five_by_service.get(svc, 0) + 1

    # Выбор корня по доминированию: первичный сигнал с наибольшим числом строк. При
    # равенстве стабильно берём лексикографически меньший, чтобы результат был
    # детерминирован. При отсутствии первичного основанием служит доминирующий 5xx.
    root_signal = None
    root_target = "unknown"
    root_locus = "target"
    if primary_votes:
        root_signal = max(sorted(primary_votes), key=lambda s: primary_votes[s])
        root_target = primary_target.get(root_signal, "unknown")
        root_locus = primary_locus.get(root_signal, "target")
    elif five_by_service:
        root_signal = "http_5xx"
        root_target = max(sorted(five_by_service), key=lambda s: five_by_service[s])

    band = score.get("band")

    # Порог утверждения инцидента. Причину заявляем при наличии свидетельств И когда
    # либо уверенность выше нижней полосы, либо сработал хотя бы один объёмный детектор
    # (spike/http/blast/network/change). Второе условие снимает парадокс «здоровье при
    # реальном всплеске»: если объёмный детектор явно сработал по волне ошибок, окно не
    # может быть объявлено здоровым только из-за того, что уверенность недобрала полосу.
    volume_groups = {"spike", "http", "blast", "change"}
    volume_fired = any(d.get("fired") and d.get("group") in volume_groups for d in detectors)
    assert_incident = bool(ledger) and (band != "low" or volume_fired)

    root_cause = None
    action = None
    if assert_incident:
        if root_signal in PRIMARY_SIGNALS:
            locus_word = "сервиса" if root_locus == "service" else "цели"
            root_cause = f"Первичный отказ «{root_signal}» у {locus_word} {root_target}"
            action = (f"Проверить доступность и состояние {locus_word} {root_target}, "
                      f"затем перезапустить затронутый поток")
        elif root_signal == "http_5xx":
            root_cause = f"Рост серверных ошибок 5xx у сервиса {root_target}"
            action = (f"Разобрать 5xx у {root_target} по номеру трассировки, проверить "
                      f"недавние изменения")
        elif err_signals and err_signals <= SECONDARY_SIGNALS:
            root_cause = "Каскад отмен от вышестоящего сервиса; первичный источник в окне не найден"
            action = "Расширить окно и искать первичный физический сигнал выше по графу вызовов"
        else:
            svc = max(sorted(err_by_service), key=lambda s: err_by_service[s]) if err_by_service else "unknown"
            root_cause = f"Прикладные ошибки сервиса {svc} без сетевого сигнала"
            action = (f"Разобрать ошибки сервиса {svc} по номеру трассировки; причина "
                      f"локальна в окне, эскалация вверх по графу не требуется")

    if not assert_incident:
        status = "healthy"
    elif band == "high":
        status = "incident"
    else:
        status = "degraded"

    ev = ledger if assert_incident else []

    return {
        "status": status,
        "confidence": {"value": score.get("confidence"), "band": band},
        "root_cause": guard(root_cause, ev),
        "evidence": ev,
        "action": guard(action, ev),
        "detectors": fired,
    }
