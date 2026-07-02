"""Сборка вердикта RCA и анти-галлюцинационные гарды (ADR-0032, Часть B.6; книга
Биркина, глава 9). Вердикт по пятиполевой схеме: статус, уверенность, первопричина,
свидетельства, действие. Центральный гард: нет цитаты, нет утверждения. Каждое
утверждение опирается на дословную цитату из входных логов в поле evidence.snippet;
при отсутствии подтверждения поле не выдумывается, а цель обозначается unknown.

Реестр свидетельств (Evidence Ledger) хранит записи с источником вида
log:service:line, дословным фрагментом, типом и признаком заземления. Первичный
отказ (connection_refused, oom, disk_full, dns_error) отделяется от вторичной волны
отмен (context_canceled, deadline_exceeded): корнем считается первичный сигнал.
"""
from __future__ import annotations

import json

from aggregator import _status_class, _target
from normalize import template as _template

# Первичные физические отказы. Разделены по локусу: отказы вызова (цель это вызываемый
# сервис) и отказы самого сервиса (локус это сам эмитент, поля цели вызова у них нет).
CALL_PRIMARY = {"connection_refused", "dns_error", "tls_error"}
SELF_PRIMARY = {"oom", "disk_full"}
PRIMARY_SIGNALS = CALL_PRIMARY | SELF_PRIMARY

# Вторичная волна отмен: приходит сверху по графу, корнем не является.
SECONDARY_SIGNALS = {"context_canceled", "deadline_exceeded"}

# Предел числа представительных цитат в реестре: по одной на пару (сервис, сигнал),
# не больше этого, чтобы вердикт не раздувался повторами одинаковых строк. Полные
# счётчики событий лежат в фактах агрегатора.
MAX_EVIDENCE = 6


def _entry(idx: int, rec: dict) -> dict:
    """Запись реестра свидетельств. snippet дословный: сырьё строки, если есть,
    иначе компактная реконструкция канонических полей (без пересказа)."""
    raw = rec.get("_raw")
    if raw:
        snippet = str(raw)
    else:
        keys = ("ts", "level", "service", "msg", "error_signal", "target", "http.status", "trace_id")
        snippet = json.dumps({k: rec[k] for k in keys if k in rec}, ensure_ascii=False)
    return {
        "source": f"log:{rec.get('service', '?')}:{idx}",
        "snippet": snippet,
        "kind": "log",
        "grounded": True,
    }


def guard(claim, evidence: list) -> object:
    """Гард «нет цитаты, нет утверждения»: возвращает утверждение только при
    наличии хотя бы одной подтверждающей записи, иначе None (утверждение отброшено)."""
    return claim if evidence else None


def build(facts: dict, detectors: list, score: dict, records) -> dict:
    """Собирает вердикт RCA из фактов, сработавших детекторов, скоринга и записей.
    Все утверждения заземлены на дословные цитаты из records."""
    records = list(records)
    fired = sorted(d["id"] for d in detectors if d.get("fired"))

    ledger: list[dict] = []
    ev_keys: set = set()
    added: set = set()

    def _add(i, r, key):
        # Представительная цитата: одна на пару (сервис, сигнал), не более лимита и
        # без повтора одной строки; полные счётчики есть в фактах агрегатора.
        if i in added or key in ev_keys or len(ledger) >= MAX_EVIDENCE:
            return
        added.add(i)
        ev_keys.add(key)
        ledger.append(_entry(i, r))

    # Определение корня: первичный физический отказ важнее вторичной волны отмен;
    # при отсутствии первичного основанием служат ошибки 5xx. Параллельно копим
    # природу ошибок окна, чтобы честно отличить каскад отмен от локальной прикладной
    # ошибки, у которой причина заземлена прямо в окне (гард главы 9).
    root_signal = None
    root_target = "unknown"
    root_locus = "target"           # target это вызываемый сервис, service это сам эмитент
    five_target = None
    err_signals: set = set()         # какие сигналы вообще встретились среди ошибок
    err_by_service: dict = {}        # число ошибок по сервисам
    err_templates: dict = {}         # доминирующий шаблон ошибки (нормализованный)
    for i, r in enumerate(records):
        if str(r.get("level", "")).lower() not in ("error", "fatal"):
            continue
        svc = str(r.get("service", "")) or "unknown"
        err_by_service[svc] = err_by_service.get(svc, 0) + 1
        tmpl = _template(str(r.get("msg", "")))
        if tmpl:
            err_templates[tmpl] = err_templates.get(tmpl, 0) + 1
        sig = r.get("error_signal")
        is5xx = _status_class(r.get("http.status", r.get("status"))) == "5xx"
        if sig:
            err_signals.add(str(sig))
            _add(i, r, (svc, str(sig)))
            if sig in PRIMARY_SIGNALS and root_signal is None:
                root_signal = sig
                if sig in SELF_PRIMARY:
                    root_target, root_locus = svc, "service"
                else:
                    root_target, root_locus = (_target(r) or svc), "target"
        elif is5xx:
            _add(i, r, (svc, "http_5xx"))
        if is5xx and five_target is None:
            five_target = svc

    if root_signal is None and five_target is not None:
        root_signal = "http_5xx"
        root_target = five_target

    # Порог утверждения: причину заявляем только при свидетельствах И уверенности выше
    # нижней полосы. Слабый сигнал (band=low, например единичный флап, отсечённый гейтом
    # значимости детекторов) инцидентом не объявляется и причину не выдумывает.
    band = score.get("band")
    assert_incident = bool(ledger) and band != "low"

    # Формулировка первопричины и действия, только при заявленном инциденте.
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
            action = f"Разобрать 5xx у {root_target} по номеру трассировки, проверить недавние изменения (D9)"
        elif err_signals and err_signals <= SECONDARY_SIGNALS:
            # Только вторичные отмены и ни одного первичного сигнала: это законный
            # каскад, источник которого лежит выше границы окна.
            root_cause = "Каскад отмен от вышестоящего сервиса; первичный источник в окне не найден"
            action = "Расширить окно и искать первичный физический сигнал выше по графу вызовов"
        else:
            # Прикладные ошибки без классифицированного сетевого сигнала: причина
            # локальна и заземлена в окне, вверх по графу идти не нужно. Называем
            # сервис-эпицентр и доминирующий шаблон ошибки, не выдумывая каскад.
            svc = max(err_by_service, key=err_by_service.get) if err_by_service else "unknown"
            tmpl = max(err_templates, key=err_templates.get) if err_templates else ""
            root_cause = (f"Прикладные ошибки сервиса {svc} без сетевого сигнала; "
                          f"доминирующий шаблон: «{tmpl}»")
            action = (f"Разобрать ошибки сервиса {svc} по номеру трассировки; причина "
                      f"локальна в окне, эскалация вверх по графу не требуется")

    # Статус по полосе доверия: без заявленного инцидента окно считается здоровым
    # (ошибок нет либо сигнал ниже порога значимости), иначе degraded или incident.
    if not assert_incident:
        status = "healthy"
    elif band == "high":
        status = "incident"
    else:
        status = "degraded"

    # Свидетельства при здоровом статусе не выносим: нет утверждения, нет и цитаты к нему.
    ev = ledger if assert_incident else []

    return {
        "status": status,                                              # 1
        "confidence": {"value": score.get("confidence"), "band": band},  # 2
        "root_cause": guard(root_cause, ev),                           # 3
        "evidence": ev,                                                # 4
        "action": guard(action, ev),                                  # 5
        "detectors": fired,
    }
