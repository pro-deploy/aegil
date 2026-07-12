"""Универсальный каталог симптомов Kubernetes для автономного SRE-агента aegil.

Каталог домен-агностичен: он не знает и не предполагает имён приложения владельца, а описывает
нейтральные симптомы, характерные для любого кластера Kubernetes. Каждый детектор чист и
детерминирован: он принимает уже собранные факты (списки подов, узлов, деплойментов, событий, сводки
kubelet, срок сертификата TLS) и возвращает список алертов. Ввод-вывод (обращения к Kubernetes, RCA и
прикладному адаптеру) собирает автопилот в ``autopilot.observe``, поэтому детекторы проверяются
модульными тестами на подставных данных без выхода в сеть.

Каждый алерт несёт синтетический вердикт для центра инцидентов. Отпечаток строится обычным механизмом
``incidents.fingerprint`` по полям ``status``, ``detectors`` и ``root_cause``, поэтому одинаковые
симптомы группируются, а конкретные имена подов и числовые значения выносятся в ``params`` и в
отпечаток не входят.

Форма алерта:
  {"code": "<нейтральный код симптома>", "severity": "critical|high|warning",
   "title": "<нейтральное описание симптома>", "verdict": {...}, "params": {...}}

Пороги выносятся в переменные окружения с единым префиксом ``AEGIL_`` и имеют нейтральные значения
по умолчанию, пригодные для произвольного кластера без предварительной калибровки под конкретное
приложение.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import k8s

# --- Пороги (переопределяются переменными окружения AEGIL_, нейтральные значения по умолчанию) ---

# Порог числа рестартов пода за окно наблюдения, за которым рестарты трактуются как шторм. Окно по
# умолчанию один час.
RESTART_STORM_THRESHOLD = int(os.getenv("AEGIL_RESTART_STORM_THRESHOLD", "5"))
RESTART_WINDOW_SECONDS = int(os.getenv("AEGIL_RESTART_WINDOW_SECONDS", "3600"))

# Порог длительности ожидания планирования пода (Pending или Unschedulable), за которым ожидание
# трактуется как затянувшееся. По умолчанию пять минут.
PENDING_AGE_SECONDS = int(os.getenv("AEGIL_PENDING_AGE_SECONDS", "300"))

# Пороги заполнения файловой системы узла в процентах: предупреждение и критично. Соответствуют
# смыслу наследных ALERT_DISK_WARN и ALERT_DISK_CRIT, но объявлены здесь под префиксом AEGIL_ с
# нейтральными значениями по умолчанию, потому что каталог симптомов является их владельцем.
DISK_WARN_PCT = int(os.getenv("AEGIL_DISK_WARN", "80"))
DISK_CRIT_PCT = int(os.getenv("AEGIL_DISK_CRIT", "90"))

# Порог заполнения памяти узла в процентах (предупреждение). Давление памяти как условие узла
# (MemoryPressure) обрабатывается отдельно и всегда критичнее процентного порога.
MEM_WARN_PCT = int(os.getenv("AEGIL_MEM_WARN", "90"))

# Пороги остатка срока действия сертификата TLS в сутках: предупреждение и высокая серьёзность.
TLS_WARN_DAYS = int(os.getenv("AEGIL_TLS_WARN_DAYS", "14"))
TLS_HIGH_DAYS = int(os.getenv("AEGIL_TLS_HIGH_DAYS", "7"))

# Причины ожидания контейнера, означающие невозможность стартовать образ.
_IMAGE_PULL_REASONS = ("ImagePullBackOff", "ErrImagePull", "InvalidImageName")
# Причины событий кластера, которые заслуживают внимания как предупреждения планирования и монтирования.
_EVENT_REASONS = ("FailedScheduling", "FailedMount", "FailedAttachVolume", "BackOff", "Unhealthy",
                  "FailedCreatePodSandBox")


def _alert(code: str, severity: str, title: str, params: dict | None = None,
           band: str = "high") -> dict:
    """Собирает алерт с синтетическим вердиктом для группировки в центре инцидентов. Параметры
    симптома кладутся и внутрь вердикта (params), чтобы пережить сохранение в журнале инцидентов и
    попасть к агентному расследованию. В отпечаток params не входят, поэтому группировка одинаковых
    симптомов не ломается конкретным именем пода или числовым значением."""
    p = params or {}
    return {"code": code, "severity": severity, "title": title, "params": p,
            "verdict": {"status": "incident", "band": band, "detectors": [code],
                        "root_cause": title, "params": p}}


def _parse_ts(raw) -> datetime | None:
    """Разбирает метку времени ISO 8601 (в том числе с суффиксом Z) в осведомлённое о зоне значение."""
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Симптомы уровня подов.
# ---------------------------------------------------------------------------


def check_crashloop(pods) -> list:
    """Поды в состоянии CrashLoopBackOff: контейнер циклически падает и перезапускается. Один алерт
    на сервис-владелец пода (отпечаток без хэшей пода), чтобы серия подов одного сервиса давала один
    инцидент."""
    out, seen = [], set()
    for p in pods or []:
        if p.get("waiting_reason") != "CrashLoopBackOff":
            continue
        svc = k8s.pod_service(p.get("name", ""))
        if svc in seen:
            continue
        seen.add(svc)
        out.append(_alert("crashloop", "high",
                          f"Под сервиса {svc} в CrashLoopBackOff (контейнер циклически падает)",
                          {"service": svc, "pod": p.get("name", ""),
                           "reason": "CrashLoopBackOff"}))
    return out


def check_image_pull(pods) -> list:
    """Поды, у которых образ не скачивается (ImagePullBackOff, ErrImagePull, InvalidImageName): под не
    может стартовать, пока образ или его тег недоступны. Один алерт на сервис."""
    out, seen = [], set()
    for p in pods or []:
        reason = p.get("waiting_reason")
        if reason not in _IMAGE_PULL_REASONS:
            continue
        svc = k8s.pod_service(p.get("name", ""))
        if svc in seen:
            continue
        seen.add(svc)
        out.append(_alert("image_pull", "high",
                          f"Под сервиса {svc} не может скачать образ ({reason})",
                          {"service": svc, "pod": p.get("name", ""), "reason": reason}))
    return out


def check_oom(pods) -> list:
    """Поды, чей контейнер был убит из-за нехватки памяти (OOMKilled в последнем завершении). Один
    алерт на сервис."""
    out, seen = [], set()
    for p in pods or []:
        if not p.get("oom_killed"):
            continue
        svc = k8s.pod_service(p.get("name", ""))
        if svc in seen:
            continue
        seen.add(svc)
        out.append(_alert("oom_killed", "high",
                          f"Контейнер сервиса {svc} убит по нехватке памяти (OOMKilled)",
                          {"service": svc, "pod": p.get("name", ""), "reason": "OOMKilled"}))
    return out


def check_pending(pods, now: datetime | None = None) -> list:
    """Поды, застрявшие в фазе Pending дольше порога: планировщик не может разместить под (нет
    ресурсов, нет подходящего узла, не смонтирован том). Длительность ожидания оценивается по метке
    времени начала (started_at или creation_timestamp), если она есть; при отсутствии метки под
    считается затянувшимся, только когда явно помечен waiting_reason о невозможности планирования."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(seconds=PENDING_AGE_SECONDS)
    out, seen = [], set()
    for p in pods or []:
        if p.get("phase") != "Pending":
            continue
        started = _parse_ts(p.get("started_at") or p.get("creation_timestamp"))
        reason = p.get("waiting_reason")
        # Затянувшимся считается под, который либо провёл в Pending дольше порога по метке времени,
        # либо явно помечен планировщиком как неразмещаемый (Unschedulable). Без метки времени и без
        # явного признака невозможности планирования под не диагностируется (это может быть штатный
        # кратковременный Pending при обычном запуске).
        overdue = (started is not None and started <= cutoff) or reason == "Unschedulable"
        if not overdue:
            continue
        svc = k8s.pod_service(p.get("name", ""))
        if svc in seen:
            continue
        seen.add(svc)
        out.append(_alert("pending", "warning",
                          f"Под сервиса {svc} не может быть запланирован (длительный Pending)",
                          {"service": svc, "pod": p.get("name", ""),
                           "reason": reason or "Pending"}))
    return out


def check_restart_storm(pods, now: datetime | None = None) -> list:
    """Рестарт-шторм: под перезапускался чаще порога за окно наблюдения, не находясь при этом в
    CrashLoopBackOff и не будучи убитым по памяти (эти случаи покрыты отдельными детекторами). Один
    алерт на сервис."""
    now = now or datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=RESTART_WINDOW_SECONDS)
    out, seen = [], set()
    for p in pods or []:
        if p.get("waiting_reason") == "CrashLoopBackOff" or p.get("oom_killed"):
            continue
        if (p.get("restarts", 0) or 0) < RESTART_STORM_THRESHOLD:
            continue
        when = _parse_ts(p.get("last_restart_at"))
        if when is None or when < window_start:
            continue
        svc = k8s.pod_service(p.get("name", ""))
        if svc in seen:
            continue
        seen.add(svc)
        out.append(_alert("restart_storm", "warning",
                          f"Рестарт-шторм пода сервиса {svc} ({p.get('restarts')} рестартов за окно)",
                          {"service": svc, "pod": p.get("name", ""),
                           "restarts": p.get("restarts", 0)}))
    return out


# ---------------------------------------------------------------------------
# Симптомы уровня деплойментов.
# ---------------------------------------------------------------------------


def check_deploy_unavailable(deployments) -> list:
    """Деплойменты, у которых число готовых реплик меньше желаемого: приложение работает не в полном
    составе либо не работает вовсе. Один алерт на деплоймент с указанием готовых и желаемых реплик."""
    out = []
    for d in deployments or []:
        desired = d.get("desired") or 0
        ready = d.get("ready") or 0
        if desired <= 0 or ready >= desired:
            continue
        sev = "critical" if ready == 0 else "high"
        out.append(_alert("deploy_unavailable", sev,
                          f"Деплоймент {d.get('name')} недоступен: готово {ready} из {desired} реплик",
                          {"deployment": d.get("name"), "ready": ready, "desired": desired}))
    return out


# ---------------------------------------------------------------------------
# Симптомы уровня узлов.
# ---------------------------------------------------------------------------


def check_node_disk(nodes, stats_by_node) -> list:
    """Файловые системы узлов, заполненные выше порогов AEGIL_DISK_WARN (предупреждение) и
    AEGIL_DISK_CRIT (критично) по сводке kubelet. Один алерт на файловую систему узла."""
    import status as status_cards
    out = []
    for n in nodes or []:
        u = status_cards.node_usage(n, (stats_by_node or {}).get(n.get("name")))
        for fs in u.get("fs") or []:
            pct = fs.get("pct") or 0
            if pct < DISK_WARN_PCT:
                continue
            crit = pct >= DISK_CRIT_PCT
            sev = "critical" if crit else "warning"
            out.append(_alert("node_disk", sev,
                              f"Файловая система узла {n.get('name')} ({fs.get('label')}) заполнена "
                              f"на {pct}%",
                              {"node": n.get("name"), "fs": fs.get("label"), "pct": pct,
                               "crit": crit}))
    return out


def check_node_memory(nodes, stats_by_node) -> list:
    """Узлы, память которых заполнена выше порога AEGIL_MEM_WARN по сводке kubelet. Отдельно от
    условия узла MemoryPressure: процентный порог срабатывает раньше, чем kubelet выставит давление."""
    import status as status_cards
    out = []
    for n in nodes or []:
        u = status_cards.node_usage(n, (stats_by_node or {}).get(n.get("name")))
        pct = u.get("mem_pct")
        if pct is None or pct < MEM_WARN_PCT:
            continue
        out.append(_alert("node_memory", "warning",
                          f"Память узла {n.get('name')} заполнена на {pct}%",
                          {"node": n.get("name"), "pct": pct}))
    return out


def check_node_pressure(nodes) -> list:
    """Узлы под давлением ресурсов по условиям Kubernetes: не Ready, MemoryPressure или DiskPressure.
    Эти условия выставляет сам kubelet, поэтому они достоверны даже когда сводка kubelet недоступна."""
    out = []
    for n in nodes or []:
        name = n.get("name")
        if not n.get("ready", True):
            out.append(_alert("node_not_ready", "critical",
                              f"Узел {name} не Ready",
                              {"node": name, "condition": "NotReady"}))
        if n.get("memory_pressure"):
            out.append(_alert("node_pressure", "high",
                              f"Узел {name} под давлением памяти (MemoryPressure)",
                              {"node": name, "condition": "MemoryPressure"}))
        if n.get("disk_pressure"):
            out.append(_alert("node_pressure", "high",
                              f"Узел {name} под давлением диска (DiskPressure)",
                              {"node": name, "condition": "DiskPressure"}))
    return out


# ---------------------------------------------------------------------------
# Симптомы уровня событий кластера.
# ---------------------------------------------------------------------------


def check_warning_events(events) -> list:
    """Предупреждающие события кластера (type=Warning) с известными причинами планирования,
    монтирования и запуска (FailedScheduling, FailedMount, FailedAttachVolume, BackOff, Unhealthy).
    Один алерт на причину, чтобы поток однотипных событий давал один инцидент; в параметры кладётся
    имя затронутого объекта и суммарный счётчик повторов."""
    out = {}
    for e in events or []:
        if e.get("type") != "Warning":
            continue
        reason = e.get("reason")
        if reason not in _EVENT_REASONS:
            continue
        acc = out.setdefault(reason, {"count": 0, "objects": set()})
        acc["count"] += int(e.get("count", 1) or 1)
        if e.get("object"):
            acc["objects"].add(e.get("object"))
    alerts_out = []
    for reason, acc in sorted(out.items()):
        objects = sorted(acc["objects"])
        alerts_out.append(_alert("warning_event", "warning",
                                 f"Предупреждающие события кластера: {reason}",
                                 {"reason": reason, "count": acc["count"],
                                  "objects": objects}, band="uncertain"))
    return alerts_out


# ---------------------------------------------------------------------------
# Симптомы вне Kubernetes, доступные через универсальные адаптеры.
# ---------------------------------------------------------------------------


def check_tls_expiry(tls_days) -> list:
    """Истечение срока действия сертификата TLS для хоста AEGIL_TLS_HOST. Значение приходит из
    app_adapter.tls_days_left (проверка не чаще раза в сутки). Если хост не задан, значение None и
    детектор молчит."""
    if tls_days is None or tls_days > TLS_WARN_DAYS:
        return []
    sev = "high" if tls_days <= TLS_HIGH_DAYS else "warning"
    return [_alert("tls_expiry", sev,
                   f"Сертификат TLS истекает через {tls_days} сут",
                   {"days": tls_days})]


# ---------------------------------------------------------------------------
# Прогон всего каталога.
# ---------------------------------------------------------------------------


def detect_all(facts: dict) -> list:
    """Прогоняет весь универсальный каталог симптомов над собранными фактами. Ключи facts:
    pods, nodes, deployments, events, stats_by_node, tls_days, now. Отсутствующий факт (None)
    означает недоступность соответствующего источника наблюдения, и связанные детекторы честно
    молчат, а не выдают ложное здоровье; различение слепоты и здоровья выполняет автопилот."""
    f = facts or {}
    now = f.get("now")
    out = []
    out += check_crashloop(f.get("pods"))
    out += check_image_pull(f.get("pods"))
    out += check_oom(f.get("pods"))
    out += check_pending(f.get("pods"), now)
    out += check_restart_storm(f.get("pods"), now)
    out += check_deploy_unavailable(f.get("deployments"))
    out += check_node_disk(f.get("nodes"), f.get("stats_by_node"))
    out += check_node_memory(f.get("nodes"), f.get("stats_by_node"))
    out += check_node_pressure(f.get("nodes"))
    out += check_warning_events(f.get("events"))
    out += check_tls_expiry(f.get("tls_days"))
    return out
