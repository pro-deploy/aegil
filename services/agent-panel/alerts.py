"""Каталог алертов автономного агента (ADR-0038, раздел 6, этапы 3, 4 и 5: A1..A12).

Каждая проверка детерминирована и чиста: принимает уже собранные факты (списки узлов и
подов, сводки kubelet, сводку конвейера, вердикты RCA, посчитанные факты окна логов) и
возвращает список алертов. Пороги вынесены в константы с переопределением через ENV. Алерт
несёт синтетический вердикт для центра инцидентов (отпечаток строится обычным механизмом
incidents.fingerprint) и параметры для плейбука (какой сервис или под виноват).

Форма алерта:
  {"code": "A2", "severity": "critical|high|warning", "title": "...",
   "verdict": {...}, "params": {...}}
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import k8s

# Пороги (ENV-переопределение, значения по умолчанию из спецификации).
STUCK_AGE_SECONDS = int(os.getenv("AGENT_STUCK_AGE_SECONDS", "600"))
DISK_WARN_PCT = int(os.getenv("AGENT_DISK_WARN_PCT", "80"))
DISK_CRIT_PCT = int(os.getenv("AGENT_DISK_CRIT_PCT", "90"))
RESTARTS_PER_HOUR = int(os.getenv("AGENT_RESTARTS_PER_HOUR", "3"))
# A6: деградация латентности распознавания, p95 latency_ms событий ml.call target=asr за
# 10 минут. Два порога: предупреждение и критично. Стартовые значения из спецификации,
# калибруются по факту через ENV.
LATENCY_ASR_P95_WARN_MS = int(os.getenv("AGENT_LATENCY_ASR_P95_WARN_MS", "8000"))
LATENCY_ASR_P95_CRIT_MS = int(os.getenv("AGENT_LATENCY_ASR_P95_CRIT_MS", "16000"))
# A8: молчание сервиса, под Running, но в Loki ноль строк от него за окно, хотя обычно
# пишет чаще. Список сервисов, которые обязаны регулярно писать (базовая линия).
SILENCE_MINUTES = int(os.getenv("AGENT_SILENCE_MINUTES", "10"))
SILENCE_SERVICES = {s.strip() for s in os.getenv(
    "AGENT_SILENCE_SERVICES", "api,worker,asr,diarize").split(",") if s.strip()}
# A9: живой режим у потолка, занятость выше порога процента.
LIVE_OCCUPANCY_PCT = int(os.getenv("AGENT_LIVE_OCCUPANCY_PCT", "85"))
# A10: сертификат TLS истекает. Порог предупреждения и высокой серьёзности в сутках.
TLS_WARN_DAYS = int(os.getenv("AGENT_TLS_WARN_DAYS", "14"))
TLS_HIGH_DAYS = int(os.getenv("AGENT_TLS_HIGH_DAYS", "7"))
# A6 плейбук: пороги роста нагрузки, при которых деградация латентности связывается с
# ростом параллелизма (тогда снижаем параллелизм), а не со сбоем самого asr.
LOAD_PROCESSING_HINT = int(os.getenv("AGENT_LOAD_PROCESSING_HINT", "3"))

# Признаки сетевых отказов в текстах вердиктов RCA.
_CONN_SIGNALS = ("connection_refused", "timeout", "dns_error")
# Признаки, что отказ касается ML-контура (GPU-узла).
_ML_HINTS = ("ml.call", "asr", "diarize", "9101", "9104")


def _verdict_text(verdict: dict) -> str:
    """Склеенный текст вердикта RCA (первопричина плюс цитаты) для поиска сигналов."""
    v = verdict or {}
    parts = [str(v.get("root_cause") or ""), str(v.get("action") or "")]
    for e in v.get("evidence") or []:
        parts.append(str(e.get("snippet") or ""))
        parts.append(str(e.get("source") or ""))
    return " ".join(parts).lower()


def _alert(code: str, severity: str, title: str, params: dict | None = None) -> dict:
    """Собирает алерт с синтетическим вердиктом для группировки в центре инцидентов.
    Параметры плейбука кладутся и внутрь вердикта (params), чтобы пережить сохранение в
    журнале инцидентов: подсказка «Показать логи» берёт имя виновного пода именно оттуда.
    В отпечаток params не входят (fingerprint смотрит только status, detectors, root_cause),
    поэтому группировка одинаковых инцидентов не ломается конкретным именем пода."""
    p = params or {}
    return {"code": code, "severity": severity, "title": title,
            "params": p,
            "verdict": {"status": "incident", "band": "high",
                        "detectors": [code], "root_cause": title, "params": p}}


# ---------------------------------------------------------------------------
# Проверки A1..A5, A7.
# ---------------------------------------------------------------------------


def check_a1(nodes, stats_by_node, rca_verdict, gpu_node: str) -> list:
    """A1: GPU-узел недоступен: узел не Ready, kubelet молчит либо RCA видит
    connection_refused/timeout к ML. Стоит вся транскрибация."""
    out = []
    diag = None
    if nodes is not None:
        gn = next((n for n in nodes if n.get("name") == gpu_node), None)
        if gn is not None and not gn.get("ready"):
            diag = f"узел {gpu_node} не Ready в Kubernetes (узел целиком или туннель)"
        elif gn is not None and (stats_by_node or {}).get(gpu_node) is None:
            diag = f"kubelet узла {gpu_node} не отвечает (туннель или kubelet)"
    if diag is None:
        text = _verdict_text(rca_verdict)
        if any(s in text for s in ("connection_refused", "timeout")) \
                and any(h in text for h in _ML_HINTS):
            diag = "вызовы ML дают connection_refused или timeout (сервисы GPU-узла)"
    if diag:
        out.append(_alert("A1", "critical",
                          f"GPU-узел недоступен: {diag}",
                          {"node": gpu_node, "diagnosis": diag}))
    return out


def check_a2(stuck_verdict, overview) -> list:
    """A2: очередь не движется: RCA /stuck видит застрявшие ИЛИ возраст старейшего
    ожидающего задания больше STUCK_AGE_SECONDS."""
    out = []
    sv = stuck_verdict or {}
    if sv.get("status") in ("incident", "degraded"):
        out.append(_alert("A2", "high", "Застрявшие задания в конвейере (RCA /stuck)",
                          {"source": "stuck"}))
        return out
    q = ((overview or {}).get("queue") or {})
    age = q.get("oldest_waiting_seconds") or 0
    queued = (q.get("by_status") or {}).get("queued", 0)
    if queued and age > STUCK_AGE_SECONDS:
        out.append(_alert("A2", "high",
                          "Очередь стоит: старейшее ожидающее задание старше порога",
                          {"source": "overview", "age_seconds": age}))
    return out


def check_a3(nodes, stats_by_node) -> list:
    """A3: любая файловая система узла заполнена выше DISK_WARN_PCT (предупреждение)
    или DISK_CRIT_PCT (критично) по сводке kubelet. Для плейбука уровня B алерт несёт
    признак критичности (crit) и метку тома: только для узла управления (control), где
    живут поды воркера, эфемерная очистка временных файлов имеет смысл."""
    import status as status_cards
    out = []
    for n in nodes or []:
        u = status_cards.node_usage(n, (stats_by_node or {}).get(n.get("name")))
        for fs in u.get("fs") or []:
            p = fs.get("pct") or 0
            if p >= DISK_WARN_PCT:
                crit = p >= DISK_CRIT_PCT
                sev = "critical" if crit else "warning"
                out.append(_alert(
                    "A3", sev,
                    f"Диск узла {n.get('name')} ({fs.get('label')}) заполнен на {p}%",
                    {"node": n.get("name"), "fs": fs.get("label"), "pct": p,
                     "crit": crit}))
    return out


def check_a4(pods, now: datetime | None = None) -> list:
    """A4: под падает: CrashLoopBackOff, OOMKilled или больше RESTARTS_PER_HOUR
    рестартов за последний час. Один алерт на сервис (отпечаток без хэшей пода)."""
    now = now or datetime.now(timezone.utc)
    hour_ago = now - timedelta(hours=1)
    out = []
    seen = set()
    pipeline = {"asr", "diarize", "worker", "api"}
    for p in pods or []:
        reason = None
        if p.get("waiting_reason") == "CrashLoopBackOff":
            reason = "CrashLoopBackOff"
        elif p.get("oom_killed"):
            reason = "OOMKilled"
        else:
            ts = p.get("last_restart_at")
            if p.get("restarts", 0) > RESTARTS_PER_HOUR and ts:
                try:
                    when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
                except ValueError:
                    when = None
                if when and when >= hour_ago:
                    reason = f"больше {RESTARTS_PER_HOUR} рестартов за час"
        if not reason:
            continue
        svc = k8s.pod_service(p.get("name", ""))
        if svc in seen:
            continue
        seen.add(svc)
        sev = "high" if svc in pipeline else "warning"
        out.append(_alert("A4", sev, f"Под сервиса {svc} падает: {reason}",
                          {"service": svc, "pod": p.get("name", ""), "reason": reason}))
    return out


def check_a5(rca_verdict) -> list:
    """A5: всплеск 5xx на api: детектор D10 в вердикте RCA. Виновник плейбука: сервис
    из allowlist, упомянутый в первопричине; иначе только эскалация."""
    v = rca_verdict or {}
    if "D10" not in (v.get("detectors") or []):
        return []
    text = _verdict_text(v)
    culprit = next((s for s in sorted(k8s.ALLOWED) if s in text), None)
    return [_alert("A5", "critical",
                   "Всплеск ошибок 5xx на api (детектор D10)",
                   {"culprit": culprit, "root_cause": v.get("root_cause")})]


def check_a7(rca_verdict, pods) -> list:
    """A7: недоступно хранилище состояния: connection_refused либо dns_error к postgres
    или redis в вердикте RCA; фаза пода прикладывается как подтверждение."""
    text = _verdict_text(rca_verdict)
    if not any(s in text for s in ("connection_refused", "dns_error")):
        return []
    out = []
    for store in ("postgres", "redis"):
        if store not in text:
            continue
        pod = next((p for p in pods or [] if p.get("name", "").startswith(store)), None)
        phase = pod.get("phase") if pod else "неизвестна (панель вне кластера)"
        out.append(_alert("A7", "critical",
                          f"Хранилище {store} недоступно (connection_refused/dns_error)",
                          {"store": store, "pod_phase": phase,
                           "pod": pod.get("name") if pod else None}))
    return out


def check_a6(rca_facts, overview) -> list:
    """A6: деградация латентности распознавания. p95 latency_ms событий ml.call с target=asr
    за окно выше порога (факты окна логов из RCA, блок latency_by_target). Плейбук решает по
    соседним фактам: если нагрузка (число обрабатываемых заданий) высока, деградация связана
    с ростом параллелизма (снизить параллелизм), иначе разовый перезапуск asr."""
    lat = ((rca_facts or {}).get("latency_by_target") or {}).get("asr") or {}
    p95 = lat.get("p95_ms")
    if not isinstance(p95, (int, float)) or p95 < LATENCY_ASR_P95_WARN_MS:
        return []
    sev = "high" if p95 >= LATENCY_ASR_P95_CRIT_MS else "warning"
    processing = ((overview or {}).get("queue") or {}).get("processing") or 0
    load_high = processing >= LOAD_PROCESSING_HINT
    return [_alert("A6", sev,
                   f"Латентность распознавания выросла: p95 {int(p95)} мс (target=asr)",
                   {"p95_ms": int(p95), "processing": processing,
                    "load_high": load_high})]


def check_a8(pods, rca_facts) -> list:
    """A8: молчание сервиса. Под сервиса в Running, но в Loki ноль строк от него за окно,
    хотя обычно пишет чаще (базовая линия SILENCE_SERVICES). Живой труп опаснее упавшего
    пода: его не видит ни один другой алерт. Закрывает отложенный детектор D7 из ADR-0032.
    Плейбук: уровень A разовый перезапуск, если сервис в allowlist, иначе эскалация."""
    if rca_facts is None or pods is None:
        return []  # без фактов окна или без списка подов молчание не диагностируется
    by_service = rca_facts.get("by_service") or {}
    out = []
    seen = set()
    for p in pods:
        if p.get("phase") != "Running" or p.get("waiting_reason"):
            continue
        svc = k8s.pod_service(p.get("name", ""))
        if svc not in SILENCE_SERVICES or svc in seen:
            continue
        seen.add(svc)
        if by_service.get(svc, 0) == 0:
            out.append(_alert(
                "A8", "warning",
                f"Сервис {svc} молчит: под Running, но за {SILENCE_MINUTES} мин ни строки логов",
                {"service": svc, "pod": p.get("name", ""),
                 "silence_minutes": SILENCE_MINUTES}))
    return out


def check_a9(overview) -> list:
    """A9: живой режим у потолка. Занятость слотов живого режима выше LIVE_OCCUPANCY_PCT
    процента потолка (данные /api/admin/overview, блок live). Плейбук: автономных действий
    нет (потолок железный), только эскалация-информирование с трендом."""
    live = (overview or {}).get("live") or {}
    active = live.get("active") or 0
    capacity = live.get("capacity") or 0
    if capacity <= 0:
        return []
    pct = int(round(100.0 * active / capacity))
    if pct < LIVE_OCCUPANCY_PCT:
        return []
    return [_alert("A9", "warning",
                   f"Живой режим у потолка: занято {active} из {capacity} слотов ({pct}%)",
                   {"active": active, "capacity": capacity, "pct": pct})]


def check_a10(tls_days) -> list:
    """A10: сертификат TLS истекает. Проверка раз в сутки (значение из кэша status.py):
    порог TLS_WARN_DAYS предупреждение, TLS_HIGH_DAYS высокая серьёзность. Плейбук:
    эскалация с фактами (продление вне досягаемости панели)."""
    if tls_days is None or tls_days > TLS_WARN_DAYS:
        return []
    sev = "high" if tls_days <= TLS_HIGH_DAYS else "warning"
    return [_alert("A10", sev,
                   f"Сертификат TLS истекает через {tls_days} сут",
                   {"days": tls_days})]


def check_a11(rca_facts) -> list:
    """A11: почта не уходит. Ошибки отправки в логах stalwart за окно (по by_service_errors
    сервиса stalwart и сигналам отказов). Плейбук: stalwart в denylist, автономного
    перезапуска нет, только эскалация с разделением кодов отказов получателей и сетевых
    ошибок (это разные проблемы)."""
    f = rca_facts or {}
    errs = (f.get("by_service_errors") or {}).get("stalwart", 0)
    if not errs:
        return []
    signals = f.get("error_signals") or {}
    # Сетевые сигналы (недоступность релея, DNS, таймаут) против кодов отказов получателей.
    network = sum(v for k, v in signals.items()
                  if any(s in str(k) for s in _CONN_SIGNALS))
    recipient = max(0, errs - network)
    return [_alert("A11", "warning",
                   f"Почта не уходит: {errs} ошибок отправки stalwart за окно",
                   {"errors": errs, "network_errors": network,
                    "recipient_errors": recipient})]


def check_a12(rca_facts) -> list:
    """A12: ошибки биллинга и квот. Ошибки в биллинговых путях за окно (по событиям и
    сигналам ошибок в логах api). Плейбук: только эскалация, автономные действия запрещены
    (любое автоматическое вмешательство в биллинг опаснее самой ошибки)."""
    f = rca_facts or {}
    events = f.get("event_counts") or {}
    billing_events = sum(v for k, v in events.items()
                         if any(s in str(k).lower()
                                for s in ("billing", "quota", "reserve", "payment")))
    if not billing_events:
        return []
    return [_alert("A12", "high",
                   f"Ошибки в биллинговых путях: {billing_events} событий за окно",
                   {"events": billing_events})]


def detect_all(facts: dict) -> list:
    """Прогоняет весь каталог (этапы 3, 4 и 5) над собранными фактами. facts:
    nodes, pods, stats_by_node, overview, rca_verdict, stuck_verdict, rca_facts,
    tls_days, gpu_node, now."""
    f = facts or {}
    out = []
    out += check_a1(f.get("nodes"), f.get("stats_by_node"), f.get("rca_verdict"),
                    f.get("gpu_node") or "")
    out += check_a2(f.get("stuck_verdict"), f.get("overview"))
    out += check_a3(f.get("nodes"), f.get("stats_by_node"))
    out += check_a4(f.get("pods"), f.get("now"))
    out += check_a5(f.get("rca_verdict"))
    out += check_a6(f.get("rca_facts"), f.get("overview"))
    out += check_a7(f.get("rca_verdict"), f.get("pods"))
    out += check_a8(f.get("pods"), f.get("rca_facts"))
    out += check_a9(f.get("overview"))
    out += check_a10(f.get("tls_days"))
    out += check_a11(f.get("rca_facts"))
    out += check_a12(f.get("rca_facts"))
    return out
