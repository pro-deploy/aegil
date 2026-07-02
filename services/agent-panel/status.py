"""Формирование статусных карточек дежурного (ADR-0038, этап 2: команды /status, /hw,
/queue, /agent). Модуль сознательно чистый: все функции принимают уже собранные данные
(списки подов и узлов, сводки kubelet, сводку конвейера) и возвращают текст карточки.
Ввод-вывод (обращения к Kubernetes, RCA и привилегированному слою api) живёт в
commands.py, поэтому формирование проверяется модульными тестами на подставных данных.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Разбор количеств Kubernetes и проценты.
# ---------------------------------------------------------------------------


def parse_cpu_cores(q) -> float:
    """Количество процессора Kubernetes в ядра: «4» это 4 ядра, «3800m» это 3.8 ядра."""
    s = str(q or "").strip()
    if not s:
        return 0.0
    try:
        if s.endswith("m"):
            return float(s[:-1]) / 1000.0
        return float(s)
    except ValueError:
        return 0.0


_MEM_UNITS = {"Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3, "Ti": 1024 ** 4,
              "K": 1000, "M": 1000 ** 2, "G": 1000 ** 3, "T": 1000 ** 4}


def parse_mem_bytes(q) -> int:
    """Количество памяти Kubernetes в байты: «16265456Ki», «8Gi», «1024»."""
    s = str(q or "").strip()
    if not s:
        return 0
    for suf in ("Ki", "Mi", "Gi", "Ti", "K", "M", "G", "T"):
        if s.endswith(suf):
            try:
                return int(float(s[: -len(suf)]) * _MEM_UNITS[suf])
            except ValueError:
                return 0
    try:
        return int(float(s))
    except ValueError:
        return 0


def pct(used, total) -> int:
    """Целый процент занятости; при неизвестном знаменателе честный ноль."""
    try:
        used = float(used or 0)
        total = float(total or 0)
    except (TypeError, ValueError):
        return 0
    if total <= 0:
        return 0
    return int(round(100.0 * used / total))


def _gib(b) -> str:
    return f"{(float(b or 0) / (1024 ** 3)):.1f}"


# ---------------------------------------------------------------------------
# Вычисления над сводкой kubelet и списками Kubernetes.
# ---------------------------------------------------------------------------


def node_usage(node_info: dict, summary) -> dict:
    """Использование узла из сводки kubelet и ёмкостей узла: проценты процессора и
    памяти, файловые системы (корневая и образов) с процентами. summary=None означает,
    что kubelet узла недоступен (сам по себе диагностический признак)."""
    out = {"name": node_info.get("name", ""), "ready": bool(node_info.get("ready")),
           "memory_pressure": bool(node_info.get("memory_pressure")),
           "disk_pressure": bool(node_info.get("disk_pressure")),
           "stats_available": summary is not None,
           "cpu_pct": None, "mem_pct": None, "fs": []}
    if summary is None:
        return out
    node = summary.get("node", {}) or {}
    cap_cores = parse_cpu_cores((node_info.get("capacity") or {}).get("cpu"))
    usage_nano = ((node.get("cpu") or {}).get("usageNanoCores")) or 0
    if cap_cores > 0:
        out["cpu_pct"] = pct(usage_nano, cap_cores * 1_000_000_000)
    mem = node.get("memory") or {}
    ws = mem.get("workingSetBytes") or mem.get("usageBytes") or 0
    avail = mem.get("availableBytes")
    total = (ws + avail) if avail is not None else parse_mem_bytes(
        (node_info.get("capacity") or {}).get("memory"))
    out["mem_pct"] = pct(ws, total)
    out["mem_used_gib"] = _gib(ws)
    out["mem_total_gib"] = _gib(total)
    for label, fs in (("корневая", node.get("fs")),
                      ("образы", (node.get("runtime") or {}).get("imageFs"))):
        if not fs:
            continue
        out["fs"].append({"label": label,
                          "pct": pct(fs.get("usedBytes"), fs.get("capacityBytes")),
                          "used_gib": _gib(fs.get("usedBytes")),
                          "total_gib": _gib(fs.get("capacityBytes"))})
    ifaces = (node.get("network") or {}).get("interfaces") or []
    out["net_errors"] = sum((i.get("rxErrors") or 0) + (i.get("txErrors") or 0)
                            for i in ifaces)
    return out


def top_pods_by_memory(summary, n: int = 5) -> list:
    """Крупнейшие потребители памяти узла по сводке kubelet: (имя пода, гибибайты)."""
    if summary is None:
        return []
    rows = []
    for p in summary.get("pods") or []:
        name = ((p.get("podRef") or {}).get("name")) or ""
        ws = ((p.get("memory") or {}).get("workingSetBytes")) or 0
        if name and ws:
            rows.append((name, ws))
    rows.sort(key=lambda x: -x[1])
    return [(name, _gib(ws)) for name, ws in rows[:n]]


def problem_pods(pods, now: datetime) -> tuple:
    """Разделяет поды на «не в Running» и «рестартовали за последний час». Возвращает
    (not_running, restarted_hour): списки словарей подов."""
    not_running, restarted = [], []
    hour_ago = now - timedelta(hours=1)
    for p in pods or []:
        if p.get("phase") not in ("Running", "Succeeded"):
            not_running.append(p)
            continue
        if p.get("waiting_reason"):
            not_running.append(p)
            continue
        ts = p.get("last_restart_at")
        if p.get("restarts") and ts:
            try:
                when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            except ValueError:
                continue
            if when >= hour_ago:
                restarted.append(p)
    return not_running, restarted


def error_share(facts: dict) -> list:
    """Доля ошибок по сервисам из фактов RCA (by_service и by_service_errors):
    список (сервис, ошибок, всего, процент), только сервисы с ошибками, по убыванию."""
    f = facts or {}
    total = f.get("by_service") or {}
    errs = f.get("by_service_errors") or {}
    rows = [(svc, n, total.get(svc, 0), pct(n, total.get(svc, 0)))
            for svc, n in errs.items() if n]
    rows.sort(key=lambda x: (-x[3], -x[1]))
    return rows


# ---------------------------------------------------------------------------
# Карточки.
# ---------------------------------------------------------------------------

_UNAVAILABLE = "недоступно (панель вне кластера)"


def _fmt_node_line(u: dict) -> str:
    flags = []
    if not u["ready"]:
        flags.append("НЕ ГОТОВ")
    if u["memory_pressure"]:
        flags.append("давление памяти")
    if u["disk_pressure"]:
        flags.append("давление диска")
    state = ", ".join(flags) if flags else "готов"
    if not u["stats_available"]:
        return f"  {u['name']}: {state}; сводка kubelet недоступна"
    cpu = f"{u['cpu_pct']}%" if u["cpu_pct"] is not None else "?"
    fs_root = next((f for f in u["fs"] if f["label"] == "корневая"), None)
    disk = f", диск {fs_root['pct']}%" if fs_root else ""
    return (f"  {u['name']}: {state}; процессор {cpu}, "
            f"память {u['mem_pct']}%{disk}")


def _fmt_age(seconds) -> str:
    s = int(seconds or 0)
    if s < 60:
        return f"{s} с"
    if s < 3600:
        return f"{s // 60} мин"
    return f"{s // 3600} ч {(s % 3600) // 60} мин"


def build_status_card(nodes, pods, stats_by_node, overview, rca_facts,
                      tls_days, gpu_node: str, now: datetime | None = None) -> str:
    """Сводная карточка /status: одна страница для мгновенной оценки состояния."""
    now = now or datetime.now(timezone.utc)
    lines = ["Сводка кластера:"]

    # Узлы: готовность, давления, проценты процессора, памяти и корневого диска.
    if nodes is None:
        lines.append(f"  узлы: {_UNAVAILABLE}")
    else:
        for n in nodes:
            lines.append(_fmt_node_line(node_usage(n, (stats_by_node or {}).get(n["name"]))))
        # Доступность GPU-узла (туннель WireGuard): узел за туннелем считается
        # доступным, когда он Ready и его kubelet отвечает на запрос сводки.
        gn = next((n for n in nodes if n["name"] == gpu_node), None)
        if gn is None:
            lines.append(f"  GPU-узел «{gpu_node}»: не найден в кластере")
        elif gn["ready"] and (stats_by_node or {}).get(gpu_node) is not None:
            lines.append(f"  GPU-узел «{gpu_node}»: доступен, туннель работает")
        else:
            lines.append(f"  GPU-узел «{gpu_node}»: НЕДОСТУПЕН (узел или туннель)")

    # Проблемные поды.
    lines.append("Поды:")
    if pods is None:
        lines.append(f"  {_UNAVAILABLE}")
    else:
        bad, restarted = problem_pods(pods, now)
        if not bad and not restarted:
            lines.append("  все поды в Running, рестартов за час нет")
        for p in bad:
            reason = p.get("waiting_reason") or p.get("phase")
            oom = ", ранее OOMKilled" if p.get("oom_killed") else ""
            lines.append(f"  ! {p['name']}: {reason}{oom}, рестартов {p.get('restarts', 0)}")
        for p in restarted:
            lines.append(f"  ~ {p['name']}: рестарт за последний час (всего {p['restarts']})")

    # Конвейер по сводке /api/admin/overview.
    lines.append("Конвейер:")
    if overview is None:
        lines.append("  сводка api недоступна (нет токена или api не отвечает)")
    else:
        q = overview.get("queue", {}) or {}
        by = q.get("by_status", {}) or {}
        depth = sum(by.values())
        lines.append(f"  в работе и ожидании {depth} заданий "
                     f"(обрабатывается {q.get('processing', 0)}, "
                     f"ожидает {by.get('queued', 0)})")
        if by.get("queued"):
            lines.append(f"  старейшее ожидающее: {_fmt_age(q.get('oldest_waiting_seconds'))}")
        d = overview.get("last_24h", {}) or {}
        lines.append(f"  за сутки: создано {d.get('created', 0)}, готово {d.get('done', 0)}, "
                     f"ошибок {d.get('errors', 0)}")
        live = overview.get("live", {}) or {}
        lines.append(f"  живой режим: {live.get('active', 0)} из {live.get('capacity', 0)} сессий "
                     f"({pct(live.get('active'), live.get('capacity'))}%)")

    # Доля ошибок в логах за 15 минут по фактам RCA.
    lines.append("Ошибки в логах за 15 минут:")
    if rca_facts is None:
        lines.append("  RCA недоступен")
    else:
        rows = error_share(rca_facts)
        if not rows:
            lines.append("  ошибок нет")
        for svc, n, total, share in rows[:6]:
            lines.append(f"  {svc}: {n} из {total} строк ({share}%)")

    # Срок TLS-сертификата (проверка раз в сутки, значение из кэша).
    if tls_days is not None:
        mark = "!" if tls_days <= 14 else "ok"
        lines.append(f"Сертификат TLS krokki.ru: осталось {tls_days} дн. [{mark}]")
    else:
        lines.append("Сертификат TLS krokki.ru: проверка недоступна")
    return "\n".join(lines)


def build_hw_card(nodes, stats_by_node) -> str:
    """Подробная карточка /hw: железо по узлам и файловым системам."""
    if nodes is None:
        return f"Железо: {_UNAVAILABLE}."
    lines = ["Железо по узлам:"]
    for n in nodes:
        summary = (stats_by_node or {}).get(n["name"])
        u = node_usage(n, summary)
        cap = n.get("capacity") or {}
        alloc = n.get("allocatable") or {}
        lines.append(f"{n['name']} ({'готов' if u['ready'] else 'НЕ ГОТОВ'}):")
        lines.append(f"  процессор: {cap.get('cpu', '?')} ядер (выделяемо {alloc.get('cpu', '?')}), "
                     + (f"загрузка {u['cpu_pct']}%" if u["cpu_pct"] is not None else "загрузка неизвестна"))
        if u["stats_available"]:
            lines.append(f"  память: занято {u['mem_used_gib']} ГиБ из {u['mem_total_gib']} ГиБ "
                         f"({u['mem_pct']}%)")
            for fs in u["fs"]:
                lines.append(f"  диск ({fs['label']}): {fs['used_gib']} из {fs['total_gib']} ГиБ "
                             f"({fs['pct']}%)")
            if u.get("net_errors"):
                lines.append(f"  сетевые ошибки интерфейсов: {u['net_errors']}")
            top = top_pods_by_memory(summary)
            if top:
                lines.append("  крупнейшие по памяти поды: "
                             + ", ".join(f"{name} ({gib} ГиБ)" for name, gib in top))
        else:
            lines.append("  сводка kubelet недоступна (узел или туннель)")
    return "\n".join(lines)


def build_queue_card(overview) -> str:
    """Карточка /queue: очередь по стадиям, темп за час и прогноз разгребания."""
    if overview is None:
        return "Очередь: сводка api недоступна (нет токена или api не отвечает)."
    q = overview.get("queue", {}) or {}
    by = q.get("by_status", {}) or {}
    lines = ["Конвейер обработки:"]
    if not by:
        lines.append("  очередь пуста, все задания в терминальных статусах")
    for st in sorted(by, key=lambda s: -by[s]):
        lines.append(f"  {st}: {by[st]}")
    if by.get("queued"):
        lines.append(f"  старейшее ожидающее: {_fmt_age(q.get('oldest_waiting_seconds'))}")
    done_hour = (overview.get("last_hour", {}) or {}).get("done", 0)
    lines.append(f"Темп: за последний час готово {done_hour} заданий.")
    waiting = by.get("queued", 0) + by.get("uploaded", 0)
    if waiting and done_hour:
        eta_min = int(round(60.0 * waiting / done_hour))
        lines.append(f"Прогноз: при текущем темпе очередь из {waiting} ожидающих "
                     f"разгребётся примерно за {_fmt_age(eta_min * 60)}.")
    elif waiting:
        lines.append(f"Прогноз: ожидает {waiting}, но за час не завершилось ни одного "
                     f"задания; при простое воркера очередь не разгребается.")
    d = overview.get("last_24h", {}) or {}
    lines.append(f"За сутки: создано {d.get('created', 0)}, готово {d.get('done', 0)}, "
                 f"ошибок {d.get('errors', 0)}.")
    return "\n".join(lines)


def build_agent_card(state: dict) -> str:
    """Карточка /agent (ADR-0038, этап 3): режим, остаток бюджета действий на час,
    активные кулдауны, последние 10 действий с исходами и положение предохранителя.
    Чистая функция: состояние собирает autopilot.agent_state()."""
    s = state or {}
    if not s.get("autonomous"):
        mode = "сухой прогон (AGENT_AUTONOMOUS=0): агент записывает, что бы сделал"
    elif s.get("paused"):
        mode = "пауза (/agent pause): действия остановлены, наблюдение работает"
    else:
        mode = "автономный: действия уровня A исполняются"
    lines = [
        "Автономный агент:",
        f"  режим: {mode}",
        f"  такт наблюдения: {s.get('tick_seconds')} с, проверка результата через "
        f"{s.get('verify_delay')} с",
        f"  бюджет действий: осталось {s.get('budget_left')} из {s.get('budget_total')} в час",
    ]
    if s.get("breaker_active"):
        lines.append(f"  предохранитель: СРАБОТАЛ, только наблюдение ещё "
                     f"{s.get('breaker_left_min')} мин")
    else:
        lines.append(f"  предохранитель: в норме "
                     f"(подряд неудач {s.get('consecutive_failures', 0)})")
    cds = s.get("cooldowns") or []
    lines.append("  активные кулдауны: " + ("нет" if not cds else ""))
    for c in cds:
        lines.append(f"    {c}")
    if s.get("blocked_pairs"):
        lines.append(f"  заблокированные пары осцилляции: {len(s['blocked_pairs'])}")
    if s.get("pending_verify"):
        lines.append(f"  ожидают проверки результата: {s['pending_verify']}")
    acts = s.get("last_actions") or []
    lines.append("Последние действия:" if acts else "Последние действия: пока не было.")
    for a in acts:
        when = datetime.fromtimestamp(a.get("ts") or 0, tz=timezone.utc).strftime("%m-%d %H:%M")
        svc = f" ({a['service']})" if a.get("service") else ""
        lines.append(f"  {when} {a.get('action')}{svc}: {a.get('outcome')}")
    lines.append("Управление: /agent pause приостанавливает действия, /agent resume "
                 "возобновляет. Наблюдение и эскалации работают всегда.")
    return "\n".join(lines)


def build_report_card(groups, guard_state, now: datetime | None = None,
                      window_hours: int = 24) -> str:
    """Карточка отчёта агента за сутки (ADR-0038, этап 5, команда /report). Чистая
    функция: сводит по группам инцидентов за окно (жизненный цикл) и по журналу действий
    гардов (виды действий, исходы, положение предохранителя и бюджета). groups это
    incidents.list_groups(), guard_state это guards.state_summary(). Формат компактной
    русской карточкой.

    За окно берётся группа, у которой последнее появление (last_seen) попало в последние
    window_hours; повторно открытые группы (reopened_from) считаются отдельно как признак
    хронических проблем."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=window_hours)

    def _in_window(g: dict) -> bool:
        ts = g.get("last_seen") or ""
        try:
            when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            return False
        return when >= cutoff

    recent = [g for g in (groups or []) if _in_window(g)]
    total = len(recent)
    resolved_auto = sum(1 for g in recent if g.get("lifecycle") == "resolved_auto")
    resolved_op = sum(1 for g in recent if g.get("lifecycle") == "resolved_operator")
    escalated = sum(1 for g in recent if g.get("lifecycle") == "escalated")
    acknowledged = sum(1 for g in recent if g.get("lifecycle") == "acknowledged")
    reopened = sum(1 for g in recent if g.get("reopened_from"))

    # Топ повторяющихся отпечатков за окно: по счётчику повторов внутри группы.
    top = sorted(recent, key=lambda g: -(g.get("count") or 0))[:3]

    # Действия по видам и исходам из журнала гардов (последние действия карточки /agent).
    by_action: dict = {}
    for a in (guard_state or {}).get("last_actions") or []:
        act = a.get("action") or "?"
        by_action.setdefault(act, {"успех": 0, "неудача": 0, "выполняется": 0})
        oc = a.get("outcome") or "выполняется"
        by_action[act][oc] = by_action[act].get(oc, 0) + 1

    lines = [f"Отчёт агента за {window_hours} ч:"]
    lines.append(f"  инцидентов за окно: {total}")
    lines.append(f"  решил сам (resolved_auto): {resolved_auto}")
    lines.append(f"  решил оператор: {resolved_op}, в работе: {acknowledged}")
    lines.append(f"  эскалировал: {escalated}")
    if reopened:
        lines.append(f"  переоткрытий (хронические): {reopened}")
    if top:
        lines.append("  топ повторяющихся:")
        for g in top:
            title = (g.get("title") or "без причины")[:50]
            lines.append(f"    x{g.get('count', 0)} [{g.get('id')}] {title}")
    else:
        lines.append("  повторяющихся инцидентов нет")
    if by_action:
        lines.append("  действия по видам (из журнала):")
        for act in sorted(by_action):
            c = by_action[act]
            lines.append(f"    {act}: успех {c['успех']}, неудача {c['неудача']}")
    else:
        lines.append("  автономных действий в журнале нет")

    gs = guard_state or {}
    if gs.get("breaker_active"):
        lines.append(f"  предохранитель: СРАБОТАЛ, ещё {gs.get('breaker_left_min', 0)} мин")
    else:
        lines.append(f"  предохранитель: в норме "
                     f"(подряд неудач {gs.get('consecutive_failures', 0)})")
    lines.append(f"  бюджет действий: осталось {gs.get('budget_left', 0)} из "
                 f"{gs.get('budget_total', 0)} в час")
    return "\n".join(lines)
