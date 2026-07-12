"""Домен-нейтральные статусные сводки кластера для дежурного оператора aegil.

Модуль сознательно чист: все функции принимают уже собранные данные (списки подов, узлов,
деплойментов, событий, сводки kubelet, срок сертификата TLS, состояние агента) и возвращают текст
карточки. Ввод-вывод (обращения к Kubernetes, RCA и прикладному адаптеру) собирает вызывающая
сторона, поэтому формирование карточек проверяется модульными тестами на подставных данных.

Сводки описывают состояние произвольного кластера Kubernetes нейтрально: поды по фазам, узлы с
ресурсами, деплойменты со статусом реплик, свежие предупреждающие события. Здесь нет ни имён
приложения владельца, ни зашитых имён узлов и сервисов, ни привязки к какому-либо конкретному
конвейеру обработки.
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
    """Использование узла из сводки kubelet и ёмкостей узла: проценты процессора и памяти, файловые
    системы с процентами. summary=None означает, что kubelet узла недоступен (сам по себе
    диагностический признак)."""
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


def pods_by_phase(pods) -> dict:
    """Счётчики подов по фазам Kubernetes (Running, Pending, Succeeded, Failed и прочее). Возвращает
    словарь фаза: число."""
    counts: dict = {}
    for p in pods or []:
        phase = p.get("phase") or "Unknown"
        counts[phase] = counts.get(phase, 0) + 1
    return counts


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


# ---------------------------------------------------------------------------
# Карточки.
# ---------------------------------------------------------------------------

_UNAVAILABLE = "недоступно (нет доступа к API Kubernetes)"


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


def build_status_card(nodes, pods, stats_by_node, deployments, events,
                      tls_days, now: datetime | None = None) -> str:
    """Сводная карточка состояния кластера: одна страница для мгновенной оценки. Домен-нейтральна:
    узлы с ресурсами, поды по фазам и проблемные поды, деплойменты со статусом реплик, свежие
    предупреждающие события, срок сертификата TLS (если задан хост наблюдения)."""
    now = now or datetime.now(timezone.utc)
    lines = ["Сводка кластера:"]

    # Узлы: готовность, давления, проценты процессора, памяти и корневого диска.
    lines.append("Узлы:")
    if nodes is None:
        lines.append(f"  {_UNAVAILABLE}")
    elif not nodes:
        lines.append("  узлов не видно")
    else:
        for n in nodes:
            lines.append(_fmt_node_line(node_usage(n, (stats_by_node or {}).get(n["name"]))))

    # Поды: разбивка по фазам и проблемные поды.
    lines.append("Поды:")
    if pods is None:
        lines.append(f"  {_UNAVAILABLE}")
    else:
        counts = pods_by_phase(pods)
        if counts:
            summary = ", ".join(f"{phase} {counts[phase]}" for phase in sorted(counts))
            lines.append(f"  по фазам: {summary}")
        bad, restarted = problem_pods(pods, now)
        if not bad and not restarted:
            lines.append("  проблемных подов нет, рестартов за час нет")
        for p in bad:
            reason = p.get("waiting_reason") or p.get("phase")
            oom = ", ранее OOMKilled" if p.get("oom_killed") else ""
            lines.append(f"  ! {p['name']}: {reason}{oom}, рестартов {p.get('restarts', 0)}")
        for p in restarted:
            lines.append(f"  ~ {p['name']}: рестарт за последний час (всего {p['restarts']})")

    # Деплойменты: недоступные реплики.
    lines.append("Деплойменты:")
    if deployments is None:
        lines.append(f"  {_UNAVAILABLE}")
    else:
        degraded = [d for d in deployments if (d.get("desired") or 0) > (d.get("ready") or 0)]
        if not degraded:
            lines.append("  все деплойменты в полном составе реплик")
        for d in degraded:
            lines.append(f"  ! {d.get('name')}: готово {d.get('ready', 0)} из {d.get('desired', 0)}")

    # Свежие предупреждающие события кластера.
    lines.append("Предупреждающие события:")
    if events is None:
        lines.append(f"  {_UNAVAILABLE}")
    else:
        warns = [e for e in events if e.get("type") == "Warning"]
        if not warns:
            lines.append("  предупреждающих событий нет")
        for e in warns[:6]:
            obj = e.get("object") or ""
            lines.append(f"  {e.get('reason')} [{obj}] x{e.get('count', 1)}: {e.get('message', '')}")

    # Срок TLS-сертификата (проверка раз в сутки, значение из кэша app_adapter). Показывается только
    # когда задан хост наблюдения AEGIL_TLS_HOST, иначе строки нет.
    if tls_days is not None:
        mark = "!" if tls_days <= 14 else "ok"
        lines.append(f"Сертификат TLS: осталось {tls_days} сут [{mark}]")
    return "\n".join(lines)


def build_hw_card(nodes, stats_by_node) -> str:
    """Подробная карточка железа: узлы, ресурсы и файловые системы. Домен-нейтральна."""
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
            lines.append("  сводка kubelet недоступна")
    return "\n".join(lines)


def build_agent_card(state: dict) -> str:
    """Карточка состояния автономного агента: уровень автономии, остаток бюджета действий на час,
    активные кулдауны, положение предохранителя и последние действия. Чистая функция: состояние
    собирает autopilot.agent_state()."""
    s = state or {}
    autonomy = s.get("autonomy") or "observe"
    mode = {
        "observe": "наблюдение (observe): агент диагностирует и предлагает, но не действует",
        "safe_repair": "безопасный ремонт (safe_repair): агент автономно чинит обратимым, опасное на "
                       "подтверждение",
        "full": "полная автономия (full): агент чинит всё, кроме необратимого и защищённого",
    }.get(autonomy, autonomy)
    if s.get("blind"):
        mode += "; ИСТОЧНИКИ НАБЛЮДЕНИЯ НЕДОСТУПНЫ (агент не видит состояние кластера)"
    lines = [
        "Автономный агент:",
        f"  уровень автономии: {mode}",
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
    lines.append("Управление: уровень автономии выбирает владелец из интерфейса. Наблюдение и "
                 "эскалации работают всегда.")
    return "\n".join(lines)


def build_report_card(groups, guard_state, now: datetime | None = None,
                      window_hours: int = 24) -> str:
    """Карточка отчёта агента за окно (по умолчанию сутки). Чистая функция: сводит по группам
    инцидентов за окно (жизненный цикл) и по журналу действий гардов (виды действий, исходы,
    положение предохранителя и бюджета). groups это incidents.list_groups(), guard_state это
    guards.state_summary(). Домен-нейтральна.

    За окно берётся группа, у которой последнее появление (last_seen) попало в последние
    window_hours; повторно открытые группы (reopened_from) считаются отдельно как признак хронических
    проблем."""
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

    top = sorted(recent, key=lambda g: -(g.get("count") or 0))[:3]

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
