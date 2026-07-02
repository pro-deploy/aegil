import os
os.environ.setdefault("RESTART_ALLOWLIST","web,asr,diarize,llm,translate,tts,embed,rca,worker,api")
"""Модульные тесты автономного агента (ADR-0038, этап 3). Без сети и без pytest.
Запуск: python3 services/adminchat/test_autopilot.py
Покрыто: каждый алерт каталога на синтетических данных, сухой прогон без действий,
исполнение с проверкой результата (resolved_auto), неудачи с эскалацией, гарды после
выбора действия и карточка /agent.
"""
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import alerts
import autopilot
import guards
import incidents
import status as status_cards


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def _fresh():
    tmp = Path(tempfile.mkdtemp())
    incidents.STORE_PATH = tmp / "incidents.log.jsonl"
    incidents.STORE_DIR = tmp
    incidents._groups.clear()
    incidents._active.clear()
    guards.STATE_PATH = tmp / "agent-guards.log.jsonl"
    guards.load()
    autopilot._pending_verify.clear()
    autopilot._dry_noted.clear()
    autopilot._escalated_noted.clear()
    autopilot.AUTONOMOUS = False
    autopilot._paused = False
    # Эскалация теперь запускает агентное расследование (ADR-0041). По умолчанию мокаем его
    # заглушкой без сети и без модели: возврат None означает, что трейс не приложен, но путь
    # инцидента отрабатывает штатно. Тесты, проверяющие сам разбор, ставят свою заглушку.
    autopilot._run_investigation = lambda gid, alert: None
    return tmp


NOW_DT = datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc)
T0 = 1_000_000.0

# Здоровые факты: алертов нет.
HEALTHY = {"nodes": None, "pods": None, "stats_by_node": {}, "overview": None,
           "rca_verdict": None, "stuck_verdict": None, "gpu_node": "gooseek",
           "now": NOW_DT}


def _facts(**kw):
    f = dict(HEALTHY)
    f.update(kw)
    return f


FACTS_A2 = _facts(stuck_verdict={"status": "incident", "detectors": ["stuck:transcribing"],
                                 "root_cause": "задание стоит на стадии transcribing"})


# ---------------------------------------------------------------------------
# Каталог алертов на синтетических данных.
# ---------------------------------------------------------------------------


def test_alert_a1():
    # Узел не Ready.
    out = alerts.check_a1([{"name": "gooseek", "ready": False}], {}, None, "gooseek")
    _eq("A1 узел не Ready", [a["code"] for a in out], ["A1"])
    _eq("A1 критический", out[0]["severity"], "critical")
    # Узел Ready, но kubelet молчит.
    out = alerts.check_a1([{"name": "gooseek", "ready": True}], {"gooseek": None},
                          None, "gooseek")
    _eq("A1 kubelet молчит", len(out), 1)
    # RCA видит connection_refused к ML.
    v = {"root_cause": "connection_refused у цели asr на порту 9101", "evidence": []}
    out = alerts.check_a1(None, {}, v, "gooseek")
    _eq("A1 по вердикту RCA", len(out), 1)
    # Здоровый узел с живым kubelet алерта не даёт.
    out = alerts.check_a1([{"name": "gooseek", "ready": True}],
                          {"gooseek": {"node": {}}}, None, "gooseek")
    _eq("A1 здоров", out, [])
    print("A1: ok")


def test_alert_a2():
    out = alerts.check_a2(FACTS_A2["stuck_verdict"], None)
    _eq("A2 по /stuck", [a["code"] for a in out], ["A2"])
    # Возраст старейшего ожидающего больше порога.
    ov = {"queue": {"by_status": {"queued": 3},
                    "oldest_waiting_seconds": alerts.STUCK_AGE_SECONDS + 60}}
    out = alerts.check_a2({"status": "healthy"}, ov)
    _eq("A2 по возрасту очереди", len(out), 1)
    ov["queue"]["oldest_waiting_seconds"] = 30
    _eq("A2 здоров", alerts.check_a2({"status": "healthy"}, ov), [])
    print("A2: ok")


def test_alert_a3():
    node = {"name": "control", "ready": True, "capacity": {"cpu": "4", "memory": "8Gi"}}
    summary = {"node": {"fs": {"usedBytes": 85, "capacityBytes": 100}}}
    out = alerts.check_a3([node], {"control": summary})
    _eq("A3 предупреждение при 85%", [a["severity"] for a in out], ["warning"])
    summary["node"]["fs"]["usedBytes"] = 95
    out = alerts.check_a3([node], {"control": summary})
    _eq("A3 критично при 95%", [a["severity"] for a in out], ["critical"])
    summary["node"]["fs"]["usedBytes"] = 50
    _eq("A3 здоров", alerts.check_a3([node], {"control": summary}), [])
    print("A3: ok")


def test_alert_a4():
    pods = [
        {"name": "asr-6b9f7-x2x1c", "phase": "Running",
         "waiting_reason": "CrashLoopBackOff", "restarts": 5, "oom_killed": False,
         "last_restart_at": "2026-07-02T11:50:00Z"},
        {"name": "web-5c4d8-aaaa1", "phase": "Running", "waiting_reason": None,
         "restarts": 9, "oom_killed": True, "last_restart_at": None},
        {"name": "api-7abcd-bbbb2", "phase": "Running", "waiting_reason": None,
         "restarts": 4, "oom_killed": False,
         "last_restart_at": "2026-07-02T11:30:00Z"},
        {"name": "rca-1a2b3-cccc3", "phase": "Running", "waiting_reason": None,
         "restarts": 1, "oom_killed": False, "last_restart_at": None},
    ]
    out = alerts.check_a4(pods, NOW_DT)
    got = {a["params"]["service"]: a["params"]["reason"] for a in out}
    _eq("A4 CrashLoopBackOff", got["asr"], "CrashLoopBackOff")
    _eq("A4 OOMKilled", got["web"], "OOMKilled")
    assert "рестартов" in got["api"], got
    assert "rca" not in got, "здоровый под попал в A4"
    # Сервис конвейера серьёзнее прочих.
    sev = {a["params"]["service"]: a["severity"] for a in out}
    _eq("A4 конвейер high", sev["asr"], "high")
    _eq("A4 остальные warning", sev["web"], "warning")
    print("A4: ok")


def test_alert_a5():
    v = {"detectors": ["D10"], "root_cause": "всплеск ошибок из-за сервиса web",
         "evidence": []}
    out = alerts.check_a5(v)
    _eq("A5 сработал", len(out), 1)
    _eq("A5 виновник из allowlist", out[0]["params"]["culprit"], "web")
    _eq("A5 без D10 молчит", alerts.check_a5({"detectors": ["D5"]}), [])
    print("A5: ok")


def test_alert_a7():
    v = {"detectors": ["D5"], "root_cause": "connection_refused к postgres:5432",
         "evidence": []}
    pods = [{"name": "postgres-0", "phase": "Pending"}]
    out = alerts.check_a7(v, pods)
    _eq("A7 сработал", len(out), 1)
    _eq("A7 хранилище", out[0]["params"]["store"], "postgres")
    _eq("A7 фаза пода приложена", out[0]["params"]["pod_phase"], "Pending")
    _eq("A7 без сигнала молчит", alerts.check_a7({"root_cause": "нет ошибок"}, pods), [])
    print("A7: ok")


# ---------------------------------------------------------------------------
# Плейбуки и выбор действия.
# ---------------------------------------------------------------------------


def test_playbooks():
    # A2: сначала requeue, затем перезапуск воркера (worker в allowlist).
    a2 = alerts.check_a2(FACTS_A2["stuck_verdict"], None)[0]
    opts = autopilot.playbook_options(a2)
    _eq("A2 план", [o["action"] for o in opts], ["requeue", "restart"])
    _eq("A2 второй шаг воркер", opts[1]["service"], "worker")
    # A4: удаление пода только для allowlist; vllm (denylist) идёт в эскалацию.
    a4 = alerts.check_a4([{"name": "asr-1-2", "waiting_reason": "CrashLoopBackOff",
                           "restarts": 5, "oom_killed": False,
                           "last_restart_at": None}], NOW_DT)[0]
    opts = autopilot.playbook_options(a4)
    _eq("A4 удаление пода", opts[0]["action"], "delete_pod")
    a4v = alerts.check_a4([{"name": "vllm-1-2", "waiting_reason": "CrashLoopBackOff",
                            "restarts": 5, "oom_killed": False,
                            "last_restart_at": None}], NOW_DT)[0]
    _eq("A4 denylist без автодействий", autopilot.playbook_options(a4v), [])
    # A5: перезапуск виновника; без виновника пусто.
    a5 = alerts.check_a5({"detectors": ["D10"],
                          "root_cause": "виноват сервис web", "evidence": []})[0]
    _eq("A5 перезапуск виновника",
        autopilot.playbook_options(a5), [{"action": "restart", "service": "web"}])
    # A1, A3, A7: только эскалация.
    for facts_alert in (alerts.check_a1([{"name": "g", "ready": False}], {}, None, "g")[0],
                        alerts.check_a7({"root_cause": "dns_error redis"}, [])[0]):
        _eq(f"{facts_alert['code']} без автодействий",
            autopilot.playbook_options(facts_alert), [])
    # Выбор модели строго из множества: мусорный ответ ведёт к фолбэку.
    bad_llm = lambda p: '{"choice": 99}'
    d = autopilot.choose_action(a2, 0, bad_llm)
    _eq("невалидный выбор модели отбит", d["action"], "requeue")
    d = autopilot.choose_action(a2, 1, lambda p: '{"choice": 1}')
    _eq("валидный выбор модели принят", d, {"action": "restart", "service": "worker"})
    _eq("исчерпанный план", autopilot.choose_action(a2, 2, None), None)
    print("плейбуки и выбор: ok")


# ---------------------------------------------------------------------------
# Такт агента: сухой прогон, исполнение, проверка, эскалация.
# ---------------------------------------------------------------------------


def test_dry_run_no_actions():
    _fresh()  # AGENT_AUTONOMOUS по умолчанию выключен
    calls = []
    orig = autopilot._execute_action
    autopilot._execute_action = lambda d, u: calls.append(d) or (True, "ok")
    try:
        out = autopilot.tick("http://rca", now=T0, facts=FACTS_A2)
    finally:
        autopilot._execute_action = orig
    _eq("сухой прогон не действует", calls, [])
    dec = [d for d in out if d["code"] == "A2"]
    _eq("решение записано", dec[0]["decision"], "dry_run")
    g = incidents.get_group(dec[0]["gid"])
    _eq("группа осталась new", g["lifecycle"], "new")
    notes = g.get("notes") or []
    assert notes and "сухой прогон" in notes[0]["text"], notes
    assert "Выполнил бы" in notes[0]["text"], notes
    # Повторный такт не спамит ленту повторной записью.
    autopilot.tick("http://rca", now=T0 + 30, facts=FACTS_A2)
    _eq("запись одна", len(g.get("notes") or []), 1)
    print("сухой прогон: ok")


def test_autonomous_resolved_auto():
    _fresh()
    autopilot.AUTONOMOUS = True
    calls = []
    orig = autopilot._execute_action
    autopilot._execute_action = lambda d, u: calls.append(d) or (True, "сделано")
    try:
        out = autopilot.tick("http://rca", now=T0, facts=FACTS_A2)
        dec = [d for d in out if d["code"] == "A2"][0]
        _eq("действие исполнено", dec["decision"], "executed")
        _eq("выбран requeue", calls[0]["action"], "requeue")
        g = incidents.get_group(dec["gid"])
        _eq("группа auto_fixing", g["lifecycle"], "auto_fixing")
        # До VERIFY_DELAY проверка не выполняется и действие не повторяется.
        autopilot.tick("http://rca", now=T0 + 60, facts=FACTS_A2)
        _eq("действие не повторено до проверки", len(calls), 1)
        # После VERIFY_DELAY алерт исчез: решено агентом с указанием действия.
        autopilot.tick("http://rca", now=T0 + autopilot.VERIFY_DELAY + 1, facts=HEALTHY)
        _eq("решено агентом", g["lifecycle"], "resolved_auto")
        _eq("актор агент", g["resolved_by"], "agent")
        _eq("действие зафиксировано", g["resolved_action"], "requeue")
    finally:
        autopilot._execute_action = orig
    print("resolved_auto после проверки: ok")


def test_failures_escalate():
    _fresh()
    autopilot.AUTONOMOUS = True
    calls = []
    orig = autopilot._execute_action
    autopilot._execute_action = lambda d, u: calls.append(d) or (True, "сделано")
    try:
        # Попытка 1: requeue. Проверка: алерт держится, неудача плюс кулдаун отпечатка.
        out = autopilot.tick("http://rca", now=T0, facts=FACTS_A2)
        gid = [d for d in out if d["code"] == "A2"][0]["gid"]
        t1 = T0 + autopilot.VERIFY_DELAY + 1
        autopilot.tick("http://rca", now=t1, facts=FACTS_A2)
        g = incidents.get_group(gid)
        _eq("после неудачи группа снова в работе", g["lifecycle"], "new")
        # Пока кулдаун отпечатка не истёк, действие отложено гардом.
        out = autopilot.tick("http://rca", now=t1 + 60, facts=FACTS_A2)
        _eq("гард отложил", [d for d in out if d["code"] == "A2"][0]["decision"], "blocked")
        _eq("действий по-прежнему одно", len(calls), 1)
        # Попытка 2 после кулдауна: перезапуск воркера.
        t2 = t1 + guards.FP_COOLDOWN_SECONDS + 10
        out = autopilot.tick("http://rca", now=t2, facts=FACTS_A2)
        _eq("вторая попытка", [d for d in out if d["code"] == "A2"][0]["decision"], "executed")
        _eq("второй шаг плейбука", calls[1], {"action": "restart", "service": "worker"})
        # Проверка снова неудачна: попытки исчерпаны, эскалация с историей.
        autopilot.tick("http://rca", now=t2 + autopilot.VERIFY_DELAY + 1, facts=FACTS_A2)
        _eq("эскалировано", g["lifecycle"], "escalated")
        assert any("Эскалация" in n["text"] for n in g.get("notes") or []), g.get("notes")
        _eq("больше действий нет", len(calls), 2)
    finally:
        autopilot._execute_action = orig
    print("эскалация после исчерпания попыток: ok")


def test_escalate_only_alerts():
    _fresh()
    facts = _facts(rca_verdict={"detectors": ["D5"], "evidence": [],
                                "root_cause": "connection_refused к postgres:5432",
                                "status": "incident", "band": "high"},
                   pods=[{"name": "postgres-0", "phase": "Pending"}])
    # Эскалация теперь запускает агентное расследование (ADR-0041), поэтому мокаем его, чтобы
    # тест не выходил в сеть и не звал модель. Проверяем, что путь инцидента больше не пишет
    # отписку «проверьте вручную», а фиксирует запуск расследования с собранными фактами.
    orig_inv = autopilot._run_investigation
    autopilot._run_investigation = lambda gid, alert: {
        "steps": [{"step": "observe", "argv": ["kubectl", "logs", "postgres-0"],
                   "class": "read", "result": {"data": "log tail"}},
                  {"step": "explain", "text": "postgres не принимает соединения, под Pending"},
                  {"step": "act", "argv": ["kubectl", "rollout", "restart",
                                           "deployment/postgres"], "class": "safe_write",
                   "outcome": "pending_confirm", "confirm_token": "tok"},
                  {"step": "done", "summary": "postgres недоступен, нужен рестарт деплоймента"}],
        "instruction": "расследуй инцидент postgres", "mode": "auto", "model": True}
    try:
        out = autopilot.tick("http://rca", now=T0, facts=facts)
    finally:
        autopilot._run_investigation = orig_inv
    dec = [d for d in out if d["code"] == "A7"][0]
    _eq("A7 сразу эскалация", dec["decision"], "escalate")
    g = incidents.get_group(dec["gid"])
    _eq("A7 escalated", g["lifecycle"], "escalated")
    notes = [n.get("text", "") for n in (g.get("notes") or [])]
    joined = " ".join(notes)
    # Путь инцидента больше НЕ содержит отписок ручного анализа.
    for banned in ("проверьте вручную", "продлите вручную", "перезапустите вручную",
                   "требует ручного анализа", "требуется внимание оператора", "разберите вручную"):
        assert banned not in joined, f"осталась отписка «{banned}»: {joined}"
    # Зафиксирован запуск агентного расследования с собранными фактами и предложением на
    # подтверждение (а не общее «разбирайтесь сами»).
    assert any("Расследование агента" in n for n in notes), notes
    assert any("Диагноз агента" in n for n in notes), notes
    assert any("на подтверждение" in n for n in notes), notes
    print("эскалация A7 запускает агентное расследование: ok")


def test_level_b_through_guards():
    # Уровень B (A3 критический): агент чистит временные файлы и ставит паузу приёма,
    # СРАЗУ уведомляя оператора; действия проходят через те же гарды (бюджет учитывается).
    _fresh()
    autopilot.AUTONOMOUS = True
    node = {"name": "control", "ready": True, "capacity": {"cpu": "4", "memory": "8Gi"}}
    summary = {"node": {"fs": {"usedBytes": 95, "capacityBytes": 100}}}
    facts = _facts(nodes=[node], stats_by_node={"control": summary})
    calls = []
    orig = autopilot._execute_action
    autopilot._execute_action = lambda d, u: calls.append(d) or (True, "сделано")
    try:
        out = autopilot.tick("http://rca", now=T0, facts=facts)
        dec = [d for d in out if d["code"] == "A3"][0]
        _eq("A3 уровень B исполнен", dec["decision"], "executed")
        _eq("первое действие очистка", calls[0]["action"], "cleanup_temp")
        g = incidents.get_group(dec["gid"])
        # Немедленное уведомление оператора об автономном действии уровня B в ленте.
        assert any("уровень B" in n["text"] and "самостоятельно" in n["text"]
                   for n in g.get("notes") or []), g.get("notes")
    finally:
        autopilot._execute_action = orig
    # Бюджет действий уменьшился (гарды учли попытку уровня B наравне с уровнем A).
    st = guards.state_summary(now=T0)
    assert st["budget_left"] < st["budget_total"], st
    print("уровень B через гарды с уведомлением: ok")


def test_a3_playbook_levels():
    # Предупреждение (не критично): только очистка. Критично: очистка плюс пауза приёма.
    a3_warn = alerts.check_a3(
        [{"name": "control", "ready": True, "capacity": {"cpu": "4", "memory": "8Gi"}}],
        {"control": {"node": {"fs": {"usedBytes": 85, "capacityBytes": 100}}}})[0]
    _eq("A3 warn один шаг очистки",
        [o["action"] for o in autopilot.playbook_options(a3_warn)], ["cleanup_temp"])
    a3_crit = alerts.check_a3(
        [{"name": "control", "ready": True, "capacity": {"cpu": "4", "memory": "8Gi"}}],
        {"control": {"node": {"fs": {"usedBytes": 95, "capacityBytes": 100}}}})[0]
    _eq("A3 crit очистка и пауза",
        [o["action"] for o in autopilot.playbook_options(a3_crit)],
        ["cleanup_temp", "intake_pause"])
    print("A3 плейбук уровней: ok")


def test_a6_playbook():
    # Латентность с ростом параллелизма: снижение параллелизма (уровень B).
    a6_load = alerts.check_a6({"latency_by_target": {"asr": {"p95_ms": 20000}}},
                              {"queue": {"processing": 5}})[0]
    _eq("A6 при нагрузке снижение параллелизма",
        autopilot.playbook_options(a6_load), [{"action": "lower_concurrency"}])
    # Латентность без роста нагрузки: разовый перезапуск asr (уровень A).
    a6_idle = alerts.check_a6({"latency_by_target": {"asr": {"p95_ms": 20000}}},
                              {"queue": {"processing": 0}})[0]
    _eq("A6 без нагрузки перезапуск asr",
        autopilot.playbook_options(a6_idle), [{"action": "restart", "service": "asr"}])
    print("A6 плейбук: ok")


def test_a8_playbook_and_escalation():
    # Сервис в allowlist молчит: разовый перезапуск (уровень A).
    a8 = alerts.check_a8([{"name": "worker-1-2", "phase": "Running", "waiting_reason": None}],
                         {"by_service": {"worker": 0, "api": 50}})[0]
    _eq("A8 перезапуск молчащего worker",
        autopilot.playbook_options(a8), [{"action": "restart", "service": "worker"}])
    print("A8 плейбук: ok")


def test_agent_card():
    _fresh()
    card = status_cards.build_agent_card(autopilot.agent_state(now=T0))
    assert "сухой прогон" in card, card
    assert "бюджет" in card.lower(), card
    assert "/agent pause" in card, card
    autopilot.pause()
    _eq("пауза действует", autopilot._paused, True)
    autopilot.AUTONOMOUS = True
    card = status_cards.build_agent_card(autopilot.agent_state(now=T0))
    assert "пауза" in card, card
    autopilot.resume()
    _eq("возобновлено", autopilot._paused, False)
    print("карточка /agent: ok")


if __name__ == "__main__":
    test_alert_a1()
    test_alert_a2()
    test_alert_a3()
    test_alert_a4()
    test_alert_a5()
    test_alert_a7()
    test_playbooks()
    test_dry_run_no_actions()
    test_autonomous_resolved_auto()
    test_failures_escalate()
    test_escalate_only_alerts()
    test_level_b_through_guards()
    test_a3_playbook_levels()
    test_a6_playbook()
    test_a8_playbook_and_escalation()
    test_agent_card()
    print("autopilot: all tests passed")
