"""Модульные тесты автономного цикла SRE-агента (autopilot.py). Проверяют правильность поведения без
выхода в сеть: ремонт поручается агентному расследованию, гейт опасности не дублируется, различаются
уровни автономии. Обязательные негативные проверки: слепота источников наблюдения не закрывает
инциденты как решённые; исключение при исполнении действия не замораживает группу в состоянии ремонта;
на уровне observe никаких мутаций не исполняется. Собирается стандартным сборщиком pytest.
"""
import os

os.environ.setdefault("SENTINEL_RESTART_ALLOWLIST", "web,api,worker")

import tempfile
from datetime import datetime, timezone
from pathlib import Path

import agent_exec
import alerts
import autopilot
import config
import guards
import incidents


NOW_DT = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)
T0 = 1_000_000.0

# Настоящая обёртка расследования (до подмены заглушкой в _fresh). Нужна тесту устойчивости к
# исключению: он проверяет, что реальный _run_investigation поглощает исключение agent_exec.
_REAL_RUN_INVESTIGATION = autopilot._run_investigation


def _fresh():
    """Изолирует состояние центра инцидентов и гардов во временном каталоге, сбрасывает внутренние
    множества автопилота и подставляет расследование-заглушку без сети и без модели."""
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
    # По умолчанию расследование возвращает успешный трейс без сети и без модели.
    autopilot._run_investigation = lambda gid, alert: {
        "steps": [{"step": "observe", "argv": ["kubectl", "get", "pods"], "outcome": "executed"},
                  {"step": "done", "summary": "диагноз поставлен"}],
        "instruction": "разберись", "mode": "safe_repair"}
    return tmp


# Здоровые видимые факты: источники доступны, симптомов нет.
def _facts(**kw):
    f = {"nodes": [], "pods": [], "deployments": [], "events": [], "stats_by_node": {},
         "rca_verdict": None, "rca_available": True, "tls_days": None, "now": NOW_DT}
    f.update(kw)
    return f


HEALTHY = _facts()

# Факты с одним универсальным симптомом: под web в CrashLoopBackOff.
def _facts_crashloop():
    return _facts(pods=[{"name": "web-1-2", "phase": "Running",
                         "waiting_reason": "CrashLoopBackOff"}])


# Полная слепота: все источники кластера недоступны и RCA недоступен.
BLIND = {"nodes": None, "pods": None, "deployments": None, "events": None,
         "stats_by_node": {}, "rca_verdict": None, "rca_available": False,
         "tls_days": None, "now": NOW_DT}


# ---------------------------------------------------------------------------
# Различение слепоты от здоровья.
# ---------------------------------------------------------------------------


def test_is_blind_distinguishes_blindness_from_health():
    assert autopilot.is_blind(BLIND) is True
    # Здоровье: источники доступны (пусть и пустые списки), RCA отвечает.
    assert autopilot.is_blind(HEALTHY) is False
    # Частичная видимость (хотя бы один источник доступен) слепотой не считается.
    assert autopilot.is_blind(_facts(pods=None, nodes=None, deployments=None, events=None,
                                     rca_available=True)) is False


# ---------------------------------------------------------------------------
# Универсальные детекторы срабатывают на симптомы k8s без имён приложения.
# ---------------------------------------------------------------------------


def test_universal_symptom_registered():
    _fresh()
    out = autopilot.tick("http://rca", now=T0, facts=_facts_crashloop(),
                         autonomy=config.AUTONOMY_OBSERVE)
    codes = [d.get("code") for d in out]
    assert "crashloop" in codes, out


# ---------------------------------------------------------------------------
# Уровень observe: никаких мутаций, только наблюдение.
# ---------------------------------------------------------------------------


def test_observe_level_executes_nothing():
    _fresh()
    calls = []
    autopilot._run_investigation = lambda gid, alert: calls.append(alert) or None
    out = autopilot.tick("http://rca", now=T0, facts=_facts_crashloop(),
                         autonomy=config.AUTONOMY_OBSERVE)
    assert calls == [], "на уровне observe расследование/ремонт не запускается"
    dec = [d for d in out if d.get("code") == "crashloop"][0]
    assert dec["decision"] == "dry_run", dec
    g = incidents.get_group(dec["gid"])
    assert g["lifecycle"] == "new", g
    notes = g.get("notes") or []
    assert notes and "наблюдение" in notes[0]["text"], notes
    # Повторный такт не спамит ленту.
    autopilot.tick("http://rca", now=T0 + 30, facts=_facts_crashloop(),
                   autonomy=config.AUTONOMY_OBSERVE)
    assert len(g.get("notes") or []) == 1, g.get("notes")


# ---------------------------------------------------------------------------
# Уровень safe_repair: ремонт поручается расследованию, проверка результата.
# ---------------------------------------------------------------------------


def test_safe_repair_delegates_and_resolves():
    _fresh()
    out = autopilot.tick("http://rca", now=T0, facts=_facts_crashloop(),
                         autonomy=config.AUTONOMY_SAFE_REPAIR)
    dec = [d for d in out if d.get("code") == "crashloop"][0]
    assert dec["decision"] == "repair", dec
    g = incidents.get_group(dec["gid"])
    assert g["lifecycle"] == "auto_fixing", g
    # До VERIFY_DELAY проверка не выполняется.
    autopilot.tick("http://rca", now=T0 + 60, facts=_facts_crashloop(),
                   autonomy=config.AUTONOMY_SAFE_REPAIR)
    assert g["lifecycle"] == "auto_fixing", g
    # После VERIFY_DELAY симптом исчез (здоровые факты): решено агентом.
    autopilot.tick("http://rca", now=T0 + autopilot.VERIFY_DELAY + 1, facts=HEALTHY,
                   autonomy=config.AUTONOMY_SAFE_REPAIR)
    assert g["lifecycle"] == "resolved_auto", g
    assert g["resolved_by"] == "agent", g


def test_repair_failure_escalates_after_attempts():
    _fresh()
    autopilot._run_investigation = lambda gid, alert: {
        "steps": [{"step": "done", "summary": "не помогло"}], "mode": "safe_repair"}
    # Попытка 1.
    out = autopilot.tick("http://rca", now=T0, facts=_facts_crashloop(),
                         autonomy=config.AUTONOMY_SAFE_REPAIR)
    gid = [d for d in out if d.get("code") == "crashloop"][0]["gid"]
    g = incidents.get_group(gid)
    # Проверка: симптом держится, попытка неудачна, группа снова в работе.
    autopilot.tick("http://rca", now=T0 + autopilot.VERIFY_DELAY + 1, facts=_facts_crashloop(),
                   autonomy=config.AUTONOMY_SAFE_REPAIR)
    assert g["lifecycle"] == "new", g
    # Пока кулдаун отпечатка держится, ремонт отложен гардом.
    out = autopilot.tick("http://rca", now=T0 + autopilot.VERIFY_DELAY + 60,
                         facts=_facts_crashloop(), autonomy=config.AUTONOMY_SAFE_REPAIR)
    assert [d for d in out if d.get("code") == "crashloop"][0]["decision"] == "blocked", out
    # Попытка 2 после кулдауна, затем неудачная проверка исчерпывает попытки и эскалирует.
    t2 = T0 + autopilot.VERIFY_DELAY + guards.FP_COOLDOWN_SECONDS + 100
    autopilot.tick("http://rca", now=t2, facts=_facts_crashloop(),
                   autonomy=config.AUTONOMY_SAFE_REPAIR)
    autopilot.tick("http://rca", now=t2 + autopilot.VERIFY_DELAY + 1, facts=_facts_crashloop(),
                   autonomy=config.AUTONOMY_SAFE_REPAIR)
    assert g["lifecycle"] == "escalated", g
    assert any("Эскалация" in n["text"] for n in g.get("notes") or []), g.get("notes")


# ---------------------------------------------------------------------------
# Негатив: слепота источников не закрывает ожидающие проверки как решённые.
# ---------------------------------------------------------------------------


def test_blindness_does_not_resolve_pending():
    _fresh()
    # Ставим ремонт при видимости.
    out = autopilot.tick("http://rca", now=T0, facts=_facts_crashloop(),
                         autonomy=config.AUTONOMY_SAFE_REPAIR)
    gid = [d for d in out if d.get("code") == "crashloop"][0]["gid"]
    g = incidents.get_group(gid)
    assert g["lifecycle"] == "auto_fixing", g
    # На момент проверки источники наблюдения ослепли: пустых фактов нет, есть неизвестность.
    out = autopilot.tick("http://rca", now=T0 + autopilot.VERIFY_DELAY + 1, facts=BLIND,
                         autonomy=config.AUTONOMY_SAFE_REPAIR)
    assert out == [{"decision": "blind"}], out
    # Инцидент НЕ помечен решённым: слепота это неизвестность, а не успех.
    assert g["lifecycle"] != "resolved_auto", g
    assert g["lifecycle"] == "auto_fixing", g
    # Проверка не потеряна, отложена и помечена неопределённостью.
    assert autopilot._pending_verify, "ожидающая проверка не должна теряться при слепоте"
    joined = " ".join(n["text"] for n in g.get("notes") or [])
    assert "источники наблюдения" in joined and "неизвестен" in joined, joined
    # Видимость вернулась, симптом исчез: теперь честно решено.
    autopilot.tick("http://rca", now=T0 + 3 * autopilot.VERIFY_DELAY, facts=HEALTHY,
                   autonomy=config.AUTONOMY_SAFE_REPAIR)
    assert g["lifecycle"] == "resolved_auto", g


def test_blindness_does_not_start_new_actions():
    _fresh()
    calls = []
    autopilot._run_investigation = lambda gid, alert: calls.append(alert) or {"steps": []}
    out = autopilot.tick("http://rca", now=T0, facts=BLIND, autonomy=config.AUTONOMY_FULL)
    assert out == [{"decision": "blind"}], out
    assert calls == [], "при слепоте новые действия не начинаются"


# ---------------------------------------------------------------------------
# Негатив: исключение при исполнении действия не замораживает группу.
# ---------------------------------------------------------------------------


def test_action_exception_does_not_freeze_group():
    _fresh()

    def _boom(verdict, *, operator="operator", client=None):
        raise RuntimeError("сеть отвалилась в момент ремонта")

    # Восстанавливаем настоящую обёртку _run_investigation (её заменил _fresh заглушкой): именно она
    # обязана поглотить исключение реального agent_exec.investigate и вернуть None, а такт обязан
    # честно зафиксировать неудачу и не оставить группу замороженной в ремонте.
    autopilot._run_investigation = _REAL_RUN_INVESTIGATION
    orig = agent_exec.investigate
    agent_exec.investigate = _boom
    try:
        out = autopilot.tick("http://rca", now=T0, facts=_facts_crashloop(),
                             autonomy=config.AUTONOMY_SAFE_REPAIR)
    finally:
        agent_exec.investigate = orig
    dec = [d for d in out if d.get("code") == "crashloop"][0]
    # Ремонт не удался, но группа НЕ осталась замороженной в auto_fixing.
    assert dec["decision"] == "repair_failed", dec
    g = incidents.get_group(dec["gid"])
    assert g["lifecycle"] in ("new", "escalated"), g
    assert g["lifecycle"] != "auto_fixing", "исключение заморозило группу в ремонте"
    joined = " ".join(n["text"] for n in g.get("notes") or [])
    assert "не удал" in joined.lower(), joined


# ---------------------------------------------------------------------------
# Публичные сигнатуры и состояние.
# ---------------------------------------------------------------------------


def test_run_loop_signature_and_state():
    _fresh()
    # run_loop(rca_url) существует с ожидаемой сигнатурой (её вызывает app.py).
    import inspect
    sig = inspect.signature(autopilot.run_loop)
    assert list(sig.parameters) == ["rca_url"], sig
    st = autopilot.agent_state(now=T0)
    assert st["autonomy"] in config._AUTONOMY_LEVELS, st
    assert "budget_left" in st and "blind" in st, st
