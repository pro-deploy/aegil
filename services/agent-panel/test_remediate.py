"""Тесты детерминированного ремонта без языковой модели. Собираемый вид pytest.

Запуск: cd services/agent-panel && python3 -m pytest -q test_remediate.py
"""
import agent_exec
import config
import policy
import remediate


def _alert(code, service):
    return {"code": code, "params": {"service": service, "pod": service + "-0"},
            "verdict": {"params": {"service": service}}}


def test_propose_restart_for_restartable_symptoms():
    for code in ("crashloop", "oom", "restart_storm", "deploy_unavailable"):
        a = remediate.propose(_alert(code, "web"))
        assert a is not None
        assert a["argv"] == ["kubectl", "rollout", "restart", "web"]
        assert a["service"] == "web"


def test_propose_none_for_unfixable_by_restart():
    # Битый образ и переполнение диска перезапуском не лечатся: автономного действия нет.
    assert remediate.propose(_alert("image_pull", "web")) is None
    assert remediate.propose(_alert("disk_full", "web")) is None
    assert remediate.propose({"code": "crashloop", "params": {}}) is None  # нет сервиса


def test_would_autoact_respects_allowlist(monkeypatch):
    monkeypatch.setattr(config, "RESTART_ALLOWLIST", {"web"})
    monkeypatch.setattr(config, "RESTART_DENYLIST", {"postgres"})
    monkeypatch.setattr(agent_exec, "effective_autonomy", lambda: config.AUTONOMY_SAFE_REPAIR)
    # Сервис в allowlist: перезапуск исполнился бы автономно.
    assert agent_exec.would_autoact(["kubectl", "rollout", "restart", "web"]) is True
    # Сервис вне allowlist: не автономно (вынесется на подтверждение).
    assert agent_exec.would_autoact(["kubectl", "rollout", "restart", "unknown"]) is False
    # Сервис в denylist: не автономно.
    assert agent_exec.would_autoact(["kubectl", "rollout", "restart", "postgres"]) is False


def test_act_executes_autonomously_when_allowed(monkeypatch):
    monkeypatch.setattr(config, "RESTART_ALLOWLIST", {"web"})
    monkeypatch.setattr(agent_exec, "effective_autonomy", lambda: config.AUTONOMY_SAFE_REPAIR)
    # Подменяем фактическое исполнение мутации успешным результатом (без кластера).
    monkeypatch.setattr(agent_exec, "_execute_mutation",
                        lambda argv, target, node, operator, confirmed: {"ok": True, "detail": "ок"})
    res = agent_exec.act(["kubectl", "rollout", "restart", "web"])
    assert res["outcome"] == "executed"


def test_act_stages_confirm_when_not_allowed(monkeypatch):
    monkeypatch.setattr(config, "RESTART_ALLOWLIST", set())
    monkeypatch.setattr(agent_exec, "effective_autonomy", lambda: config.AUTONOMY_SAFE_REPAIR)
    res = agent_exec.act(["kubectl", "rollout", "restart", "web"])
    assert res["outcome"] == "pending_confirm"
    assert res.get("token")


def test_act_reads_are_never_gated(monkeypatch):
    monkeypatch.setattr(agent_exec, "_read", lambda argv, target, node, operator: {"ok": True})
    res = agent_exec.act(["kubectl", "get", "pods"])
    assert res["outcome"] == "read"
