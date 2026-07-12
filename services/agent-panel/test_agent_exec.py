"""Тесты агентного исполнителя команд. Без сети: клиент модели подменяется фейком, сценирующим
вызовы инструментов, а исполнение (k8s API и node-agent), гарды и аудит мокаются через monkeypatch.

Проверяется: полный агентный цикл (наблюдение, действие, завершение); детерминированный гейт по
уровням автономии (observe только предлагает, safe_repair исполняет безопасный ремонт из allowlist,
destructive уходит в отложенное подтверждение); observe с мутацией эскалируется в act; блокировка
гардом; исполнение подтверждённой команды; продуктовый слой allowlist и denylist перезапуска;
фолбэк одиночной команды без модели; аудит чтений и постановки в подтверждение.
"""
import os

os.environ.setdefault("AEGIL_LLM_API_KEY", "test-key")

import pytest

import agent_exec
import config
import llm
import policy


# --- Фейк клиента модели ------------------------------------------------------------------------

class _FakeClient:
    def __init__(self, turns):
        self.turns = list(turns)
        self.sent = []

    def start(self, system, tools):
        return llm.Conversation(system=system, tools=tools)

    def send_user(self, conv, text):
        conv.messages.append({"role": "user", "content": text})

    def send_tool_results(self, conv, results):
        self.sent.append(results)

    def run(self, conv, stream=False, on_text=None):
        return self.turns.pop(0)


def _turn(*calls, text="", stop="tool_use"):
    tcs = [llm.ToolCall(id=c[0], name=c[1], input=c[2]) for c in calls]
    return llm.Turn(text=text, tool_calls=tcs, stop_reason=stop if tcs else "end")


# --- Общая изоляция: пути состояния в tmp, аудит и гарды под контролем ---------------------------

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(agent_exec, "_PENDING_PATH", tmp_path / "pending.json")
    monkeypatch.setattr(agent_exec, "_AUTONOMY_PATH", tmp_path / "autonomy")
    # Аудит: перехватываем вызовы вместо записи в файл.
    calls = {"read": [], "write": [], "pending": []}
    monkeypatch.setattr(agent_exec.audit, "audit_read",
                        lambda *a, **k: calls["read"].append((a, k)))
    monkeypatch.setattr(agent_exec.audit, "audit_write",
                        lambda *a, **k: calls["write"].append((a, k)))
    monkeypatch.setattr(agent_exec.audit, "audit_pending",
                        lambda *a, **k: calls["pending"].append((a, k)))
    # Гарды: по умолчанию всё разрешено, фиксация без файла.
    monkeypatch.setattr(agent_exec.guards, "check", lambda *a, **k: (True, ""))
    monkeypatch.setattr(agent_exec.guards, "record_attempt", lambda *a, **k: None)
    monkeypatch.setattr(agent_exec.guards, "record_result", lambda *a, **k: None)
    # Кластер: два узла, типизированные операции успешны.
    monkeypatch.setattr(agent_exec.k8s, "list_nodes",
                        lambda: [{"name": "cp-1", "role": "control-plane"}, {"name": "w-1", "role": "worker"}])
    monkeypatch.setattr(agent_exec.k8s, "list_pods", lambda: [{"name": "api-abc", "phase": "Running"}])
    monkeypatch.setattr(agent_exec.k8s, "rollout_restart", lambda name, iso: (True, "перезапущено"))
    monkeypatch.setattr(agent_exec.k8s, "delete_pod", lambda pod: (True, "удалён"))
    monkeypatch.setattr(agent_exec.k8s, "pod_service", lambda p: p.rsplit("-", 1)[0])
    monkeypatch.setattr(agent_exec.k8s, "resolve_node", lambda n: n)
    monkeypatch.setattr(agent_exec.k8s, "get_node_agent_endpoint", lambda n: f"http://{n}:9110")
    monkeypatch.setattr(agent_exec.config, "NODEAGENT_TOKEN", "tok")
    # Узловой агент: успешный ответ.
    monkeypatch.setattr(agent_exec, "_run_node",
                        lambda node, argv, timeout=30: {"exit_code": 0, "stdout": "готово", "node": node})
    return calls


def _autonomy(level):
    agent_exec.set_mode(level)


# --- Полный цикл --------------------------------------------------------------------------------

def test_full_loop_observe_act_done(env, monkeypatch):
    _autonomy(config.AUTONOMY_SAFE_REPAIR)
    monkeypatch.setattr(agent_exec.config, "RESTART_ALLOWLIST", {"api"})
    client = _FakeClient([
        _turn(("1", "observe", {"argv": ["kubectl", "get", "pods"], "target": "cluster"})),
        _turn(("2", "act", {"argv": ["kubectl", "rollout", "restart", "deploy/api"],
                            "target": "cluster", "why": "перезапуск"})),
        _turn(("3", "done", {"summary": "перезапустил api"})),
    ])
    res = agent_exec.run("почини api", "op1", client=client)
    kinds = [s["step"] for s in res["steps"]]
    assert kinds == ["observe", "act", "done"]
    assert res["steps"][0]["outcome"] == "executed"
    assert res["steps"][1]["outcome"] == "executed"
    assert res["summary"] == "перезапустил api"
    # Чтение и мутация записаны в аудит.
    assert len(env["read"]) == 1
    assert len(env["write"]) == 1


def test_observe_labeled_mutation_is_gated(env, monkeypatch):
    # Модель назвала observe, но команда мутирующая: шаг обязан пройти гейт, не исполниться как чтение.
    _autonomy(config.AUTONOMY_SAFE_REPAIR)
    client = _FakeClient([
        _turn(("1", "observe", {"argv": ["kubectl", "delete", "ns", "prod"], "target": "cluster"})),
    ])
    res = agent_exec.run("сделай", "op1", client=client)
    step = res["steps"][0]
    assert step["outcome"] == "pending_confirm"  # destructive -> подтверждение, а не чтение
    assert step["class"] == policy.DESTRUCTIVE


# --- Ветки гейта --------------------------------------------------------------------------------

def test_destructive_stops_for_confirmation(env):
    _autonomy(config.AUTONOMY_FULL)
    client = _FakeClient([
        _turn(("1", "act", {"argv": ["kubectl", "delete", "pvc", "data-0"], "target": "cluster",
                            "why": "чистка"})),
        _turn(("2", "done", {"summary": "не должно дойти"})),
    ])
    res = agent_exec.run("удали том", "op1", client=client)
    # Ход остановлен на подтверждении: done из второго хода не выполняется.
    assert len(res["steps"]) == 1
    step = res["steps"][0]
    assert step["outcome"] == "pending_confirm"
    assert step["confirm_token"]
    assert len(env["pending"]) == 1  # постановка в подтверждение аудирована


def test_observe_level_proposes_only(env):
    _autonomy(config.AUTONOMY_OBSERVE)
    client = _FakeClient([
        _turn(("1", "act", {"argv": ["kubectl", "rollout", "restart", "deploy/api"],
                            "target": "cluster", "why": "перезапуск"})),
        _turn(("2", "done", {"summary": "предложил перезапуск"})),
    ])
    res = agent_exec.run("перезапусти", "op1", client=client)
    assert res["steps"][0]["outcome"] == "proposed"
    assert res["steps"][1]["step"] == "done"
    # Ничего не исполнено, мутаций в аудите нет.
    assert len(env["write"]) == 0


def test_restart_denylist_forces_confirm(env, monkeypatch):
    _autonomy(config.AUTONOMY_FULL)
    monkeypatch.setattr(agent_exec.config, "RESTART_ALLOWLIST", {"postgres"})  # даже если в allowlist
    client = _FakeClient([
        _turn(("1", "act", {"argv": ["kubectl", "rollout", "restart", "statefulset/postgres"],
                            "target": "cluster", "why": "перезапуск"})),
    ])
    res = agent_exec.run("перезапусти postgres", "op1", client=client)
    # postgres в denylist по умолчанию: подтверждение обязательно.
    assert res["steps"][0]["outcome"] == "pending_confirm"


def test_restart_outside_allowlist_forces_confirm(env, monkeypatch):
    _autonomy(config.AUTONOMY_SAFE_REPAIR)
    monkeypatch.setattr(agent_exec.config, "RESTART_ALLOWLIST", set())  # пусто = автоперезапуск выключен
    client = _FakeClient([
        _turn(("1", "act", {"argv": ["kubectl", "rollout", "restart", "deploy/api"],
                            "target": "cluster", "why": "перезапуск"})),
    ])
    res = agent_exec.run("перезапусти api", "op1", client=client)
    assert res["steps"][0]["outcome"] == "pending_confirm"


# --- Гарды --------------------------------------------------------------------------------------

def test_guard_blocks_mutation(env, monkeypatch):
    _autonomy(config.AUTONOMY_SAFE_REPAIR)
    monkeypatch.setattr(agent_exec.config, "RESTART_ALLOWLIST", {"api"})
    monkeypatch.setattr(agent_exec.guards, "check", lambda *a, **k: (False, "исчерпан бюджет"))
    client = _FakeClient([
        _turn(("1", "act", {"argv": ["kubectl", "rollout", "restart", "deploy/api"],
                            "target": "cluster", "why": "перезапуск"})),
    ])
    res = agent_exec.run("перезапусти", "op1", client=client)
    assert res["steps"][0]["outcome"] == "blocked"
    assert "бюджет" in res["steps"][0]["result"]["error"]


# --- Подтверждение отложенного ------------------------------------------------------------------

def test_confirm_executes_pending(env):
    _autonomy(config.AUTONOMY_FULL)
    client = _FakeClient([
        _turn(("1", "act", {"argv": ["kubectl", "delete", "pvc", "data-0"], "target": "cluster",
                            "why": "чистка"})),
    ])
    res = agent_exec.run("удали том", "op1", client=client)
    token = res["steps"][0]["confirm_token"]
    # Чужой оператор не может подтвердить.
    other = agent_exec.confirm(token, "op2")
    assert other["ok"] is False
    # Инициатор подтверждает и исполняет.
    ok = agent_exec.confirm(token, "op1")
    assert ok["ok"] is True
    # Повторный токен уже недействителен.
    again = agent_exec.confirm(token, "op1")
    assert again["ok"] is False


def test_pending_expiry(env, monkeypatch):
    _autonomy(config.AUTONOMY_FULL)
    monkeypatch.setattr(agent_exec, "PENDING_TTL_SECONDS", -1)  # истекает мгновенно
    client = _FakeClient([
        _turn(("1", "act", {"argv": ["kubectl", "delete", "ns", "prod"], "target": "cluster",
                            "why": "снос"})),
    ])
    res = agent_exec.run("снеси", "op1", client=client)
    token = res["steps"][0]["confirm_token"]
    assert agent_exec.confirm(token, "op1")["ok"] is False  # уже истёк


# --- Фолбэк без модели --------------------------------------------------------------------------

def test_single_command_fallback(env):
    _autonomy(config.AUTONOMY_SAFE_REPAIR)
    res = agent_exec.run("kubectl get pods", "op1", client=None)
    # Без клиента модели: одна команда. get pods это чтение, но в _run_single идёт как act;
    # классификатор всё равно относит к read, поэтому исполняется как безопасное.
    assert len(res["steps"]) == 1


def test_single_command_node_prefix(env):
    _autonomy(config.AUTONOMY_SAFE_REPAIR)
    res = agent_exec.run("node:w-1 df -h /", "op1", client=None)
    step = res["steps"][0]
    assert step["node"] == "w-1"
    assert step["step"] in ("observe", "node_cmd")


# --- Уровень автономии и сводка -----------------------------------------------------------------

def test_set_mode_persists_and_legacy(env):
    assert agent_exec.set_mode("full") == "full"
    assert agent_exec.effective_autonomy() == "full"
    assert agent_exec.set_mode("manual") == "observe"  # старое имя
    assert agent_exec.effective_autonomy() == "observe"
    assert agent_exec.set_mode("чепуха") == "observe"  # мусор не меняет


def test_state_summary(env, monkeypatch):
    monkeypatch.setattr(agent_exec.guards, "observe_only", lambda: False)
    monkeypatch.setattr(agent_exec.guards, "state_summary", lambda: {"budget_left": 6})
    _autonomy(config.AUTONOMY_SAFE_REPAIR)
    s = agent_exec.state_summary()
    assert s["autonomy"] == "safe_repair"
    assert "guards" in s and "pending" in s


# --- Инструменты MCP -----------------------------------------------------------------------------

import mcp_tools
from mcp_tools import ServerCfg


class _FakeCaller:
    def __init__(self, cfg, tools, results=None):
        self.cfg, self._tools, self._results = cfg, tools, results or {}

    def list_tools(self):
        return self._tools

    def call_tool(self, raw_name, args):
        return self._results.get(raw_name, "результат MCP")


@pytest.fixture
def mcp_env(env, monkeypatch):
    """Реестр MCP с одним читающим сервером (obs) и одним потенциально мутирующим (mut)."""
    tools = [{"name": "query", "description": "запрос", "input_schema": {"type": "object"}}]
    factory = lambda cfg: _FakeCaller(cfg, tools)
    reg = mcp_tools.build_registry(session_factory=factory, config=[
        ServerCfg("obs", "http://obs/mcp", read_only=True),
        ServerCfg("mut", "http://mut/mcp", read_only=False),
    ])
    monkeypatch.setattr(agent_exec, "_REGISTRY", reg)
    return env


def test_mcp_readonly_executes(mcp_env):
    _autonomy(config.AUTONOMY_SAFE_REPAIR)
    client = _FakeClient([
        _turn(("1", "mcp__obs__query", {"q": "up"})),
        _turn(("2", "done", {"summary": "посмотрел метрики"})),
    ])
    res = agent_exec.run("покажи метрики", "op1", client=client)
    assert res["steps"][0]["outcome"] == "executed"
    assert res["steps"][0]["result"]["text"] == "результат MCP"
    assert len(mcp_env["read"]) == 1  # читающий инструмент MCP аудирован как чтение


def test_mcp_mutating_requires_confirmation(mcp_env):
    _autonomy(config.AUTONOMY_FULL)
    client = _FakeClient([
        _turn(("1", "mcp__mut__query", {"q": "apply"})),
        _turn(("2", "done", {"summary": "не дойдёт"})),
    ])
    res = agent_exec.run("сделай через mcp", "op1", client=client)
    assert len(res["steps"]) == 1
    assert res["steps"][0]["outcome"] == "pending_confirm"
    token = res["steps"][0]["confirm_token"]
    # Подтверждение исполняет вызов MCP.
    ok = agent_exec.confirm(token, "op1")
    assert ok["ok"] is True


def test_mcp_mutating_observe_only_proposes(mcp_env):
    _autonomy(config.AUTONOMY_OBSERVE)
    client = _FakeClient([
        _turn(("1", "mcp__mut__query", {"q": "apply"})),
        _turn(("2", "done", {"summary": "предложил"})),
    ])
    res = agent_exec.run("через mcp", "op1", client=client)
    assert res["steps"][0]["outcome"] == "proposed"


def test_build_tools_includes_mcp(mcp_env):
    names = [t["name"] for t in agent_exec._build_tools()]
    assert "observe" in names and "mcp__obs__query" in names and "mcp__mut__query" in names


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
