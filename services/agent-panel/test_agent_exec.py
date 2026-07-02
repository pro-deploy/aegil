"""Модульные тесты агентного исполнителя команд (ADR-0041, спецификация разделы 3, 4, 5, 6).
Без сети и без pytest. Запуск: python3 services/adminchat/test_agent_exec.py

Модель и HTTP-транспорт node-agent мокаются, поэтому тесты детерминированы и не выходят в сеть.
Проверяется: auto-режим исполняет safe_write и НЕ исполняет finance и destructive (они уходят в
отложенное подтверждение); manual-режим ничего не исполняет сам (всё предложения); observe не
считается в бюджет гардов; фолбэк без модели исполняет одну команду оператора; гарды вызываются
ПЕРЕД мутацией.

Запрещённые правилами проекта символы (длинное тире, стрелка) в текстах не используются: переходы
и следствия названы словами.
"""
import tempfile
from pathlib import Path

import agent_exec
import guards


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def _fresh_guards():
    """Свежее состояние гардов во временном файле, чтобы тесты не влияли друг на друга и на прод."""
    tmp = Path(tempfile.mkdtemp())
    guards.STATE_PATH = tmp / "agent-guards.log.jsonl"
    guards.load()
    return tmp


def _fresh_mode(mode):
    """Свежий файл режима во временной директории."""
    tmp = Path(tempfile.mkdtemp())
    agent_exec._MODE_PATH = tmp / "agent-mode.txt"
    agent_exec.set_mode(mode)
    return tmp


def _reset_pending():
    agent_exec.PENDING.clear()


# node-agent считается доступным в тестах (токен задан), а транспорт мокается через http_post.
agent_exec.NODEAGENT_TOKEN = "test-token"


# Подмена дискавери endpoint node-agent, чтобы _run_node_agent не ходил в Kubernetes API.
import k8s
k8s.get_node_agent_endpoint = lambda node: f"http://10.0.0.1:9110"


# Мок HTTP-транспорта node-agent: возвращает успешный ответ по контракту, записывает вызовы.
class FakeNodeAgent:
    def __init__(self, exit_code=0):
        self.calls = []
        self.exit_code = exit_code

    def __call__(self, url, body, headers):
        self.calls.append({"url": url, "body": body, "headers": headers})
        return {"exit_code": self.exit_code, "stdout": "готово", "stderr": "",
                "duration_ms": 5, "node": body.get("argv", ["?"])[0] and "gpu"}


def _model_script(calls):
    """Мок модели: отдаёт заранее заданную последовательность JSON-ответов, по одному на вызов."""
    seq = list(calls)

    def _complete(prompt):
        if not seq:
            return '{"tool":"done","summary":"больше нечего делать"}'
        return seq.pop(0)

    return _complete


# ---------------------------------------------------------------------------


def test_auto_executes_safe_write():
    """auto-режим: safe_write (rollout restart) исполняется сразу через гарды и аудит."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    # Настоящее исполнение мутации в кластере деградирует (вне кластера k8s вернёт ok=None),
    # но нам важно, что политика РАЗРЕШИЛА исполнение (outcome executed или failed, не pending).
    step = agent_exec._handle_act(
        {"argv": ["kubectl", "rollout", "restart", "deployment/asr"], "target": "cluster",
         "why": "asr тормозит"}, operator="agent")
    _eq("класс safe_write", step["class"], "safe_write")
    assert step["outcome"] in ("executed", "failed"), step
    assert step["outcome"] != "pending_confirm", "safe_write не должен уходить в подтверждение"
    print("auto исполняет safe_write: ok")


def test_auto_defers_finance():
    """auto-режим: finance НЕ исполняется автономно, уходит в отложенное подтверждение."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    step = agent_exec._handle_act(
        {"argv": ["curl", "-XPOST", "http://api/api/admin/tariff"], "target": "cluster",
         "why": "смена тарифа"}, operator="agent")
    _eq("класс finance", step["class"], "finance")
    _eq("не исполнено, а отложено", step["outcome"], "pending_confirm")
    assert step["confirm_token"] in agent_exec.PENDING, "токен должен лежать в PENDING"
    print("auto откладывает finance: ok")


def test_auto_defers_destructive():
    """auto-режим: destructive НЕ исполняется автономно, уходит в отложенное подтверждение."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    step = agent_exec._handle_act(
        {"argv": ["kubectl", "delete", "namespace", "krokki"], "target": "cluster",
         "why": "зачистка"}, operator="agent")
    _eq("класс destructive", step["class"], "destructive")
    _eq("не исполнено, а отложено", step["outcome"], "pending_confirm")
    assert step["confirm_token"] in agent_exec.PENDING
    print("auto откладывает destructive: ok")


def test_manual_proposes_everything():
    """manual-режим: ничего не исполняется сам, любая мутация возвращается предложением."""
    _fresh_guards()
    _fresh_mode("manual")
    _reset_pending()
    # safe_write в manual становится предложением, а не исполнением.
    step = agent_exec._handle_act(
        {"argv": ["kubectl", "delete", "pod", "asr-x"], "target": "cluster", "why": "рестарт"},
        operator="agent")
    _eq("класс safe_write", step["class"], "safe_write")
    _eq("в ручном режиме предложено", step["outcome"], "proposed")
    assert step["confirm_token"] in agent_exec.PENDING
    # finance в manual тоже предложение (pending_confirm), не исполнение.
    step2 = agent_exec._handle_act(
        {"argv": ["/tariff", "abc", "pro"], "why": "смена тарифа"}, operator="agent")
    _eq("finance в ручном тоже не исполнено", step2["outcome"], "pending_confirm")
    print("manual всё предлагает: ok")


def test_observe_not_in_budget():
    """observe не считается в бюджет гардов и исполняется всегда, даже при auto."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    fake = FakeNodeAgent()
    step = agent_exec._handle_observe(
        {"argv": ["df", "-h", "/"], "target": "gpu"}, http_post=fake)
    _eq("класс read", step["class"], "read")
    _eq("не считается в бюджет", step["counts_budget"], False)
    # Бюджет гардов не тронут наблюдением.
    g = guards.state_summary()
    _eq("бюджет не израсходован наблюдением", g["budget_left"], g["budget_total"])
    assert len(fake.calls) == 1, "наблюдение на узле должно идти через node-agent"
    print("observe не в бюджете: ok")


def test_observe_mutating_becomes_act():
    """observe с мутирующей командой перенаправляется в act (классификатор подтверждает read)."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    step = agent_exec._handle_observe(
        {"argv": ["kubectl", "delete", "namespace", "krokki"], "target": "cluster"})
    # Команда мутирующая (destructive), поэтому уходит на подтверждение, а не исполняется как чтение.
    _eq("мутирующее наблюдение стало act", step["outcome"], "pending_confirm")
    _eq("класс destructive", step["class"], "destructive")
    print("observe мутирующее становится act: ok")


def test_guards_called_before_mutation():
    """Гарды вызываются ПЕРЕД исполнением мутации: исчерпанный бюджет блокирует safe_write."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    # Забиваем бюджет действий гарда до предела.
    import time
    now = time.time()
    for i in range(guards.BUDGET_PER_HOUR):
        guards.record_attempt(f"fill-{i}", "restart", now=now)
    step = agent_exec._handle_act(
        {"argv": ["kubectl", "rollout", "restart", "deployment/asr"], "target": "cluster",
         "why": "рестарт"}, operator="agent")
    _eq("класс safe_write", step["class"], "safe_write")
    _eq("гард заблокировал по бюджету", step["outcome"], "blocked")
    assert "бюджет" in step["message"], step["message"]
    print("гарды перед мутацией: ok")


def test_fallback_no_model_single_command():
    """Фолбэк без модели исполняет ОДНУ команду оператора без планирования."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    # Чтение через фолбэк: одна команда, класс read, шаг observe.
    res = agent_exec.run("df -h /", operator="op", llm_complete=None)
    _eq("без модели", res["model"], False)
    _eq("один шаг", len(res["steps"]), 1)
    _eq("шаг наблюдения", res["steps"][0]["step"], "observe")
    # Мутация через фолбэк: одна команда, финансовая уходит в подтверждение, не исполняется.
    res2 = agent_exec.run("curl http://api/api/admin/tariff", operator="op", llm_complete=None)
    _eq("финансовая отложена в фолбэке", res2["steps"][0]["outcome"], "pending_confirm")
    print("фолбэк одной командой: ok")


def test_confirm_executes_pending():
    """Подтверждение исполняет отложенную команду одноразовым токеном; повтор токена отклонён."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    step = agent_exec._handle_act(
        {"argv": ["kubectl", "delete", "pod", "asr-x"], "target": "cluster", "why": "рестарт"},
        operator="agent")
    # Переведём режим в manual, чтобы safe_write ушёл в proposed с токеном.
    # (тут auto, поэтому safe_write уже исполнился; сделаем finance для отложенного токена)
    step_fin = agent_exec._handle_act(
        {"argv": ["/tariff", "abc", "pro"], "why": "смена тарифа"}, operator="agent")
    token = step_fin["confirm_token"]
    res = agent_exec.confirm(token, operator="operator1")
    assert "step" in res, res
    _eq("токен одноразовый: повтор отклонён", agent_exec.confirm(token, "operator1")["ok"], False)
    print("подтверждение отложенного: ok")


def test_full_loop_with_model():
    """Полный цикл с моделью: наблюдение, объяснение, действие, завершение. finance по пути
    уходит в подтверждение и не исполняется автономно."""
    _fresh_guards()
    _fresh_mode("auto")
    _reset_pending()
    fake = FakeNodeAgent()
    model = _model_script([
        '{"tool":"observe","argv":["df","-h","/"],"target":"gpu"}',
        '{"tool":"explain","text":"диск почти полон, чищу кеш docker"}',
        '{"tool":"node_cmd","node":"gpu","argv":["docker","system","prune","-f"],"why":"освободить место"}',
        '{"tool":"done","summary":"диск очищен"}',
    ])
    res = agent_exec.run("почисти диск на gpu-узле", operator="op",
                         llm_complete=model, http_post=fake)
    _eq("цикл с моделью", res["model"], True)
    kinds = [s["step"] for s in res["steps"]]
    assert "observe" in kinds and "explain" in kinds and "done" in kinds, kinds
    # node_cmd prune это safe_write, в auto исполнился через node-agent.
    node_steps = [s for s in res["steps"] if s["step"] == "node_cmd"]
    _eq("один узловой шаг", len(node_steps), 1)
    _eq("узловой safe_write исполнен", node_steps[0]["outcome"], "executed")
    print("полный цикл с моделью: ok")


def test_mode_get_set():
    """get_mode и set_mode переключают режим и переживают чтение файла; мусор отклоняется."""
    _fresh_mode("auto")
    _eq("по умолчанию auto", agent_exec.get_mode(), "auto")
    _eq("переключение в manual", agent_exec.set_mode("manual"), "manual")
    _eq("прочитан manual", agent_exec.get_mode(), "manual")
    _eq("мусор не меняет режим", agent_exec.set_mode("garbage"), "manual")
    print("режимы get/set: ok")


if __name__ == "__main__":
    test_auto_executes_safe_write()
    test_auto_defers_finance()
    test_auto_defers_destructive()
    test_manual_proposes_everything()
    test_observe_not_in_budget()
    test_observe_mutating_becomes_act()
    test_guards_called_before_mutation()
    test_fallback_no_model_single_command()
    test_confirm_executes_pending()
    test_full_loop_with_model()
    test_mode_get_set()
    print("ВСЕ ТЕСТЫ agent_exec ПРОЙДЕНЫ")
