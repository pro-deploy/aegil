"""Модульные тесты слоя доступа к API Kubernetes (модуль k8s).

Тесты собираются стандартным сборщиком pytest (функции с префиксом test_) и выполняются без
обращения к сети. HTTP-транспорт httpx и обёртка чтения JSON подменяются через фикстуру
monkeypatch, поэтому ни один тест не открывает реального соединения, а поведение при недоступности
API моделируется явно. Проверяется: привязка метки роли узла к конфигурации продукта, отсутствие
зашитых доменных синонимов узлов, разрешение дружеского имени через метку роли, обработка ошибок и
таймаутов API как честного отказа вместо падения, валидация имён по DNS-1123 до обращения к API,
дисциплина allowlist и denylist до обращения к API, а также единый префикс AEGIL_ для параметров
дискавери node-agent.

Запрещённые правилами проекта символы (длинное тире, стрелка) в текстах не используются.
"""
from __future__ import annotations

import httpx
import pytest

import config
import k8s


# --- Вспомогательные подделки транспорта -------------------------------------------------------


class _FakeResponse:
    """Минимальный ответ httpx: код состояния, тело JSON и текст. Метод raise_for_status повторяет
    поведение настоящего httpx, бросая исключение на кодах 4xx и 5xx."""

    def __init__(self, status_code=200, json_body=None, text=""):
        self.status_code = status_code
        self._json = json_body if json_body is not None else {}
        self.text = text

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("ошибка", request=None, response=None)


class _FakeClient:
    """Подделка httpx.Client, фиксирующая переданный таймаут и отдающая заранее заданный ответ или
    бросающая заранее заданное исключение на любом методе (get, delete, patch)."""

    last_timeout = None
    calls = []

    def __init__(self, verify=None, timeout=None):
        _FakeClient.last_timeout = timeout
        self.verify = verify

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def _respond(self, method, url):
        _FakeClient.calls.append((method, url))
        if _FakeClient.raise_exc is not None:
            raise _FakeClient.raise_exc
        return _FakeClient.response

    def get(self, url, **kw):
        return self._respond("get", url)

    def delete(self, url, **kw):
        return self._respond("delete", url)

    def patch(self, url, **kw):
        return self._respond("patch", url)


_FakeClient.response = _FakeResponse()
_FakeClient.raise_exc = None


@pytest.fixture(autouse=True)
def _reset_fakeclient():
    """Сбрасывает состояние подделки транспорта перед каждым тестом, чтобы тесты не влияли друг
    на друга."""
    _FakeClient.calls = []
    _FakeClient.response = _FakeResponse()
    _FakeClient.raise_exc = None
    _FakeClient.last_timeout = None
    yield


def _use_fake_client(monkeypatch, response=None, raise_exc=None):
    """Подменяет httpx.Client в модуле k8s на подделку и включает признак «в кластере», чтобы
    ветка обращения к API исполнялась без сети."""
    if response is not None:
        _FakeClient.response = response
    _FakeClient.raise_exc = raise_exc
    monkeypatch.setattr(k8s.httpx, "Client", _FakeClient)
    monkeypatch.setattr(k8s, "_incluster",
                        lambda: ("https://api.local:443", "token", False))


# --- Метка роли узла привязана к конфигурации --------------------------------------------------


def test_node_role_label_bound_to_config():
    """Метка роли узла в модуле k8s это ровно значение из config.NODE_ROLE_LABEL, а не зашитая
    строка: настройка config.NODE_ROLE_LABEL действительно управляет поведением."""
    assert k8s.NODE_ROLE_LABEL == config.NODE_ROLE_LABEL


def test_no_hardcoded_krokki_role_label():
    """В модуле не осталось наследной зашитой метки роли исходной платформы."""
    assert k8s.NODE_ROLE_LABEL != "krokki.io/role"


def test_no_hardcoded_node_aliases():
    """Зашитого словаря доменных синонимов узлов в модуле нет вовсе."""
    assert not hasattr(k8s, "_NODE_ROLE_ALIASES")


def test_source_has_no_domain_names():
    """Исходный текст модуля не содержит наследных доменных кличек узлов и имён исходной
    платформы."""
    import inspect

    src = inspect.getsource(k8s).lower()
    for token in ("gooseek", "гусик", "krokki", "stalwart", "adminchat"):
        assert token not in src, f"в исходнике осталось наследное имя: {token}"


# --- Разрешение имени узла через метку роли ----------------------------------------------------


def _nodes_payload(items):
    return {"items": items}


def test_resolve_node_exact_name(monkeypatch):
    """Точное имя существующего узла возвращается как есть."""
    monkeypatch.setattr(k8s, "_get_json", lambda path, **kw: _nodes_payload([
        {"metadata": {"name": "node-a", "labels": {}}},
        {"metadata": {"name": "node-b", "labels": {}}},
    ]))
    assert k8s.resolve_node("node-b") == "node-b"


def test_resolve_node_by_role_label(monkeypatch):
    """Дружеское имя резолвится по фактическому значению метки роли из config.NODE_ROLE_LABEL,
    без каких-либо зашитых синонимов."""
    label = config.NODE_ROLE_LABEL
    monkeypatch.setattr(k8s, "_get_json", lambda path, **kw: _nodes_payload([
        {"metadata": {"name": "real-node-1", "labels": {label: "gpu"}}},
        {"metadata": {"name": "real-node-2", "labels": {label: "control"}}},
    ]))
    assert k8s.resolve_node("gpu") == "real-node-1"
    assert k8s.resolve_node("CONTROL") == "real-node-2"


def test_resolve_node_legacy_alias_not_resolved(monkeypatch):
    """Наследная кличка узла, отсутствующая в метках, больше не резолвится: зашитых синонимов нет,
    и совпадения по подстроке с реальными именами тоже нет."""
    monkeypatch.setattr(k8s, "_get_json", lambda path, **kw: _nodes_payload([
        {"metadata": {"name": "real-node-1", "labels": {config.NODE_ROLE_LABEL: "gpu"}}},
    ]))
    assert k8s.resolve_node("gooseek") is None


def test_resolve_node_substring(monkeypatch):
    """Сокращённая форма реального имени узла распознаётся по подстроке."""
    monkeypatch.setattr(k8s, "_get_json", lambda path, **kw: _nodes_payload([
        {"metadata": {"name": "cluster-worker-01", "labels": {}}},
    ]))
    assert k8s.resolve_node("worker-01") == "cluster-worker-01"


def test_resolve_node_out_of_cluster_returns_valid_name(monkeypatch):
    """Вне кластера (список узлов недоступен) валидное по DNS-1123 имя возвращается как есть,
    а недопустимое отбрасывается."""
    monkeypatch.setattr(k8s, "_get_json", lambda path, **kw: None)
    assert k8s.resolve_node("some-node") == "some-node"
    assert k8s.resolve_node("НЕ ВАЛИДНОЕ ИМЯ") is None


def test_resolve_node_empty(monkeypatch):
    """Пустое имя это None без обращения к API."""
    called = {"n": 0}

    def _spy(path, **kw):
        called["n"] += 1
        return None

    monkeypatch.setattr(k8s, "_get_json", _spy)
    assert k8s.resolve_node("") is None
    assert k8s.resolve_node("   ") is None
    assert called["n"] == 0


# --- Обработка ошибок и таймаутов API ----------------------------------------------------------


def test_get_json_swallows_timeout(monkeypatch):
    """Таймаут при чтении JSON превращается в None (мягкая деградация), а не в исключение."""
    _use_fake_client(monkeypatch, raise_exc=httpx.TimeoutException("таймаут"))
    assert k8s._get_json("/api/v1/nodes") is None


def test_list_deployments_handles_api_error(monkeypatch):
    """Недоступность API при получении деплойментов даёт None, а не падение обработчика."""
    _use_fake_client(monkeypatch, raise_exc=httpx.ConnectError("нет связи"))
    assert k8s.list_deployments() is None


def test_list_deployments_handles_http_error(monkeypatch):
    """Ответ 500 при получении деплойментов также даёт None, а не исключение из raise_for_status."""
    _use_fake_client(monkeypatch, response=_FakeResponse(status_code=500))
    assert k8s.list_deployments() is None


def test_list_deployments_ok(monkeypatch):
    """При исправном API деплойменты разбираются в ожидаемую структуру со статусом реплик."""
    body = {"items": [
        {"metadata": {"name": "svc-b"}, "spec": {"replicas": 3},
         "status": {"readyReplicas": 2, "availableReplicas": 2}},
        {"metadata": {"name": "svc-a"}, "spec": {"replicas": 1},
         "status": {"readyReplicas": 1, "availableReplicas": 1}},
    ]}
    _use_fake_client(monkeypatch, response=_FakeResponse(json_body=body))
    got = k8s.list_deployments()
    assert [d["name"] for d in got] == ["svc-a", "svc-b"]
    assert got[1] == {"name": "svc-b", "desired": 3, "ready": 2, "available": 2}


def test_list_deployments_out_of_cluster(monkeypatch):
    """Вне кластера деплойменты недоступны: None без обращения к транспорту."""
    monkeypatch.setattr(k8s, "_incluster", lambda: None)
    assert k8s.list_deployments() is None


def test_rollout_restart_handles_api_error(monkeypatch):
    """Исключение сети во время перезапуска возвращается как честный отказ (ok=False с текстом),
    а не всплывает наружу и не роняет вызывающий цикл."""
    monkeypatch.setattr(k8s, "ALLOWED", {"svc"})
    monkeypatch.setattr(k8s, "DENY", set())
    _use_fake_client(monkeypatch, raise_exc=httpx.ConnectError("нет связи"))
    ok, detail = k8s.rollout_restart("svc", "2026-07-08T00:00:00Z")
    assert ok is False
    assert "API Kubernetes" in detail


def test_rollout_restart_ok(monkeypatch):
    """Успешный ответ API даёт ok=True."""
    monkeypatch.setattr(k8s, "ALLOWED", {"svc"})
    monkeypatch.setattr(k8s, "DENY", set())
    _use_fake_client(monkeypatch, response=_FakeResponse(status_code=200))
    ok, detail = k8s.rollout_restart("svc", "2026-07-08T00:00:00Z")
    assert ok is True


def test_delete_pod_handles_api_error(monkeypatch):
    """Исключение сети во время удаления пода возвращается как честный отказ, а не падение."""
    monkeypatch.setattr(k8s, "ALLOWED", {"svc"})
    monkeypatch.setattr(k8s, "DENY", set())
    _use_fake_client(monkeypatch, raise_exc=httpx.ReadTimeout("таймаут"))
    ok, detail = k8s.delete_pod("svc-6b9f7-x2x1c")
    assert ok is False
    assert "API Kubernetes" in detail


# --- Дисциплина allowlist и denylist до обращения к API ----------------------------------------


def test_rollout_restart_denylist_before_api(monkeypatch):
    """Сервис из denylist не перезапускается и до транспорта дело не доходит."""
    monkeypatch.setattr(k8s, "ALLOWED", {"postgres"})
    monkeypatch.setattr(k8s, "DENY", {"postgres"})
    monkeypatch.setattr(k8s.httpx, "Client", _FakeClient)
    ok, detail = k8s.rollout_restart("postgres", "2026-07-08T00:00:00Z")
    assert ok is False
    assert "denylist" in detail
    assert _FakeClient.calls == []


def test_rollout_restart_not_in_allowlist_before_api(monkeypatch):
    """Сервис не из allowlist не перезапускается и до транспорта дело не доходит."""
    monkeypatch.setattr(k8s, "ALLOWED", set())
    monkeypatch.setattr(k8s, "DENY", set())
    monkeypatch.setattr(k8s.httpx, "Client", _FakeClient)
    ok, detail = k8s.rollout_restart("unknown", "2026-07-08T00:00:00Z")
    assert ok is False
    assert "allowlist" in detail
    assert _FakeClient.calls == []


def test_delete_pod_denylist_before_api(monkeypatch):
    """Под сервиса из denylist не удаляется и до транспорта дело не доходит."""
    monkeypatch.setattr(k8s, "ALLOWED", {"postgres"})
    monkeypatch.setattr(k8s, "DENY", {"postgres"})
    monkeypatch.setattr(k8s.httpx, "Client", _FakeClient)
    ok, detail = k8s.delete_pod("postgres-6b9f7-x2x1c")
    assert ok is False
    assert "denylist" in detail
    assert _FakeClient.calls == []


# --- Валидация имён по DNS-1123 до обращения к API ---------------------------------------------


def test_delete_pod_invalid_name_rejected(monkeypatch):
    """Недопустимое по DNS-1123 имя пода отвергается до любых проверок allowlist и до транспорта."""
    monkeypatch.setattr(k8s.httpx, "Client", _FakeClient)
    ok, detail = k8s.delete_pod("../escape")
    assert ok is False
    assert "недопустимое" in detail
    assert _FakeClient.calls == []


def test_pod_log_tail_invalid_name(monkeypatch):
    """Недопустимое имя пода при чтении лога даёт None без обращения к транспорту."""
    monkeypatch.setattr(k8s.httpx, "Client", _FakeClient)
    monkeypatch.setattr(k8s, "_incluster",
                        lambda: ("https://api.local:443", "token", False))
    assert k8s.pod_log_tail("bad/name") is None
    assert _FakeClient.calls == []


def test_node_stats_summary_invalid_name(monkeypatch):
    """Недопустимое имя узла в сводке kubelet даёт None без обращения к API."""
    called = {"n": 0}

    def _spy(path, **kw):
        called["n"] += 1
        return {}

    monkeypatch.setattr(k8s, "_get_json", _spy)
    assert k8s.node_stats_summary("bad/name") is None
    assert called["n"] == 0


# --- Явные таймауты на всех вызовах httpx ------------------------------------------------------


def test_read_functions_pass_explicit_timeout(monkeypatch):
    """Читающие функции передают явный числовой таймаут в транспорт (защита от зависания на
    недоступном API-сервере)."""
    _use_fake_client(monkeypatch, response=_FakeResponse(json_body={"items": []}))
    k8s._get_json("/api/v1/nodes")
    assert isinstance(_FakeClient.last_timeout, (int, float))
    assert _FakeClient.last_timeout > 0


def test_mutating_functions_pass_explicit_timeout(monkeypatch):
    """Мутирующие функции также передают явный таймаут в транспорт."""
    monkeypatch.setattr(k8s, "ALLOWED", {"svc"})
    monkeypatch.setattr(k8s, "DENY", set())
    _use_fake_client(monkeypatch, response=_FakeResponse(status_code=200))
    k8s.rollout_restart("svc", "2026-07-08T00:00:00Z")
    assert isinstance(_FakeClient.last_timeout, (int, float))
    assert _FakeClient.last_timeout > 0


# --- Дискавери node-agent под единым префиксом AEGIL_ ----------------------------------------


def test_node_agent_discovery_uses_aegil_prefix(monkeypatch):
    """Параметры дискавери node-agent читаются из переменных окружения продукта с префиксом
    AEGIL_ (пространство имён, селектор, порт), а не из наследных беспрефиксных имён."""
    monkeypatch.setenv("AEGIL_NODEAGENT_NAMESPACE", "obs")
    monkeypatch.setenv("AEGIL_NODEAGENT_SELECTOR", "app=custom-agent")
    monkeypatch.setenv("AEGIL_NODEAGENT_PORT", "9200")
    # Наследные беспрефиксные имена не должны влиять на результат.
    monkeypatch.setenv("NODE_AGENT_NAMESPACE", "legacy")
    monkeypatch.setenv("NODE_AGENT_PORT", "1")

    captured = {}

    def _fake_get_json(path, **kw):
        captured["path"] = path
        return {"items": [
            {"spec": {"nodeName": "node-a"}, "status": {"podIP": "10.0.0.7"}},
        ]}

    monkeypatch.setattr(k8s, "_get_json", _fake_get_json)
    monkeypatch.setattr(k8s, "resolve_node", lambda n: "node-a")

    endpoint = k8s.get_node_agent_endpoint("node-a")
    assert endpoint == "http://10.0.0.7:9200"
    assert "namespaces/obs/pods" in captured["path"]
    assert "app=custom-agent" in captured["path"]


def test_node_agent_endpoint_invalid_node(monkeypatch):
    """Недопустимое имя узла отвергается до обращения к API."""
    called = {"n": 0}

    def _spy(path, **kw):
        called["n"] += 1
        return {"items": []}

    monkeypatch.setattr(k8s, "resolve_node", lambda n: "bad/name")
    monkeypatch.setattr(k8s, "_get_json", _spy)
    assert k8s.get_node_agent_endpoint("bad/name") is None
    assert called["n"] == 0
