"""Тесты подключения серверов MCP как инструментов агента. Без сети: живой транспорт не трогается,
вызыватель сервера подменяется фейком. Проверяется разбор конфигурации, пространство имён, схемы
для модели, пометка read_only и исполнение через реестр.
"""
import mcp_tools
from mcp_tools import ServerCfg


class _FakeCaller:
    def __init__(self, cfg, tools, results=None):
        self.cfg = cfg
        self._tools = tools
        self._results = results or {}
        self.calls = []

    def list_tools(self):
        return self._tools

    def call_tool(self, raw_name, args):
        self.calls.append((raw_name, args))
        if raw_name in self._results:
            r = self._results[raw_name]
            if isinstance(r, Exception):
                raise r
            return r
        return "результат"


def _factory(tools, results=None):
    return lambda cfg: _FakeCaller(cfg, tools, results)


def test_load_config_valid():
    raw = '[{"name":"grafana","url":"http://g/mcp","read_only":true,"token":"t"}]'
    cfgs = mcp_tools.load_config(raw)
    assert len(cfgs) == 1
    assert cfgs[0].name == "grafana" and cfgs[0].read_only is True and cfgs[0].token == "t"


def test_load_config_empty_and_garbage():
    assert mcp_tools.load_config("") == []
    assert mcp_tools.load_config("не json") == []
    assert mcp_tools.load_config('[{"name":"","url":""}]') == []  # пустые пропускаются


def test_build_registry_namespacing_and_readonly():
    tools = [{"name": "query", "description": "запрос метрик", "input_schema": {"type": "object"}}]
    reg = mcp_tools.build_registry(session_factory=_factory(tools),
                                   config=[ServerCfg("prometheus", "http://p/mcp", read_only=True)])
    assert len(reg) == 1
    t = reg.get("mcp__prometheus__query")
    assert t is not None and t.read_only is True and t.raw_name == "query" and t.server == "prometheus"


def test_schemas_marks_mutating():
    tools = [{"name": "apply", "description": "меняет", "input_schema": {"type": "object"}}]
    reg = mcp_tools.build_registry(session_factory=_factory(tools),
                                   config=[ServerCfg("m", "http://m/mcp", read_only=False)])
    sch = reg.schemas()[0]
    assert sch["name"] == "mcp__m__apply"
    assert "подтвержд" in sch["description"].lower()  # пометка про подтверждение оператора


def test_call_success_and_error():
    tools = [{"name": "ok", "input_schema": {}}, {"name": "bad", "input_schema": {}}]
    reg = mcp_tools.build_registry(
        session_factory=_factory(tools, results={"ok": "12 подов", "bad": RuntimeError("сеть")}),
        config=[ServerCfg("s", "http://s/mcp", read_only=True)])
    assert reg.call("mcp__s__ok", {}) == {"text": "12 подов"}
    err = reg.call("mcp__s__bad", {})
    assert "error" in err and "сеть" in err["error"]
    assert "error" in reg.call("mcp__s__missing", {})  # неизвестный инструмент


def test_unavailable_server_skipped():
    def bad_factory(cfg):
        raise ConnectionError("недоступен")
    reg = mcp_tools.build_registry(session_factory=bad_factory,
                                   config=[ServerCfg("x", "http://x/mcp")])
    assert len(reg) == 0  # недоступный сервер просто пропущен, без падения


def test_is_mcp_tool():
    assert mcp_tools.is_mcp_tool("mcp__grafana__query")
    assert not mcp_tools.is_mcp_tool("observe")


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
