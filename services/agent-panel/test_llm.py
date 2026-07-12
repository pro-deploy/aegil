"""Тесты клиента модели с вызовом инструментов. Без сети: подлежащий SDK-клиент подменяется
фейком, воспроизводящим форму ответа провайдера. Проверяется нормализация tool_use и tool_result,
ведение истории диалога и переключение провайдеров.
"""
import os

os.environ.setdefault("SENTINEL_LLM_API_KEY", "test-key")

import llm
from llm import ToolCall, Turn


# --- Фейки SDK ----------------------------------------------------------------------------------

class _Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Msg:
    def __init__(self, content, stop_reason):
        self.content = content
        self.stop_reason = stop_reason


class _FakeAnthropic:
    """Воспроизводит anthropic.Anthropic().messages.create, отдавая заранее заданные ответы."""
    def __init__(self, scripted):
        self._scripted = list(scripted)
        self.calls = []

        class _Messages:
            def __init__(inner):
                inner.outer = self

            def create(inner, **params):
                self.calls.append(params)
                return self._scripted.pop(0)

        self.messages = _Messages()


class _FakeOpenAIMsg:
    def __init__(self, content, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls


class _FakeOpenAIChoice:
    def __init__(self, message, finish_reason):
        self.message = message
        self.finish_reason = finish_reason


class _FakeOpenAIResp:
    def __init__(self, choice):
        self.choices = [choice]


class _FakeOpenAI:
    def __init__(self, scripted):
        self._scripted = list(scripted)
        self.calls = []

        class _Completions:
            def create(inner, **params):
                self.calls.append(params)
                return self._scripted.pop(0)

        class _Chat:
            completions = _Completions()

        self.chat = _Chat()


class _FnCall:
    def __init__(self, id, name, arguments):
        self.id = id
        self.type = "function"

        class _F:
            pass
        self.function = _F()
        self.function.name = name
        self.function.arguments = arguments


# --- Anthropic ----------------------------------------------------------------------------------

def test_anthropic_tool_use_then_end():
    # Первый шаг: модель просит вызвать инструмент. Второй: завершает текстом.
    step1 = _Msg([
        _Block(type="text", text="Смотрю поды."),
        _Block(type="tool_use", id="tu_1", name="observe", input={"argv": ["kubectl", "get", "pods"]}),
    ], stop_reason="tool_use")
    step2 = _Msg([_Block(type="text", text="Готово, всё в порядке.")], stop_reason="end_turn")
    fake = _FakeAnthropic([step1, step2])
    client = llm.AnthropicClient(sdk_client=fake)

    conv = client.start("Ты SRE-агент.", [{"name": "observe", "description": "чтение",
                                            "input_schema": {"type": "object"}}])
    client.send_user(conv, "Проверь поды")
    turn = client.run(conv)

    assert turn.stop_reason == "tool_use"
    assert turn.text == "Смотрю поды."
    assert len(turn.tool_calls) == 1
    tc = turn.tool_calls[0]
    assert tc.id == "tu_1" and tc.name == "observe" and tc.input == {"argv": ["kubectl", "get", "pods"]}

    # Возвращаем результат инструмента и делаем следующий шаг.
    client.send_tool_results(conv, [("tu_1", "3 пода Running", False)])
    turn2 = client.run(conv)
    assert turn2.stop_reason == "end"
    assert turn2.text == "Готово, всё в порядке."

    # История: user, assistant(step1), user(tool_result), assistant(step2).
    assert [m["role"] for m in conv.messages] == ["user", "assistant", "user", "assistant"]
    tool_result_msg = conv.messages[2]
    assert tool_result_msg["content"][0]["type"] == "tool_result"
    assert tool_result_msg["content"][0]["tool_use_id"] == "tu_1"


def test_anthropic_request_shape():
    fake = _FakeAnthropic([_Msg([_Block(type="text", text="ок")], stop_reason="end_turn")])
    client = llm.AnthropicClient(model="claude-opus-4-8", sdk_client=fake)
    conv = client.start("система", [{"name": "act", "input_schema": {"type": "object"}}])
    client.send_user(conv, "сделай")
    client.run(conv)
    params = fake.calls[0]
    assert params["model"] == "claude-opus-4-8"
    assert params["thinking"] == {"type": "adaptive"}
    assert params["tools"][0]["name"] == "act"
    assert params["system"] == "система"


def test_anthropic_streaming_calls_on_text():
    # Поток: text_stream отдаёт куски, get_final_message возвращает финал.
    chunks = ["Ана", "лизирую."]

    class _Stream:
        def __enter__(inner):
            return inner

        def __exit__(inner, *a):
            return False

        @property
        def text_stream(inner):
            return iter(chunks)

        def get_final_message(inner):
            return _Msg([_Block(type="text", text="Анализирую.")], stop_reason="end_turn")

    class _FakeStreaming:
        class messages:
            @staticmethod
            def stream(**params):
                return _Stream()

    client = llm.AnthropicClient(sdk_client=_FakeStreaming())
    conv = client.start("s", [])
    client.send_user(conv, "u")
    seen = []
    turn = client.run(conv, stream=True, on_text=seen.append)
    assert seen == chunks
    assert turn.text == "Анализирую."


# --- OpenAI-совместимый -------------------------------------------------------------------------

def test_openai_tool_use_then_end():
    step1 = _FakeOpenAIResp(_FakeOpenAIChoice(
        _FakeOpenAIMsg(content="Смотрю.", tool_calls=[
            _FnCall("call_1", "observe", '{"argv": ["kubectl", "get", "pods"]}')]),
        finish_reason="tool_calls"))
    step2 = _FakeOpenAIResp(_FakeOpenAIChoice(
        _FakeOpenAIMsg(content="Готово."), finish_reason="stop"))
    fake = _FakeOpenAI([step1, step2])
    client = llm.OpenAICompatibleClient(model="qwen", sdk_client=fake)

    conv = client.start("система", [{"name": "observe", "input_schema": {"type": "object"}}])
    client.send_user(conv, "проверь")
    turn = client.run(conv)
    assert turn.stop_reason == "tool_use"
    assert turn.tool_calls[0].name == "observe"
    assert turn.tool_calls[0].input == {"argv": ["kubectl", "get", "pods"]}

    client.send_tool_results(conv, [("call_1", "3 пода", False)])
    turn2 = client.run(conv)
    assert turn2.stop_reason == "end"
    # История начинается с system, tool-результат это отдельное сообщение роли tool.
    roles = [m["role"] for m in conv.messages]
    assert roles[0] == "system"
    assert "tool" in roles


def test_openai_malformed_arguments_are_safe():
    step = _FakeOpenAIResp(_FakeOpenAIChoice(
        _FakeOpenAIMsg(content="", tool_calls=[_FnCall("c1", "act", "не json")]),
        finish_reason="tool_calls"))
    client = llm.OpenAICompatibleClient(sdk_client=_FakeOpenAI([step]))
    conv = client.start("s", [{"name": "act", "input_schema": {"type": "object"}}])
    client.send_user(conv, "u")
    turn = client.run(conv)
    assert turn.tool_calls[0].input == {}  # мусорные аргументы не роняют разбор


# --- Фабрика и готовность -----------------------------------------------------------------------

def test_build_client_selects_provider(monkeypatch):
    monkeypatch.setattr(llm.config, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(llm.config, "LLM_BASE_URL", "http://vllm:8000/v1")
    c = llm.build_client(sdk_client=_FakeOpenAI([]))
    assert isinstance(c, llm.OpenAICompatibleClient)

    monkeypatch.setattr(llm.config, "LLM_PROVIDER", "anthropic")
    c2 = llm.build_client(sdk_client=_FakeAnthropic([]))
    assert isinstance(c2, llm.AnthropicClient)


def test_is_configured(monkeypatch):
    monkeypatch.setattr(llm.config, "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(llm.config, "LLM_API_KEY", "k")
    assert llm.is_configured()
    monkeypatch.setattr(llm.config, "LLM_API_KEY", "")
    assert not llm.is_configured()
    monkeypatch.setattr(llm.config, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(llm.config, "LLM_BASE_URL", "http://x")
    assert llm.is_configured()


if __name__ == "__main__":
    import sys
    # Мини-раннер без pytest для быстрой самопроверки (monkeypatch-тесты пропускаются).
    fns = [(k, v) for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v) and "monkeypatch" not in v.__code__.co_varnames]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print(f"ok   {name}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {name}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed (monkeypatch-тесты только под pytest)")
    sys.exit(1 if failed else 0)
