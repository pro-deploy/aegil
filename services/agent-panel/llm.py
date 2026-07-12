"""Клиент языковой модели с полноценным вызовом инструментов (tool calling).

Единственная точка обращения продукта aegil к языковой модели. Агентный цикл и автопилот
получают клиента внедрением зависимости и ведут через него многошаговый диалог: модель на каждом
шаге либо отвечает текстом, либо запрашивает вызовы инструментов, код исполняет их и возвращает
результаты, и так до завершения. Клиент домен-агностичен и не знает ни о каком приложении.

Поддерживаются два провайдера, выбираемых переменной ``AEGIL_LLM_PROVIDER`` (см. config.py):

  anthropic  Anthropic Messages API через официальный SDK ``anthropic``. По умолчанию. Модель по
             умолчанию ``claude-opus-4-8`` с адаптивным мышлением. Идентификатор модели задаётся
             ``AEGIL_LLM_MODEL``.
  openai     OpenAI-совместимый протокол через SDK ``openai`` (в том числе своя модель в кластере:
             vLLM или Ollama с совместимым эндпоинтом, адрес в ``AEGIL_LLM_BASE_URL``).

Клиент нормализует различия провайдеров: наружу отдаётся единый тип шага ``Turn`` с текстом,
списком запрошенных вызовов инструментов ``ToolCall`` и причиной остановки, а история диалога
ведётся внутри объекта ``Conversation`` в родном формате провайдера. Инструменты описываются
списком словарей ``{"name", "description", "input_schema"}`` (JSON Schema входа) и транслируются в
формат провайдера. Подлежащий SDK-клиент можно внедрить параметром для тестов без сети.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

import config

# Модель по умолчанию для облачного провайдера Anthropic, если оператор не задал свою. Согласно
# актуальному каталогу это самая способная модель линейки Opus.
_DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"
# Верхняя граница длины ответа. Большие значения требуют потокового вывода, чтобы не упереться в
# таймаут HTTP; клиент включает поток автоматически при вызове run(stream=True).
_MAX_TOKENS = 8192


@dataclass
class ToolCall:
    """Запрошенный моделью вызов инструмента. id связывает вызов с его результатом на следующем
    шаге, name это имя инструмента, input это словарь аргументов, разобранный из ответа модели."""
    id: str
    name: str
    input: dict


@dataclass
class Turn:
    """Результат одного шага модели. text это текст, обращённый к оператору (может быть пустым,
    если модель только вызывает инструменты); tool_calls это запрошенные вызовы; stop_reason это
    нормализованная причина остановки: 'tool_use' (нужны результаты инструментов), 'end' (модель
    завершила ответ) либо 'length' (упёрлись в предел длины)."""
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    stop_reason: str = "end"


@dataclass
class Conversation:
    """Ход диалога в родном формате провайдера. Непрозрачен для вызывающего: пополняется только
    методами клиента (send_user, send_tool_results, run). Хранит системную инструкцию, объявление
    инструментов и список сообщений."""
    system: str
    tools: list[dict]
    messages: list[dict] = field(default_factory=list)


class LLMClient(Protocol):
    """Контракт клиента модели, на который опираются агентный цикл и автопилот."""

    def start(self, system: str, tools: list[dict]) -> Conversation: ...

    def send_user(self, conv: Conversation, text: str) -> None: ...

    def send_tool_results(self, conv: Conversation,
                          results: list[tuple[str, str, bool]]) -> None: ...

    def run(self, conv: Conversation, stream: bool = False,
            on_text: Callable[[str], None] | None = None) -> Turn: ...


# ---------------------------------------------------------------------------
# Провайдер Anthropic (Messages API, официальный SDK).
# ---------------------------------------------------------------------------

class AnthropicClient:
    """Клиент поверх Anthropic Messages API. Ведёт диалог в родном формате блоков контента, с
    адаптивным мышлением и полноценным протоколом tool_use и tool_result."""

    def __init__(self, model: str = "", api_key: str = "", base_url: str = "",
                 timeout: float | None = None, sdk_client: Any = None):
        self.model = model or config.LLM_MODEL or _DEFAULT_ANTHROPIC_MODEL
        self._timeout = timeout if timeout is not None else config.LLM_TIMEOUT
        if sdk_client is not None:
            self._client = sdk_client
        else:
            import anthropic  # импорт внутри, чтобы модуль грузился без установленного SDK
            kwargs: dict = {"timeout": self._timeout}
            if api_key or config.LLM_API_KEY:
                kwargs["api_key"] = api_key or config.LLM_API_KEY
            if base_url or config.LLM_BASE_URL:
                kwargs["base_url"] = base_url or config.LLM_BASE_URL
            self._client = anthropic.Anthropic(**kwargs)

    def start(self, system: str, tools: list[dict]) -> Conversation:
        native_tools = [{"name": t["name"], "description": t.get("description", ""),
                         "input_schema": t.get("input_schema", {"type": "object"})} for t in tools]
        return Conversation(system=system, tools=native_tools)

    def send_user(self, conv: Conversation, text: str) -> None:
        conv.messages.append({"role": "user", "content": text})

    def send_tool_results(self, conv: Conversation,
                          results: list[tuple[str, str, bool]]) -> None:
        # Все результаты инструментов одного шага возвращаются одним сообщением пользователя.
        blocks = [{"type": "tool_result", "tool_use_id": tool_id, "content": content,
                   "is_error": is_error} for tool_id, content, is_error in results]
        conv.messages.append({"role": "user", "content": blocks})

    def run(self, conv: Conversation, stream: bool = False,
            on_text: Callable[[str], None] | None = None) -> Turn:
        params: dict = {
            "model": self.model,
            "max_tokens": _MAX_TOKENS,
            "system": conv.system,
            "messages": conv.messages,
            "thinking": {"type": "adaptive"},
        }
        if conv.tools:
            params["tools"] = conv.tools

        if stream:
            with self._client.messages.stream(**params) as s:
                for text_delta in s.text_stream:
                    if on_text:
                        on_text(text_delta)
                message = s.get_final_message()
        else:
            message = self._client.messages.create(**params)

        # Полный список блоков ответа кладём в историю как ход ассистента, чтобы модель на следующем
        # шаге видела свои вызовы инструментов и мышление в неизменном виде.
        conv.messages.append({"role": "assistant", "content": message.content})

        text_parts: list[str] = []
        calls: list[ToolCall] = []
        for block in message.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
            elif btype == "tool_use":
                calls.append(ToolCall(id=block.id, name=block.name, input=dict(block.input)))

        stop = getattr(message, "stop_reason", "end_turn")
        return Turn(text="".join(text_parts), tool_calls=calls,
                    stop_reason=_norm_stop(stop, bool(calls)))


# ---------------------------------------------------------------------------
# Провайдер OpenAI-совместимый (в том числе своя модель в кластере).
# ---------------------------------------------------------------------------

class OpenAICompatibleClient:
    """Клиент поверх OpenAI-совместимого протокола вызова инструментов (chat.completions с полем
    tools). Подходит для своей модели в кластере через vLLM или Ollama с совместимым эндпоинтом."""

    def __init__(self, model: str = "", api_key: str = "", base_url: str = "",
                 timeout: float | None = None, sdk_client: Any = None):
        self.model = model or config.LLM_MODEL
        self._timeout = timeout if timeout is not None else config.LLM_TIMEOUT
        if sdk_client is not None:
            self._client = sdk_client
        else:
            import openai
            kwargs: dict = {"timeout": self._timeout}
            # Локальные серверы часто не требуют ключа, но SDK требует непустую строку.
            kwargs["api_key"] = api_key or config.LLM_API_KEY or "not-needed"
            if base_url or config.LLM_BASE_URL:
                kwargs["base_url"] = base_url or config.LLM_BASE_URL
            self._client = openai.OpenAI(**kwargs)

    def start(self, system: str, tools: list[dict]) -> Conversation:
        native_tools = [{"type": "function", "function": {
            "name": t["name"], "description": t.get("description", ""),
            "parameters": t.get("input_schema", {"type": "object"})}} for t in tools]
        conv = Conversation(system=system, tools=native_tools)
        conv.messages.append({"role": "system", "content": system})
        return conv

    def send_user(self, conv: Conversation, text: str) -> None:
        conv.messages.append({"role": "user", "content": text})

    def send_tool_results(self, conv: Conversation,
                          results: list[tuple[str, str, bool]]) -> None:
        # В OpenAI-протоколе каждый результат это отдельное сообщение роли tool со своим tool_call_id.
        for tool_id, content, _is_error in results:
            conv.messages.append({"role": "tool", "tool_call_id": tool_id, "content": content})

    def run(self, conv: Conversation, stream: bool = False,
            on_text: Callable[[str], None] | None = None) -> Turn:
        params: dict = {"model": self.model, "messages": conv.messages,
                        "max_tokens": _MAX_TOKENS}
        if conv.tools:
            params["tools"] = conv.tools

        # Потоковый разбор вызовов инструментов в OpenAI-протоколе требует сборки дельт; для простоты
        # и надёжности агентного цикла делаем непотоковый запрос, а текст при stream отдаём разом.
        resp = self._client.chat.completions.create(**params)
        choice = resp.choices[0]
        msg = choice.message

        text = msg.content or ""
        if stream and on_text and text:
            on_text(text)

        calls: list[ToolCall] = []
        native_calls = getattr(msg, "tool_calls", None) or []
        for tc in native_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except (json.JSONDecodeError, TypeError):
                args = {}
            calls.append(ToolCall(id=tc.id, name=tc.function.name, input=args))

        # Ход ассистента в историю в родном виде (с tool_calls), чтобы следующий шаг был связным.
        assistant_msg: dict = {"role": "assistant", "content": text}
        if native_calls:
            assistant_msg["tool_calls"] = [
                {"id": tc.id, "type": "function",
                 "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                for tc in native_calls]
        conv.messages.append(assistant_msg)

        return Turn(text=text, tool_calls=calls,
                    stop_reason=_norm_stop(choice.finish_reason, bool(calls)))


def _norm_stop(raw: str | None, has_calls: bool) -> str:
    """Нормализует причину остановки провайдера к 'tool_use', 'length' или 'end'."""
    if has_calls or raw in ("tool_use", "tool_calls"):
        return "tool_use"
    if raw in ("max_tokens", "length"):
        return "length"
    return "end"


def build_client(sdk_client: Any = None) -> LLMClient:
    """Строит клиента модели по конфигурации продукта (AEGIL_LLM_PROVIDER). sdk_client позволяет
    внедрить подлежащий SDK-клиент (для тестов без сети)."""
    provider = config.LLM_PROVIDER
    if provider == "openai":
        return OpenAICompatibleClient(sdk_client=sdk_client)
    return AnthropicClient(sdk_client=sdk_client)


def is_configured() -> bool:
    """Готов ли слой модели к работе: для облака нужен ключ, для своей модели достаточно адреса.
    Если не готов, агентный цикл недоступен и панель работает как исполнитель одиночных команд."""
    if config.LLM_PROVIDER == "openai":
        return bool(config.LLM_BASE_URL)
    return bool(config.LLM_API_KEY)
