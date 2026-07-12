"""Подключение открытых серверов Model Context Protocol (MCP) как дополнительных инструментов агента.

Смысл: не писать клиент к каждой внешней системе руками, а подключить готовый открытый сервер MCP.
Наиболее ценно для широты диагноза, то есть для читающих серверов наблюдаемости (Grafana, Prometheus,
Loki, Tempo): с ними агент видит метрики, трассы и дашборды, а не только логи и состояние кластера.

Безопасность. Инструменты MCP это СТРУКТУРИРОВАННЫЕ вызовы, а не список аргументов, поэтому
детерминированный классификатор policy.classify (который разбирает argv) к ним напрямую неприменим.
Чтобы не пробить защитную модель продукта, действует консервативное правило: сервер, ЯВНО помеченный
оператором как read_only, отдаёт только читающие инструменты, которые агент исполняет свободно; любой
сервер без этой пометки (по умолчанию) считается потенциально мутирующим, и вызов его инструмента
требует подтверждения оператора через тот же механизм отложенного подтверждения, что и опасные команды.
Так сохраняется инвариант: ни одна мутация не исполняется автономно в обход гейта.

Конфигурация в переменной SENTINEL_MCP_SERVERS: JSON-список объектов
  {"name": "grafana", "url": "http://grafana-mcp:8000/mcp", "read_only": true, "token": "..."}
name задаёт пространство имён инструмента (mcp__<name>__<tool>), url это эндпоинт MCP по протоколу
Streamable HTTP, read_only разрешает свободное исполнение (по умолчанию false, fail-safe), token
необязателен (уходит в заголовок Authorization при обращении к серверу).

Транспорт живого подключения вынесен за интерфейс синхронного «вызывателя» и опционален: если пакет
mcp не установлен или сервер недоступен, он просто пропускается, а панель работает без него. Вся
логика реестра, пространства имён и гейтинга тестируется на фейковом вызывателе без сети.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable

_SANITIZE = re.compile(r"[^a-zA-Z0-9_]")


@dataclass
class ServerCfg:
    name: str
    url: str
    read_only: bool = False
    token: str = ""


@dataclass
class MCPTool:
    """Инструмент MCP, представленный агенту. name это пространственно-именованное имя для модели
    (mcp__<server>__<tool>), raw_name это исходное имя инструмента на сервере, read_only определяет,
    можно ли исполнять его без подтверждения оператора."""
    name: str
    raw_name: str
    server: str
    description: str
    input_schema: dict
    read_only: bool
    _caller: Any = field(default=None, repr=False)


def load_config(raw: str | None = None) -> list[ServerCfg]:
    """Разбирает SENTINEL_MCP_SERVERS в список конфигураций серверов. Пустое или мусорное значение
    даёт пустой список (MCP выключен)."""
    raw = raw if raw is not None else os.getenv("SENTINEL_MCP_SERVERS", "")
    raw = raw.strip()
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except json.JSONDecodeError:
        print("mcp_tools: SENTINEL_MCP_SERVERS не разобран как JSON, MCP выключен", flush=True)
        return []
    out: list[ServerCfg] = []
    for it in items if isinstance(items, list) else []:
        name = str(it.get("name", "")).strip()
        url = str(it.get("url", "")).strip()
        if not name or not url:
            continue
        out.append(ServerCfg(name=name, url=url,
                             read_only=bool(it.get("read_only", False)),
                             token=str(it.get("token", ""))))
    return out


def _ns(server: str, tool: str) -> str:
    return f"mcp__{_SANITIZE.sub('_', server)}__{_SANITIZE.sub('_', tool)}"


def is_mcp_tool(name: str) -> bool:
    return str(name or "").startswith("mcp__")


class MCPRegistry:
    """Реестр инструментов MCP: их схемы для модели, поиск по имени, исполнение через вызыватель
    сервера. Полностью синхронен; асинхронность живого транспорта скрыта внутри вызывателя."""

    def __init__(self):
        self._tools: dict[str, MCPTool] = {}

    def add(self, tool: MCPTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> MCPTool | None:
        return self._tools.get(name)

    def schemas(self) -> list[dict]:
        """Схемы инструментов в формате, который принимает клиент модели (llm.py)."""
        out = []
        for t in self._tools.values():
            note = "" if t.read_only else " (мутация: исполняется только с подтверждения оператора)"
            out.append({"name": t.name, "description": (t.description or t.raw_name) + note,
                        "input_schema": t.input_schema or {"type": "object"}})
        return out

    def call(self, name: str, args: dict) -> dict:
        """Исполняет инструмент MCP и возвращает результат словарём {text} либо {error}. Мягкая
        деградация: недоступный сервер даёт ошибку шага, а не падение."""
        tool = self._tools.get(name)
        if not tool or tool._caller is None:
            return {"error": f"инструмент MCP «{name}» не найден"}
        try:
            text = tool._caller.call_tool(tool.raw_name, args or {})
            return {"text": str(text)}
        except Exception as e:  # noqa: BLE001 честная ошибка шага
            return {"error": f"ошибка вызова инструмента MCP «{name}»: {e}"}

    def __len__(self) -> int:
        return len(self._tools)


def build_registry(session_factory: Callable[[ServerCfg], Any] | None = None,
                   config: list[ServerCfg] | None = None) -> MCPRegistry:
    """Строит реестр по конфигурации: для каждого сервера получает список инструментов через
    вызыватель и регистрирует их с пространством имён. Недоступный сервер пропускается с сигналом.
    session_factory(cfg) возвращает объект с методами list_tools() -> list[dict] и
    call_tool(raw_name, args) -> str; по умолчанию используется живой транспорт поверх SDK mcp,
    для тестов внедряется фейк."""
    reg = MCPRegistry()
    cfgs = config if config is not None else load_config()
    factory = session_factory or _default_factory
    for cfg in cfgs:
        try:
            caller = factory(cfg)
            tools = caller.list_tools()
        except Exception as e:  # noqa: BLE001 сервер недоступен, продолжаем без него
            print(f"mcp_tools: сервер «{cfg.name}» недоступен, пропущен: {e}", flush=True)
            continue
        for t in tools or []:
            raw = str(t.get("name", "")).strip()
            if not raw:
                continue
            reg.add(MCPTool(name=_ns(cfg.name, raw), raw_name=raw, server=cfg.name,
                            description=str(t.get("description", "")),
                            input_schema=t.get("input_schema") or {"type": "object"},
                            read_only=cfg.read_only, _caller=caller))
    return reg


# ---------------------------------------------------------------------------
# Живой транспорт (опционален): синхронный вызыватель поверх асинхронного SDK mcp.
# ---------------------------------------------------------------------------

class _LiveCaller:
    """Синхронный вызыватель к серверу MCP по Streamable HTTP. Каждая операция открывает сессию,
    выполняет initialize и запрос, закрывает сессию. Простота важнее эффективности для запросов
    наблюдаемости; асинхронность SDK скрыта за asyncio.run."""

    def __init__(self, cfg: ServerCfg):
        self.cfg = cfg

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.cfg.token}"} if self.cfg.token else {}

    def list_tools(self) -> list[dict]:
        import asyncio
        return asyncio.run(self._alist())

    def call_tool(self, raw_name: str, args: dict) -> str:
        import asyncio
        return asyncio.run(self._acall(raw_name, args))

    async def _session(self):
        from mcp import ClientSession
        from mcp.client.streamable_http import streamablehttp_client
        return ClientSession, streamablehttp_client

    async def _alist(self) -> list[dict]:
        ClientSession, streamablehttp_client = await self._session()
        async with streamablehttp_client(self.cfg.url, headers=self._headers()) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.list_tools()
                out = []
                for t in res.tools:
                    schema = getattr(t, "inputSchema", None) or {"type": "object"}
                    out.append({"name": t.name, "description": t.description or "",
                                "input_schema": schema})
                return out

    async def _acall(self, raw_name: str, args: dict) -> str:
        ClientSession, streamablehttp_client = await self._session()
        async with streamablehttp_client(self.cfg.url, headers=self._headers()) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
                res = await s.call_tool(raw_name, args)
                parts = []
                for block in getattr(res, "content", []) or []:
                    text = getattr(block, "text", None)
                    if text:
                        parts.append(text)
                return "\n".join(parts) if parts else str(res)


def _default_factory(cfg: ServerCfg) -> _LiveCaller:
    return _LiveCaller(cfg)
