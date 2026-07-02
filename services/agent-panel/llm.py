"""Клиент языковой модели продукта. Единственная точка обращения к LLM: агентный цикл, автопилот
и формулировка вердикта получают функцию complete через внедрение зависимости. Эндпоинт задаётся
переменной окружения LLM_SERVICE_URL и по умолчанию не привязан ни к какому приложению, поэтому
продукт подключается к любой OpenAI-совместимой или локальной модели (например vLLM или Ollama
через тонкий прокси, отдающий {"text": ...} на POST /completion)."""
from __future__ import annotations

import os

import httpx

LLM_SERVICE_URL = os.getenv("LLM_SERVICE_URL", "http://llm:9102").rstrip("/")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "60"))


def complete(prompt: str) -> str:
    """Возвращает текстовое завершение модели по промпту. Контракт совместим с прежним прокси:
    POST {LLM_SERVICE_URL}/completion телом {"prompt": ...}, ответ {"text": ...}."""
    with httpx.Client(timeout=LLM_TIMEOUT) as c:
        r = c.post(f"{LLM_SERVICE_URL}/completion", json={"prompt": prompt})
        r.raise_for_status()
        return r.json().get("text", "")
