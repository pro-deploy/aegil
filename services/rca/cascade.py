"""Каскад маршрутизации с активным обучением (ADR-0032, Часть B; книга Биркина,
глава 10.6). Лёгкий классификатор SetFit относит запрос к веткам с уверенностью;
если уверенность ниже порога, запрос эскалируется к большой модели (Gemma 4), её
решение возвращается и записывается новым размеченным примером, на котором тренер
позже дообучит SetFit. При отсутствии модели и при сбоях работает детерминированный
ключевой фолбэк (мягкая деградация).

Все зависимости инъектируются (обученный классификатор, вызов большой модели,
запись примера), поэтому логика проверяется модульно без сети и без ML-библиотек.
"""
from __future__ import annotations

import json
import re

from router import BRANCHES, route

ESCALATION_THRESHOLD = 0.65


def _normalize(labels) -> list:
    """Оставляет только валидные ветки в каноническом порядке."""
    s = {str(x) for x in (labels or [])}
    return [b for b in BRANCHES if b in s]


def build_route_prompt(query: str) -> str:
    """Промпт большой модели-учителю: вернуть строго JSON-массив подходящих веток."""
    return (
        "Ты классифицируешь запрос инженера по диагностическим веткам. Доступные "
        "ветки: " + ", ".join(BRANCHES) + ". Верни СТРОГО JSON-массив подходящих "
        "веток из этого списка, без пояснений и без текста вокруг. Запрос: " + query
    )


def parse_route_labels(text: str) -> list:
    """Извлекает ветки из ответа модели: первый JSON-массив, отфильтрованный по канону."""
    if not text:
        return []
    m = re.search(r"\[.*?\]", text, re.S)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
    except (ValueError, TypeError):
        return []
    if not isinstance(arr, list):
        return []
    return _normalize(arr)


def classify_and_learn(query: str, setfit=None, llm_complete=None, recorder=None,
                       threshold: float = ESCALATION_THRESHOLD):
    """Маршрутизирует запрос с активным обучением. Возвращает (labels, source), где
    source это setfit | llm | keyword.

    setfit: объект с predict_with_confidence(query)->(labels, confidence) или None.
    llm_complete: вызов большой модели llm_complete(prompt)->str (учитель).
    recorder: запись примера recorder(query, labels, source) в хранилище.
    """
    # 1. Обученный классификатор, если уверен.
    if setfit is not None:
        try:
            labels, conf = setfit.predict_with_confidence(query)
        except Exception:
            labels, conf = None, 0.0
        norm = _normalize(labels)
        if norm and conf >= threshold:
            return norm, "setfit"

    # 2. Эскалация к большой модели-учителю с записью примера.
    if llm_complete is not None:
        try:
            labels = parse_route_labels(llm_complete(build_route_prompt(query)))
        except Exception:
            labels = []
        if labels:
            if recorder is not None:
                try:
                    recorder(query, labels, "llm")
                except Exception:
                    pass
            return labels, "llm"

    # 3. Детерминированный ключевой фолбэк (мягкая деградация).
    return route(query), "keyword"
