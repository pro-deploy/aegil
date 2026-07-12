"""Формулировка отчёта на естественном языке. По центральному принципу языковая
модель отвечает только за язык: она облекает УЖЕ посчитанный детерминированный
вердикт в читаемый отчёт и
ничего не считает и не выдумывает. Гард сохраняется: в промпте модели запрещено
добавлять факты сверх приведённых. При недоступности модели работает мягкая
деградация к детерминированной текстовой сводке из вердикта.

Вызов модели инъектируется как llm_complete(prompt)->str (обёртка над llm-сервисом),
что делает модуль пригодным для проверки без сети.
"""
from __future__ import annotations

import json
import re

_INSTRUCTION = (
    "Ты пишешь краткий отчёт об инциденте для инженера на русском языке. Используй "
    "ТОЛЬКО приведённые ниже посчитанные факты, первопричину, свидетельства и "
    "действие. Ничего не добавляй и не выдумывай, не придумывай числа и имена. Если "
    "какого-то поля нет, не упоминай его. Верни связный отчёт из нескольких "
    "предложений без разметки."
)


def deterministic_summary(verdict: dict) -> str:
    """Текстовая сводка вердикта без языковой модели (фолбэк мягкой деградации)."""
    status = verdict.get("status")
    if status == "healthy":
        return "Инцидент не обнаружен: значимого сигнала в окне нет."
    conf = verdict.get("confidence", {}) or {}
    rc = verdict.get("root_cause") or "первопричина не установлена"
    action = verdict.get("action") or "действие не определено"
    n = len(verdict.get("evidence", []) or [])
    return (
        f"Статус: {status}. Уверенность: {conf.get('value')} ({conf.get('band')}). "
        f"Первопричина: {rc}. Рекомендация: {action}. Свидетельств: {n}."
    )


# Жёсткие токены, которые модель не имеет права вносить сверх приведённых фактов:
# числа, адреса, версии, порты (любой токен с цифрой) и латинские технические имена
# (Postgres, Redis, CUDA и подобные). Русская связующая проза не ограничивается.
_HARD_TOKEN = re.compile(r"[0-9][\w.:\-]*|[A-Za-z][\w.\-]*\d[\w.\-]*|[A-Z][A-Za-z]{2,}")


# Разбиение контекста на самостоятельные жёсткие токены той же природы, что и в
# тексте отчёта. Заземление проверяется по РАВЕНСТВУ токенов, а не по вхождению
# подстроки. Прежняя подстрочная проверка была дырявой: число «10» считалось
# заземлённым любой строкой, содержащей эти цифры (например любым таймстампом или
# длинным идентификатором), из-за чего модель могла безнаказанно вносить выдуманные
# числа. Токенная проверка требует, чтобы ровно такой токен встретился в контексте.


def _hard_tokens(text: str) -> set:
    return {t.lower() for t in _HARD_TOKEN.findall(text or "")}


def _grounding_tokens(verdict: dict, facts: dict | None) -> set:
    """Строит множество заземлённых жёстких токенов из всех источников: вердикт, срез
    фактов и дословные фрагменты реестра свидетельств."""
    parts = [json.dumps(verdict, ensure_ascii=False)]
    if facts is not None:
        parts.append(json.dumps(facts, ensure_ascii=False, default=str))
    for e in verdict.get("evidence", []) or []:
        parts.append(str(e.get("snippet", "")))
    return _hard_tokens(" ".join(parts))


def is_grounded(text: str, verdict: dict, facts: dict | None = None) -> bool:
    """Гард «нет цитаты, нет утверждения» для естественного языка: каждый жёсткий токен
    отчёта (число, адрес, версия, латинское тех-имя) обязан присутствовать в контексте
    заземления КАК ОТДЕЛЬНЫЙ ТОКЕН, а не как подстрока. Иначе отчёт признаётся
    выдуманным и отбраковывается."""
    grounded = _grounding_tokens(verdict, facts)
    for tok in _hard_tokens(text):
        if tok not in grounded:
            return False
    return True


def build_prompt(verdict: dict, facts: dict | None = None) -> str:
    """Собирает промпт для модели: инструкция плюс уже посчитанные факты и вердикт."""
    context = {"verdict": verdict}
    if facts is not None:
        # Передаём компактный срез фактов, без сырых списков латентностей.
        context["facts"] = {k: facts[k] for k in (
            "total_lines", "level_counts", "error_rate", "symptom_counts",
            "status_classes", "blast_radius", "time_span") if k in facts}
    return _INSTRUCTION + "\n\nДАННЫЕ (JSON):\n" + json.dumps(context, ensure_ascii=False)


def formulate(verdict: dict, facts: dict | None = None, llm_complete=None) -> dict:
    """Возвращает отчёт. Без llm_complete или при его сбое, детерминированная сводка;
    иначе просит модель облечь факты в текст, но принимает ответ ТОЛЬКО если он заземлён
    (is_grounded): модель, добавившая числа, адреса или имена сверх фактов, отбраковывается
    и заменяется детерминированной сводкой. source указывает источник отчёта, а reason
    поясняет отбраковку для наблюдаемости."""
    det = deterministic_summary(verdict)
    if llm_complete is None:
        return {"report": det, "source": "deterministic"}
    try:
        text = llm_complete(build_prompt(verdict, facts))
        text = str(text).strip() if text else ""
        if text:
            if is_grounded(text, verdict, facts):
                return {"report": text, "source": "model"}
            return {"report": det, "source": "deterministic", "reason": "model_output_ungrounded"}
    except Exception:
        pass
    return {"report": det, "source": "deterministic"}
