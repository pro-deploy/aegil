"""Клиент сервиса детерминированного разбора логов (RCA). Панель и автопилот обращаются к RCA
только через эти функции. Адрес RCA задаётся вызывающим (переменная RCA_URL), поэтому продукт не
привязан к конкретному развёртыванию. Контракт RCA: POST /analyze телом с окном анализа возвращает
факты, детекторы, скоринг и вердикт; POST /stuck возвращает вердикт по застрявшим единицам работы."""
from __future__ import annotations

import httpx

# Короткие речевые ярлыки статуса вердикта для озвучивания в панели.
_STATUS_SPEECH = {"healthy": "инцидент не обнаружен", "degraded": "деградация",
                  "incident": "инцидент"}


def analyze(rca_url: str, payload: dict) -> dict:
    """Разбор окна логов: возвращает {facts, detectors, score, verdict, report}."""
    with httpx.Client(timeout=60.0) as c:
        r = c.post(f"{rca_url.rstrip('/')}/analyze", json=payload)
        r.raise_for_status()
        return r.json()


def stuck(rca_url: str) -> dict:
    """Вердикт по застрявшим единицам работы (очередь, зависшие задачи)."""
    with httpx.Client(timeout=30.0) as c:
        r = c.post(f"{rca_url.rstrip('/')}/stuck")
        r.raise_for_status()
        return r.json()


def verdict_payload(out: dict) -> dict:
    """Структурированный вердикт для карточки панели плюс краткая речевая сводка speech."""
    v = out.get("verdict", {}) or {}
    f = out.get("facts", {}) or {}
    conf = v.get("confidence", {}) or {}
    rep = out.get("report", {}) or {}
    status = v.get("status")
    evidence = [{"source": e.get("source"), "snippet": str(e.get("snippet", ""))}
                for e in (v.get("evidence") or [])[:6]]
    speech = [f"Статус: {_STATUS_SPEECH.get(status, status or '')}."]
    if v.get("root_cause"):
        speech.append(str(v["root_cause"]) + ".")
    if v.get("action"):
        speech.append(str(v["action"]) + ".")
    return {
        "type": "verdict",
        "status": status,
        "confidence": conf.get("value"),
        "band": conf.get("band"),
        "root_cause": v.get("root_cause"),
        "action": v.get("action"),
        "evidence": evidence,
        "report": rep.get("report"),
        "lines": f.get("total_lines"),
        "detectors": v.get("detectors") or [],
        "speech": " ".join(speech),
    }
