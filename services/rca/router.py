"""Маршрутизация запроса инженера по диагностическим веткам. Шесть веток: логи,
алерты, сеть и порты, аномалии, зависимости и топология, релизы и изменения. Запрос
может относиться сразу к нескольким веткам (мультиметочный случай).

Маршрутизацию выполняет лёгкий обученный классификатор (SetFit). Здесь
задан подключаемый интерфейс классификатора и детерминированный ключевой фолбэк,
который работает без модели (мягкая деградация): при отсутствии обученного
классификатора запрос относится к веткам по ключевым словам, а при отсутствии
совпадений, к основной ветке логов.
"""
from __future__ import annotations

import re

BRANCHES = ("logs", "alerts", "network", "anomalies", "dependencies", "releases")

# Ключевые слова по веткам (русский и английский), нижним регистром.
_KEYWORDS = {
    "logs": ("лог", "ошиб", "error", "исключен", "exception", "стектрейс", "traceback"),
    "alerts": ("алерт", "alert", "триггер", "monitoring", "монитор", "prometheus", "zabbix", "grafana"),
    "network": ("сет", "network", "порт", "port", "connection", "refused", "таймаут",
                "timeout", "dns", "tcp", "eof", "deadline"),
    "anomalies": ("аномал", "anomaly", "всплеск", "spike", "выброс", "необычн", "отклонен"),
    "dependencies": ("зависим", "depend", "топологи", "topolog", "граф", "upstream",
                     "downstream", "каскад", "cascade", "сервис вызыва"),
    "releases": ("релиз", "release", "депло", "deploy", "изменени", "change", "выкат",
                 "мердж", "merge", "commit", "коммит", "верси"),
}


# Совпадение по границе слова: ключ должен начинать слово, чтобы «лог» не срабатывал
# внутри «топологии», «каталога», «аналога» и подобных.
_BRANCH_RE = {
    b: re.compile(r"(?<![0-9a-zа-яё])(?:" + "|".join(re.escape(k) for k in kws) + r")")
    for b, kws in _KEYWORDS.items()
}


class KeywordRouter:
    """Детерминированный ключевой классификатор веток (фолбэк без модели)."""

    def predict(self, query: str) -> list[str]:
        q = (query or "").lower()
        hits = [b for b in BRANCHES if _BRANCH_RE[b].search(q)]
        return hits or ["logs"]


def route(query: str, classifier=None) -> list[str]:
    """Возвращает ветки для запроса. classifier — обученный классификатор с методом
    predict(query)->list[str] (например SetFit); при None используется ключевой
    фолбэк. Результат упорядочен по канону BRANCHES и не пуст."""
    clf = classifier or KeywordRouter()
    labels = set(clf.predict(query) or [])
    ordered = [b for b in BRANCHES if b in labels]
    return ordered or ["logs"]
