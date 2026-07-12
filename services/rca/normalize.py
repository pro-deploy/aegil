"""Нормализация лог-сообщения в шаблон и извлечение симптомов из произвольного
текста лога пода Kubernetes.

Модуль решает две задачи, обе домен-агностичные и без внешних зависимостей.

Первая задача, историческая: свёртка похожих сообщений в один шаблон (идея Drain3
без внешней библиотеки). Переменные части (идентификаторы, адреса, числа)
маскируются, чтобы схожие события считались одним шаблоном, а агрегатор мог
посчитать доминирующие паттерны и их долю. Порядок масок важен: сначала более
специфичные (uuid, ip, длинный hex), затем общие числа, иначе число внутри адреса
схлопнется преждевременно.

Вторая задача, ключевая для универсального приёма логов: извлечение уровня
серьёзности и сетевых и прочих симптомов эвристически из ПРОИЗВОЛЬНОЙ текстовой
строки лога. Раньше эти сведения брались только из полей чужого структурного
канона (level, error_signal), из-за чего обычные текстовые логи подов Kubernetes,
то есть стектрейсы, panic, сообщения OOM-killer, были невидимы для всего движка.
Теперь уровень и симптомы выводятся из текста напрямую, поэтому движок видит логи
любого приложения без предварительной структуры.
"""
from __future__ import annotations

import re

_UUID = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HEX = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_NUM = re.compile(r"\b\d+")  # без замыкающей границы, чтобы ловить «30s» -> «<num>s»


def template(msg: str) -> str:
    """Возвращает шаблон сообщения с замаскированными переменными частями."""
    if not msg:
        return ""
    s = _UUID.sub("<uuid>", msg)
    s = _IP.sub("<ip>", s)
    s = _HEX.sub("<hex>", s)
    s = _NUM.sub("<num>", s)
    return s


# Эвристика уровня серьёзности по тексту строки. Проверяется по убыванию тяжести:
# первый сработавший маркер задаёт уровень. Маркеры подобраны так, чтобы покрыть
# распространённые в экосистеме Kubernetes формы: паника языка Go, фатальные сбои,
# сообщения OOM-killer ядра, стандартные заголовки уровней и стектрейсы Python.
_LEVEL_PATTERNS = (
    ("fatal", re.compile(
        r"\b(fatal|panic|out\s?of\s?memory|oomkill(?:ed|er)?|segfault|"
        r"core\s?dump(?:ed)?|kernel\s?panic|terminated)\b|signal\s?SIGKILL", re.I)),
    ("error", re.compile(
        r"\b(error|err|exception|traceback|stack\s?trace|failed|failure|"
        r"fatal_error|refused|denied|unable\s+to|cannot|crash(?:ed|loopbackoff)?|"
        r"unhandled)\b", re.I)),
    ("warn", re.compile(r"\b(warn(?:ing)?|deprecat(?:ed|ion)|retry(?:ing)?|throttl(?:e|ed|ing))\b", re.I)),
    ("debug", re.compile(r"\b(debug|trace)\b", re.I)),
)


def infer_level(text: str) -> str:
    """Выводит уровень серьёзности из произвольной текстовой строки лога. При
    отсутствии явных маркеров возвращает info. Домен-агностична: опирается на общие
    формы серьёзных сообщений, а не на конкретный логирующий канон приложения."""
    if not text:
        return "info"
    for level, pat in _LEVEL_PATTERNS:
        if pat.search(text):
            return level
    return "info"


# Каталог сетевых и инфраструктурных симптомов, извлекаемых прямо из текста строки.
# Ключ это устойчивое имя симптома (совпадает с ранее использовавшимися значениями
# чужого поля error_signal, чтобы верхний слой вердикта работал единообразно). Значение
# это регулярное выражение над нижним регистром текста. Каталог покрывает реальные
# сообщения библиотек Go, Python, ядра Linux и типовых прокси без привязки к домену.
_SYMPTOM_PATTERNS = {
    "connection_refused": re.compile(r"connection\s+refused|econnrefused|dial\s+tcp.*refused", re.I),
    "connection_reset": re.compile(r"connection\s+reset|econnreset|reset\s+by\s+peer|broken\s+pipe|epipe", re.I),
    "dns_error": re.compile(r"no\s+such\s+host|name\s+resolution|dns\s+(?:error|lookup|resolution)|"
                            r"could\s+not\s+resolve|servfail|nxdomain", re.I),
    "tls_error": re.compile(r"tls\s+handshake|x509|certificate\s+(?:verify|expired|invalid|unknown)|"
                            r"ssl\s+error|handshake\s+failure", re.I),
    "timeout": re.compile(r"\btimed?\s?out\b|\btimeout\b|etimedout|i/o\s+timeout", re.I),
    "deadline_exceeded": re.compile(r"deadline\s+exceeded|context\s+deadline", re.I),
    "context_canceled": re.compile(r"context\s+cancell?ed|request\s+cancell?ed|client\s+disconnected", re.I),
    "oom": re.compile(r"out\s?of\s?memory|oomkill(?:ed|er)?|cannot\s+allocate\s+memory|"
                      r"memoryerror|killed\s+process.*out\s+of\s+memory", re.I),
    "disk_full": re.compile(r"no\s+space\s+left|disk\s+full|enospc|quota\s+exceeded|"
                            r"write\s+failed.*space", re.I),
    "crashloop": re.compile(r"crashloopbackoff|back-?off\s+restarting|restart(?:ing|ed)\s+failed\s+container", re.I),
    "image_pull_error": re.compile(r"imagepullbackoff|errimagepull|failed\s+to\s+pull\s+image", re.I),
    "permission_denied": re.compile(r"permission\s+denied|access\s+denied|forbidden|unauthorized|eacces", re.I),
}


def extract_symptoms(text: str) -> set:
    """Извлекает множество имён симптомов из произвольной строки лога. Пусто, если
    ни один маркер не встретился. Симптомы домен-агностичны: это универсальные формы
    инфраструктурных отказов, а не поля конкретного приложения."""
    if not text:
        return set()
    return {name for name, pat in _SYMPTOM_PATTERNS.items() if pat.search(text)}


# Множества классов симптомов, нужные слоям детекторов и вердикта. Держим их здесь,
# рядом с каталогом, чтобы источник истины был один.
NETWORK_SIGNALS = frozenset({
    "connection_refused", "connection_reset", "dns_error", "tls_error",
    "timeout", "deadline_exceeded",
})

# Первичные физические отказы вызова (локус это вызываемая цель).
CALL_PRIMARY = frozenset({"connection_refused", "connection_reset", "dns_error", "tls_error"})
# Первичные физические отказы самого пода (локус это сам эмитент).
SELF_PRIMARY = frozenset({"oom", "disk_full", "crashloop", "image_pull_error"})
PRIMARY_SIGNALS = CALL_PRIMARY | SELF_PRIMARY
# Вторичная волна отмен: приходит сверху по графу вызовов, корнем не является.
SECONDARY_SIGNALS = frozenset({"context_canceled", "deadline_exceeded", "timeout"})
