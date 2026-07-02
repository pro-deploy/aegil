"""Адаптер управляемого приложения. Ядро продукта домен-агностично, но у автопилота есть
плейбуки уровня B, которые обращаются к прикладному слою управления (например «вернуть застрявшую
единицу работы в очередь», «приостановить приём», «снизить параллелизм»). Такие действия
специфичны для конкретного приложения, поэтому вынесены сюда за необязательный HTTP-адаптер.

Если APP_ADMIN_URL не задан, адаптер выключен: вызовы возвращают честный отказ, а не выдумывают
результат, и агент опирается только на инфраструктурный ремонт (перезапуск сервисов, чистка узла).
Адоптер, желающий дать агенту прикладные действия, указывает APP_ADMIN_URL и APP_ADMIN_TOKEN и
реализует у себя соответствующие эндпоинты; контракт совместим с прежним привилегированным слоём
(заголовки X-Admin-Token и X-Admin-Operator).

Функции stats_by_node и tls_days_left generic (сводка kubelet и срок TLS-сертификата) и работают
всегда. GPU_NODE это дружеское имя узла для наблюдения, задаётся окружением и по умолчанию пусто."""
from __future__ import annotations

import os
import time

import httpx

import k8s

APP_ADMIN_URL = os.getenv("APP_ADMIN_URL", "").rstrip("/")
APP_ADMIN_TOKEN = os.getenv("APP_ADMIN_TOKEN", "")
TLS_HOST = os.getenv("TLS_HOST", "")
GPU_NODE = os.getenv("GPU_NODE", "")

_TLS_TTL_SECONDS = 24 * 3600
_TLS_CACHE = [0.0, None]


def enabled() -> bool:
    """Включён ли прикладной адаптер (задан ли адрес и токен)."""
    return bool(APP_ADMIN_URL and APP_ADMIN_TOKEN)


def admin_post(path: str, payload: dict, operator: str):
    """Вызов прикладного действия. Возвращает (ok, detail). None при выключенном адаптере."""
    if not enabled():
        return None, "прикладной адаптер выключен (APP_ADMIN_URL/APP_ADMIN_TOKEN не заданы)"
    try:
        with httpx.Client(timeout=30.0) as c:
            r = c.post(f"{APP_ADMIN_URL}{path}",
                       headers={"X-Admin-Token": APP_ADMIN_TOKEN, "X-Admin-Operator": operator},
                       json=payload)
    except Exception as e:
        return False, f"ошибка вызова приложения: {e}"
    if r.status_code in (200, 201):
        return True, "выполнено"
    return False, f"приложение вернуло {r.status_code}"


def admin_get(path: str):
    """Чтение прикладного эндпоинта. None при выключенном адаптере или недоступности."""
    if not enabled():
        return None
    try:
        with httpx.Client(timeout=15.0) as c:
            r = c.get(f"{APP_ADMIN_URL}{path}", headers={"X-Admin-Token": APP_ADMIN_TOKEN})
            r.raise_for_status()
            return r.json()
    except Exception:
        return None


def stats_by_node(nodes) -> dict:
    """Сводки kubelet по всем узлам: имя узла ведёт к сводке или None (kubelet молчит)."""
    if not nodes:
        return {}
    return {n["name"]: k8s.node_stats_summary(n["name"]) for n in nodes}


def tls_days_left():
    """Дней до истечения сертификата TLS_HOST; None если хост не задан или недоступен. Раз в сутки."""
    if not TLS_HOST:
        return None
    now = time.time()
    if now - _TLS_CACHE[0] < _TLS_TTL_SECONDS:
        return _TLS_CACHE[1]
    days = None
    try:
        import socket
        import ssl
        from datetime import datetime, timezone
        ctx = ssl.create_default_context()
        with socket.create_connection((TLS_HOST, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=TLS_HOST) as ss:
                cert = ss.getpeercert()
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = int((exp - datetime.now(timezone.utc)).total_seconds() // 86400)
    except Exception:
        days = None
    _TLS_CACHE[0], _TLS_CACHE[1] = now, days
    return days
