"""Необязательный адаптер управляемого приложения.

Ядро продукта aegil домен-агностично: оно не знает заранее ни имён сервисов заказчика, ни
топологии его кластера и выясняет их через API Kubernetes и через конфигурацию, заданную владельцем.
Тем не менее у владельца может существовать прикладной уровень управления, доступный по протоколу
HTTP, у которого имеются собственные обратимые операции, специфичные именно для его приложения. Такие
операции невозможно описать заранее в универсальном каталоге, поэтому они вынесены за необязательный
адаптер: если владелец задаёт адрес и токен своего прикладного административного интерфейса, панель
получает возможность читать его состояние и вызывать его действия, а если не задаёт, адаптер честно
выключен и панель опирается только на инфраструктурный ремонт средствами самого Kubernetes.

Вся настройка адаптера идёт через переменные окружения с единым префиксом ``AEGIL_``.
``AEGIL_APP_ADMIN_URL`` и ``AEGIL_APP_ADMIN_TOKEN`` задают адрес и токен прикладного
интерфейса, ``AEGIL_TLS_HOST`` задаёт хост, для которого измеряется остаток срока действия
сертификата TLS. Никаких зашитых имён узлов, сервисов или доменов здесь нет.

Функции ``stats_by_node`` (сводка kubelet по узлам) и ``tls_days_left`` (остаток срока действия
сертификата TLS для заданного хоста) являются универсальными и работают всегда, независимо от того,
включён ли прикладной адаптер.
"""
from __future__ import annotations

import os
import time

import httpx

import k8s

# Прикладной административный интерфейс приложения владельца. Пустые значения означают, что адаптер
# выключен и панель опирается только на инфраструктурный ремонт средствами Kubernetes.
APP_ADMIN_URL = os.getenv("AEGIL_APP_ADMIN_URL", "").rstrip("/")
APP_ADMIN_TOKEN = os.getenv("AEGIL_APP_ADMIN_TOKEN", "")

# Хост, для которого измеряется остаток срока действия сертификата TLS. Пусто по умолчанию: если хост
# не задан, срок сертификата не измеряется и не показывается.
TLS_HOST = os.getenv("AEGIL_TLS_HOST", "")

_TLS_TTL_SECONDS = 24 * 3600
_TLS_CACHE = [0.0, None]


def enabled() -> bool:
    """Включён ли прикладной адаптер, то есть заданы ли адрес и токен прикладного интерфейса."""
    return bool(APP_ADMIN_URL and APP_ADMIN_TOKEN)


def admin_post(path: str, payload: dict, operator: str):
    """Вызывает обратимое прикладное действие. Возвращает пару (ok, detail). При выключенном адаптере
    возвращает (None, причина), честно сообщая, что действие недоступно, а не выдумывая результат."""
    if not enabled():
        return None, ("прикладной адаптер выключен: не заданы AEGIL_APP_ADMIN_URL или "
                      "AEGIL_APP_ADMIN_TOKEN")
    try:
        with httpx.Client(timeout=30.0) as c:
            r = c.post(f"{APP_ADMIN_URL}{path}",
                       headers={"X-Admin-Token": APP_ADMIN_TOKEN, "X-Admin-Operator": operator},
                       json=payload)
    except Exception as e:  # noqa: BLE001 недоступность приложения не должна ронять панель
        return False, f"ошибка вызова приложения: {e}"
    if r.status_code in (200, 201):
        return True, "выполнено"
    return False, f"приложение вернуло {r.status_code}"


def admin_get(path: str):
    """Читает состояние прикладного эндпоинта. Возвращает None при выключенном адаптере, а также при
    недоступности приложения (мягкая деградация, единообразно с прочими читающими функциями)."""
    if not enabled():
        return None
    try:
        with httpx.Client(timeout=15.0) as c:
            r = c.get(f"{APP_ADMIN_URL}{path}", headers={"X-Admin-Token": APP_ADMIN_TOKEN})
            r.raise_for_status()
            return r.json()
    except Exception:  # noqa: BLE001
        return None


def stats_by_node(nodes) -> dict:
    """Собирает сводки kubelet по всем узлам кластера: имя узла соответствует его сводке либо None,
    если kubelet узла не отвечает (само по себе диагностический признак). Возвращает пустой словарь,
    если список узлов недоступен."""
    if not nodes:
        return {}
    return {n["name"]: k8s.node_stats_summary(n["name"]) for n in nodes}


def tls_days_left():
    """Возвращает число суток до истечения сертификата TLS для хоста AEGIL_TLS_HOST. Возвращает
    None, если хост не задан или недоступен. Измерение выполняется не чаще раза в сутки за счёт
    кэша, потому что срок сертификата меняется медленно."""
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
    except Exception:  # noqa: BLE001 недоступность хоста не должна ронять наблюдение
        days = None
    _TLS_CACHE[0], _TLS_CACHE[1] = now, days
    return days
