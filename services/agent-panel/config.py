"""Конфигурация продукта: всё, что раньше было зашито под конкретное приложение (имена сервисов,
роли узлов, списки допустимых и запрещённых к перезапуску сервисов, пороги алертов, эндпоинты),
вынесено сюда и управляется переменными окружения. Так один и тот же образ агент-панели
подключается к любому кластеру и к любому приложению без правки кода. Значения по умолчанию
нейтральны и не привязаны ни к какому приложению.

Переменные окружения:
  RCA_URL                адрес сервиса разбора логов (по умолчанию http://rca:9107)
  LLM_SERVICE_URL        адрес языковой модели (см. llm.py)
  NAMESPACE              пространство имён Kubernetes для наблюдения и действий (default: default)
  RESTART_ALLOWLIST      безсостоятельные сервисы, которые агент может перезапускать (через запятую)
  RESTART_DENYLIST       сервисы, перезапуск которых запрещён (хранилища, особые поды)
  NODE_ROLE_LABEL        метка роли узла для дружеских имён (default: node-role.kubernetes.io/role)
  ALERT_DISK_WARN        порог заполнения диска, предупреждение (default: 80)
  ALERT_DISK_CRIT        порог заполнения диска, критично (default: 90)
  AGENT_AUTONOMOUS       1 включает автономный ремонт, иначе только наблюдение и эскалации
"""
from __future__ import annotations

import os


def _csv(name: str, default: str) -> set:
    raw = os.getenv(name, default)
    return {x.strip() for x in raw.split(",") if x.strip()}


# Пространство имён и адреса внешних систем.
NAMESPACE = os.getenv("NAMESPACE", "default")
RCA_URL = os.getenv("RCA_URL", "http://rca:9107").rstrip("/")

# Управление перезапусками. Пусто по умолчанию: без явного списка агент никого не перезапускает
# автономно, что безопасно для незнакомого кластера. Адоптер перечисляет свои безсостоятельные
# сервисы в RESTART_ALLOWLIST и хранилища в RESTART_DENYLIST.
RESTART_ALLOWLIST = _csv("RESTART_ALLOWLIST", "")
RESTART_DENYLIST = _csv("RESTART_DENYLIST", "postgres,redis,minio,etcd,vault")

# Метка роли узла для дружеских имён («control», «gpu» и т. п.) в командах оператора.
NODE_ROLE_LABEL = os.getenv("NODE_ROLE_LABEL", "node-role.kubernetes.io/role")

# Пороги алертов (проценты заполнения диска и прочее выносится по мере обобщения детекторов).
ALERT_DISK_WARN = int(os.getenv("ALERT_DISK_WARN", "80"))
ALERT_DISK_CRIT = int(os.getenv("ALERT_DISK_CRIT", "90"))

# Автономный ремонт. По умолчанию выключен: сухой прогон (наблюдение и эскалации), чтобы на новом
# кластере агент сперва показал, что БЫ он сделал, и лишь затем ему разрешают действовать.
AGENT_AUTONOMOUS = os.getenv("AGENT_AUTONOMOUS", "").strip() in ("1", "true", "yes")
