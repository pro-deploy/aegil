"""Конфигурация продукта kube-sentinel.

Вся настройка, которая отличает одно развёртывание от другого (пространство имён, адреса внешних
систем, списки допустимых к перезапуску сервисов, защищаемые ресурсы, уровень автономии, доступ к
языковой модели), вынесена сюда и управляется переменными окружения с единым префиксом
``SENTINEL_``. Один и тот же образ панели подключается к любому кластеру и к любому приложению без
правки кода. Значения по умолчанию нейтральны и не привязаны ни к какому приложению; соглашения
описаны в ``docs/CONVENTIONS.md``.
"""
from __future__ import annotations

import os

# Уровни автономии. observe: сухой прогон, только наблюдение и предложения. safe_repair: автономно
# исполняется read и safe_write, destructive и защищённые шаблоны за подтверждением. full: автономно
# всё, кроме destructive и защищённых шаблонов, которые требуют подтверждения всегда.
AUTONOMY_OBSERVE = "observe"
AUTONOMY_SAFE_REPAIR = "safe_repair"
AUTONOMY_FULL = "full"
_AUTONOMY_LEVELS = (AUTONOMY_OBSERVE, AUTONOMY_SAFE_REPAIR, AUTONOMY_FULL)


def _env(name: str, default: str = "") -> str:
    """Значение переменной окружения продукта с обрезкой пробелов."""
    return os.getenv(name, default).strip()


def _csv(name: str, default: str = "") -> set[str]:
    """Множество непустых значений из переменной окружения, перечисленных через запятую."""
    return {x.strip() for x in os.getenv(name, default).split(",") if x.strip()}


def _int(name: str, default: int) -> int:
    """Целочисленная переменная окружения с устойчивостью к пустому и мусорному значению."""
    raw = _env(name)
    try:
        return int(raw)
    except ValueError:
        return default


# --- Пространство имён и внешние системы ---------------------------------------------------------

# Наблюдаемое и управляемое пространство имён. По умолчанию берётся из downward API (переменную
# SENTINEL_NAMESPACE в манифесте заполняет fieldRef metadata.namespace), иначе default.
NAMESPACE = _env("SENTINEL_NAMESPACE") or "default"

# Сервис детерминированного разбора логов.
RCA_URL = (_env("SENTINEL_RCA_URL") or "http://rca:9107").rstrip("/")

# --- Языковая модель -----------------------------------------------------------------------------

# Провайдер протокола вызова инструментов: anthropic (по умолчанию) или openai-совместимый. Модель,
# ключ и, при своей модели в кластере, базовый адрес задаются владельцем. Пустой ключ означает, что
# агентный цикл недоступен и панель работает как исполнитель одиночных команд оператора.
LLM_PROVIDER = (_env("SENTINEL_LLM_PROVIDER") or "anthropic").lower()
LLM_MODEL = _env("SENTINEL_LLM_MODEL")
LLM_API_KEY = _env("SENTINEL_LLM_API_KEY")
LLM_BASE_URL = _env("SENTINEL_LLM_BASE_URL").rstrip("/")
LLM_TIMEOUT = _int("SENTINEL_LLM_TIMEOUT", 120)

# --- Узловой агент -------------------------------------------------------------------------------

NODEAGENT_TOKEN = _env("SENTINEL_NODEAGENT_TOKEN")
NODEAGENT_TIMEOUT = _int("SENTINEL_NODEAGENT_TIMEOUT", 30)

# --- Политика и автономия ------------------------------------------------------------------------

# Безсостоятельные сервисы, которые агент может перезапускать автономно. Пусто по умолчанию: на
# незнакомом кластере агент никого не перезапускает, пока владелец не перечислит свои сервисы.
RESTART_ALLOWLIST = _csv("SENTINEL_RESTART_ALLOWLIST")
# Сервисы, перезапуск которых запрещён всегда (хранилища и особые поды).
RESTART_DENYLIST = _csv("SENTINEL_RESTART_DENYLIST", "postgres,redis,minio,etcd,vault")

# Защищаемые ресурсы и пути: действия над ними всегда требуют подтверждения оператора независимо от
# уровня автономии. Заменяет наследный доменный класс finance. Владелец вносит сюда свои
# production-базы, тома и критичные пути; по умолчанию пусто.
PROTECTED_PATTERNS = _csv("SENTINEL_PROTECTED_PATTERNS")

# Метка роли узла для дружеских имён в командах оператора. Если метки нет, агент оперирует именами
# узлов как есть; зашитых имён узлов в продукте нет.
NODE_ROLE_LABEL = _env("SENTINEL_NODE_ROLE_LABEL") or "node-role.kubernetes.io/role"


def autonomy() -> str:
    """Текущий уровень автономии из окружения. Недопустимое значение трактуется как observe
    (самый безопасный уровень, fail-safe)."""
    level = _env("SENTINEL_AUTONOMY").lower()
    return level if level in _AUTONOMY_LEVELS else AUTONOMY_OBSERVE
