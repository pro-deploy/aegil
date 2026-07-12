"""Запись размеченных примеров маршрутизации в Postgres для сервиса разбора
первопричин aegil. Пример состоит из запроса инженера и веток, размеченных
большой моделью-учителем при эскалации каскада. Тренер (сервис rca-trainer) позже
дообучает на накопленных примерах лёгкий классификатор SetFit.

Запись выполнена как best-effort и не должна ронять маршрутизацию: при отсутствии
драйвера, недоступности базы или сбое подключения пример не сохраняется, а сама
маршрутизация продолжается штатно (мягкая деградация). При этом сбой записи больше не
глушится молча: каждая неудача журналируется на уровне warning, чтобы потеря примеров
была обнаружима в наблюдаемости, а не проходила незаметно.

Адрес базы берётся из переменной окружения AEGIL_POSTGRES_DSN согласно единому
префиксу конфигурации продукта (docs/CONVENTIONS.md). Используется тот же кластерный
Postgres, что и у тренера и у инструмента засева.

Соединение с базой переиспользуется между вызовами: оно открывается один раз лениво и
хранится на уровне модуля, а при обрыве переоткрывается на следующем вызове. Это
устраняет открытие нового подключения на каждый записываемый пример, которое при
активном обучении создавало заметную нагрузку на базу.
"""
from __future__ import annotations

import logging
import os
import threading

DSN = os.getenv("AEGIL_POSTGRES_DSN", "")

_log = logging.getLogger("rca.store")

# Определение таблицы примеров маршрутизации. Схема создаётся идемпотентно при первом
# обращении, чтобы сервис поднимался на чистой базе без внешнего шага миграции.
# Уникальный индекс по нормализованному тексту примера обеспечивает идемпотентность
# засева и записи на стороне базы (см. seed_load.py и ON CONFLICT ниже).
_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS rca_route_examples (
        id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        query       text NOT NULL,
        labels      text[] NOT NULL,
        source      text NOT NULL DEFAULT 'llm',
        query_norm  text GENERATED ALWAYS AS (lower(btrim(query))) STORED,
        created_at  timestamptz NOT NULL DEFAULT now(),
        trained_at  timestamptz
    )
    """,
    "CREATE UNIQUE INDEX IF NOT EXISTS rca_route_examples_query_norm_uq "
    "ON rca_route_examples (query_norm)",
)

# Определение таблицы исходов ремонтов. Замыкает контур активного обучения на фактических
# результатах устранения инцидентов: успешно устранённый инцидент становится размеченным
# примером (отпечаток симптома, статус вердикта, первопричина и применённое действие, признак
# фактического устранения), пригодным для последующего дообучения. Схема создаётся идемпотентно
# при первом обращении тем же приёмом, что и у таблицы примеров маршрутизации, чтобы сервис
# поднимался на чистой базе без внешнего шага миграции.
_OUTCOME_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS repair_outcomes (
        id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        fingerprint    text NOT NULL,
        verdict_status text,
        root_cause     text,
        action         text,
        resolved       boolean NOT NULL DEFAULT false,
        created_at     timestamptz NOT NULL DEFAULT now()
    )
    """,
    "CREATE INDEX IF NOT EXISTS repair_outcomes_fingerprint_idx "
    "ON repair_outcomes (fingerprint)",
)

# Переиспользуемое соединение и мьютекс для безопасного доступа из нескольких потоков
# веб-сервера. psycopg2-соединение не является потокобезопасным, поэтому запись
# сериализуется коротким мьютексом; это дешевле, чем открывать соединение на пример.
_conn = None
_conn_lock = threading.Lock()
_schema_ready = False


def _connect(dsn):
    import psycopg2

    return psycopg2.connect(dsn)


def _get_conn(connect):
    """Возвращает живое переиспользуемое соединение, при необходимости открывая его и
    создавая схему. При обрыве прежнее соединение закрывается и открывается новое."""
    global _conn, _schema_ready
    if _conn is not None:
        if getattr(_conn, "closed", 0):
            _conn = None
            _schema_ready = False
        else:
            return _conn
    _conn = connect(DSN)
    if not _schema_ready:
        with _conn, _conn.cursor() as cur:
            for stmt in (*_SCHEMA, *_OUTCOME_SCHEMA):
                cur.execute(stmt)
        _schema_ready = True
    return _conn


def _reset_conn() -> None:
    """Сбрасывает кэшированное соединение, чтобы следующий вызов открыл новое."""
    global _conn, _schema_ready
    try:
        if _conn is not None:
            _conn.close()
    except Exception:
        pass
    _conn = None
    _schema_ready = False


def record_example(query: str, labels: list, source: str = "llm", connect=None) -> bool:
    """Сохраняет пример в rca_route_examples. Возвращает True при успехе.

    Параметр connect позволяет подменить способ открытия соединения (для модульных
    тестов без сети); по умолчанию используется psycopg2.connect. Запись идемпотентна
    на стороне базы: повторный пример с тем же нормализованным текстом не создаёт
    дубликата за счёт ON CONFLICT по уникальному индексу query_norm."""
    if not DSN or not query or not labels:
        return False
    connect = connect or _connect
    with _conn_lock:
        try:
            conn = _get_conn(connect)
            with conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO rca_route_examples (query, labels, source) "
                    "VALUES (%s, %s, %s) ON CONFLICT (query_norm) DO NOTHING",
                    (query, list(labels), source),
                )
            return True
        except Exception as e:
            # Сбой записи журналируется, а не гасится молча: иначе потеря обучающих
            # примеров была бы необнаружима. Соединение сбрасывается, чтобы обрыв не
            # закрепился на все последующие вызовы.
            _log.warning("не удалось записать пример маршрутизации: %s", e)
            _reset_conn()
            return False


def record_outcome(dsn, fingerprint, status, root_cause, action, resolved, connect=None) -> bool:
    """Записывает исход ремонта инцидента в таблицу repair_outcomes и возвращает True при
    успехе. Замыкает контур активного обучения на фактических результатах устранения:
    каждый разрешённый инцидент фиксируется как размеченный пример (отпечаток симптома,
    статус вердикта, первопричина, применённое действие и признак фактического устранения),
    пригодный для последующего дообучения.

    Параметр dsn присутствует ради явности контракта вызова со стороны веб-слоя; фактически
    адрес базы берётся из того же модульного значения AEGIL_POSTGRES_DSN, что и у записи
    примеров маршрутизации, поэтому переиспользуется общее ленивое соединение под мьютексом.
    Параметр connect позволяет подменить способ открытия соединения в модульных тестах без
    сети; по умолчанию используется psycopg2.connect.

    Запись best-effort и не должна ронять вызывающего: при отсутствии драйвера, недоступности
    базы, сбое подключения или пустом отпечатке исход не сохраняется, а сама работа
    продолжается штатно. Сбой при этом не гасится молча, а журналируется на уровне warning,
    чтобы потеря размеченных примеров была обнаружима в наблюдаемости."""
    if not DSN or not fingerprint:
        return False
    connect = connect or _connect
    with _conn_lock:
        try:
            conn = _get_conn(connect)
            with conn, conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO repair_outcomes "
                    "(fingerprint, verdict_status, root_cause, action, resolved) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (fingerprint, status, root_cause, action, bool(resolved)),
                )
            return True
        except Exception as e:
            # Сбой журналируется, а не гасится молча: иначе потеря размеченного исхода
            # ремонта прошла бы незаметно. Соединение сбрасывается, чтобы обрыв не закрепился
            # на все последующие вызовы.
            _log.warning("не удалось записать исход ремонта: %s", e)
            _reset_conn()
            return False


def outcomes_stats(dsn, connect=None) -> dict:
    """Возвращает сводку по накопленным исходам ремонтов для наблюдаемости: общее число
    записей, число фактически устранённых (resolved) и число неустранённых (failed).

    Как и у record_outcome, параметр dsn присутствует ради явности контракта, а адрес базы
    фактически берётся из модульного значения AEGIL_POSTGRES_DSN. Чтение best-effort:
    при недоступности базы возвращается нулевая сводка с пометкой недоступности, а сбой
    журналируется на уровне warning, а не гасится молча."""
    empty = {"total": 0, "resolved": 0, "failed": 0, "available": False}
    if not DSN:
        return empty
    connect = connect or _connect
    with _conn_lock:
        try:
            conn = _get_conn(connect)
            with conn, conn.cursor() as cur:
                cur.execute(
                    "SELECT count(*), "
                    "count(*) FILTER (WHERE resolved), "
                    "count(*) FILTER (WHERE NOT resolved) "
                    "FROM repair_outcomes"
                )
                total, resolved, failed = cur.fetchone()
            return {"total": int(total), "resolved": int(resolved),
                    "failed": int(failed), "available": True}
        except Exception as e:
            _log.warning("не удалось прочитать сводку исходов ремонтов: %s", e)
            _reset_conn()
            return empty
