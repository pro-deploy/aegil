"""Читатель окна логов из Loki для анализатора первопричин.

Приёмник домен-агностичен и принимает две формы строки лога одновременно. Если
строка это объект JSON, её поля берутся как есть (структурный лог приложения).
Если строка это произвольный текст, что и есть обычный вид лога подов Kubernetes,
то есть стектрейсы, panic, сообщения OOM-killer, уровень серьёзности выводится
эвристически из текста, а сам текст сохраняется как сообщение. Тем самым движок
видит логи любого приложения, а не только один конкретный структурный канон.
Раньше записью считался только внутренний JSON-конверт наследной платформы,
поэтому текстовые логи были невидимы для всех детекторов, и на чужом кластере
движок был слеп по своей главной функции.

Каждая запись несёт временную метку самого Loki (поле _ts_ns, наносекунды эпохи)
и исходную строку (поле _raw) для дословного цитирования в реестре свидетельств.
Сортировка ведётся по метке времени Loki, а не по лексикографическому сравнению
строкового поля, которого во внешнем логе может не быть вовсе.

Конфигурация берётся из переменных окружения с единым префиксом SENTINEL_. Адрес
Loki из SENTINEL_LOKI_URL, селектор потоков из SENTINEL_LOKI_QUERY (по умолчанию
селектор по наблюдаемому пространству имён без зашитого имени приложения). Окно
читается с направлением backward и пагинируется, чтобы конец окна, где обычно и
лежит инцидент, не терялся молча при упоре в лимит выборки.
"""
from __future__ import annotations

import json
import os
import time

import httpx

from normalize import infer_level

LOKI_URL = os.getenv("SENTINEL_LOKI_URL", "http://loki:3100").rstrip("/")

# Наблюдаемое пространство имён. По умолчанию селектор строится по нему, без зашитого
# имени приложения заказчика (соглашение о доменной нейтральности).
NAMESPACE = os.getenv("SENTINEL_NAMESPACE", "default")
DEFAULT_QUERY = os.getenv("SENTINEL_LOKI_QUERY", '{namespace="%s"}' % NAMESPACE)

# Раздельные таймауты соединения и чтения тела: медленный источник не должен
# бесконечно держать анализ, но и не должен рваться на первой же секунде.
CONNECT_TIMEOUT = float(os.getenv("SENTINEL_LOKI_CONNECT_TIMEOUT", "5"))
READ_TIMEOUT = float(os.getenv("SENTINEL_LOKI_READ_TIMEOUT", "30"))

# Размер страницы выборки и потолок числа страниц. Пагинация идёт назад по времени
# от конца окна, поэтому первые же страницы несут самые свежие строки инцидента.
PAGE_LIMIT = int(os.getenv("SENTINEL_LOKI_PAGE_LIMIT", "5000"))
MAX_PAGES = int(os.getenv("SENTINEL_LOKI_MAX_PAGES", "20"))


class LokiError(RuntimeError):
    """Ошибка обращения к Loki (недоступность, тайм-аут, некорректный ответ)."""


def _parse(line: str, ts_ns: int) -> dict:
    """Разбирает одну строку лога Loki в запись.

    Если строка это объект JSON, его поля берутся как есть, а недостающий уровень
    выводится из сообщения эвристикой. Если строка это произвольный текст, она
    целиком становится сообщением, уровень выводится из текста. В обоих случаях
    сохраняются метка времени Loki (_ts_ns) и исходная строка (_raw)."""
    rec: dict
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        obj = None
    if isinstance(obj, dict):
        rec = dict(obj)
        # Уровень: берём из поля, если оно есть и осмысленно, иначе выводим из текста
        # сообщения. Так структурный лог без поля level всё равно получает уровень.
        if not str(rec.get("level", "")).strip():
            probe = str(rec.get("msg", "")) or line
            rec["level"] = infer_level(probe)
    else:
        # Произвольная текстовая строка лога пода: уровень и сообщение из самого текста.
        rec = {"msg": line, "level": infer_level(line)}
    rec["_raw"] = line
    rec["_ts_ns"] = int(ts_ns)
    return rec


def _query_page(client: httpx.Client, query: str, start_ns: int, end_ns: int,
                limit: int) -> list[tuple[int, str]]:
    """Забирает одну страницу строк за [start_ns, end_ns] с направлением backward.
    Возвращает список пар (метка времени в наносекундах, строка), как отдал Loki."""
    params = {
        "query": query,
        "start": str(start_ns),
        "end": str(end_ns),
        "limit": str(limit),
        "direction": "backward",
    }
    try:
        r = client.get(f"{LOKI_URL}/loki/api/v1/query_range", params=params)
        r.raise_for_status()
        data = r.json()
    except httpx.HTTPError as exc:
        raise LokiError(f"обращение к Loki не удалось: {exc}") from exc
    except (ValueError, TypeError) as exc:
        raise LokiError(f"некорректный ответ Loki: {exc}") from exc
    rows: list[tuple[int, str]] = []
    for stream in data.get("data", {}).get("result", []):
        for value in stream.get("values", []):
            try:
                ts_ns, line = int(value[0]), value[1]
            except (IndexError, ValueError, TypeError):
                continue
            rows.append((ts_ns, line))
    return rows


def fetch_window(query: str = DEFAULT_QUERY, minutes: int = 60,
                 limit: int = PAGE_LIMIT, end: float | None = None) -> list[dict]:
    """Возвращает записи окна [end-minutes, end], отсортированные по времени Loki.

    end это Unix-время в секундах (по умолчанию текущее). Для базовой линии подаётся
    end со сдвигом назад. Окно читается страницами с направлением backward: конец
    окна, где обычно лежит инцидент, забирается первым и не теряется при упоре в лимит.
    Пагинация идёт назад по времени до опустошения окна или до потолка числа страниц.
    При недоступности Loki поднимается LokiError, которую вызывающий слой должен
    обработать явно, а не отдавать голый отказ сервера."""
    end_ns = int((end if end is not None else time.time()) * 1e9)
    start_ns = end_ns - int(minutes * 60 * 1e9)
    page_limit = max(1, int(limit))

    records: list[dict] = []
    seen: set[tuple[int, str]] = set()
    cursor_end = end_ns
    timeout = httpx.Timeout(READ_TIMEOUT, connect=CONNECT_TIMEOUT)
    with httpx.Client(timeout=timeout) as client:
        for _page in range(MAX_PAGES):
            rows = _query_page(client, query, start_ns, cursor_end, page_limit)
            if not rows:
                break
            min_ts = cursor_end
            new_in_page = 0
            for ts_ns, line in rows:
                key = (ts_ns, line)
                if key in seen:
                    continue
                seen.add(key)
                records.append(_parse(line, ts_ns))
                new_in_page += 1
                if ts_ns < min_ts:
                    min_ts = ts_ns
            # Условие остановки: страница не полна (окно вычерпано) либо не принесла
            # ни одной новой строки (защита от зацикливания на одинаковых метках).
            if len(rows) < page_limit or new_in_page == 0:
                break
            # Следующая страница строго старше самой старой строки текущей, чтобы не
            # перечитывать её повторно. Наносекунда сдвига исключает пограничный повтор.
            cursor_end = min_ts - 1
            if cursor_end <= start_ns:
                break

    records.sort(key=lambda rec: rec.get("_ts_ns", 0))
    return records
