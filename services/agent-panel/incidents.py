"""Центр инцидентов панели администратора (ADR-0033, ADR-0038). Складывает вердикты RCA в
ленту и группирует одинаковые инциденты в одну запись со счётчиком повторов, чтобы поток не
захлёбывался дублями. Два инцидента считаются одинаковыми, если совпадают статус, набор
сработавших детекторов и первопричина с замаскированными числами (отпечаток).

Жизненный цикл группы (ADR-0038): new (зарегистрирован, никто не занимался), auto_fixing
(агент выполняет попытку устранения), resolved_auto (агент устранил, проверка подтвердила),
resolved_operator (оператор устранил кнопкой «Решить» или командой), escalated (агент не смог
или не имел права, требует внимания оператора), acknowledged (оператор взял в работу).

Инциденты никогда не удаляются. Повторное появление отпечатка после resolved открывает НОВУЮ
группу со ссылкой на прежнюю (поле reopened_from), а не воскрешает старую: история остаётся
честной, а счётчик переоткрытий сам по себе сигнал хронической проблемы.

Хранилище append-only JSONL, нарезанное помесячно (incidents-YYYY-MM.log.jsonl), чтобы один
файл не рос бесконечно. При старте лента восстанавливается повтором событий из всех файлов;
для совместимости сначала читается старый единый файл incidents.log.jsonl, если он есть.

Хранилище и разделяемое состояние потокобезопасны. Автопилот работает в отдельном потоке
параллельно обработчикам FastAPI, поэтому дозапись в файл и любое изменение разделяемых словарей
групп выполняются под единственной реентерабельной блокировкой _LOCK. Без неё конкурентные
upsert из такта агента и из обработчика теряли бы данные и перемешивали строки в журнале.

Каталог журнала выносится за пределы рабочего дерева агента на постоянный том (по умолчанию
каталог данных SENTINEL_STATE_DIR, обычно /data; конкретные пути переопределяются переменными
SENTINEL_INCIDENTS и SENTINEL_INCIDENTS_DIR).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path


def _state_dir() -> Path:
    """Каталог данных вне рабочего дерева. По умолчанию /data (постоянный том), переопределяется
    переменной SENTINEL_STATE_DIR."""
    return Path(os.getenv("SENTINEL_STATE_DIR", "/data"))


# Старый единый журнал (совместимость): читается при старте, если существует. Новые события
# в него не пишутся. Явный SENTINEL_INCIDENTS имеет приоритет, иначе файл в каталоге данных.
STORE_PATH = Path(os.getenv("SENTINEL_INCIDENTS") or str(_state_dir() / "incidents.log.jsonl"))
# Каталог помесячных журналов. Явный SENTINEL_INCIDENTS_DIR имеет приоритет, иначе каталог
# рядом со старым единым файлом.
STORE_DIR = Path(os.getenv("SENTINEL_INCIDENTS_DIR") or str(STORE_PATH.parent))

# Реентерабельная блокировка на весь модуль: сериализует изменение разделяемых словарей групп и
# дозапись в журнал между потоком автопилота и обработчиками FastAPI. Реентерабельность нужна,
# потому что публичные функции вызывают друг друга под уже взятой блокировкой (например,
# purge_noise вызывает set_lifecycle).
_LOCK = threading.RLock()

# Статусы жизненного цикла группы (ADR-0038, раздел 3 спецификации).
LIFECYCLES = ("new", "auto_fixing", "resolved_auto", "resolved_operator",
              "escalated", "acknowledged")
# Решённые статусы: повторение отпечатка после них открывает новую группу.
RESOLVED = ("resolved_auto", "resolved_operator")

_DIGITS = re.compile(r"\d+")
_groups: dict = {}   # идентификатор группы -> группа
_active: dict = {}   # ключ отпечатка -> идентификатор последней (актуальной) группы


def _now() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".%03dZ" % int((t % 1) * 1000)


def _mask(s: str) -> str:
    return _DIGITS.sub("#", s or "")


def fingerprint(verdict: dict) -> str:
    """Отпечаток инцидента: статус, набор детекторов, первопричина без чисел. Одинаковый
    отпечаток означает один и тот же инцидент, повторившийся во времени."""
    status = str(verdict.get("status", ""))
    dets = ",".join(sorted(verdict.get("detectors") or []))
    rc = _mask(str(verdict.get("root_cause") or ""))
    return f"{status}|{dets}|{rc}"


def _month_path(ts: str) -> Path:
    """Помесячный файл журнала по метке времени события (первые семь знаков ISO: YYYY-MM)."""
    return STORE_DIR / f"incidents-{ts[:7]}.log.jsonl"


def _append(rec: dict) -> None:
    """Дозапись события в помесячный журнал. Вызывается только под _LOCK, поэтому конкурентные
    записи из разных потоков не перемешивают строки."""
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    with _month_path(rec["ts"]).open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _apply(verdict: dict, ts: str) -> tuple:
    """Учитывает один вердикт. Обновляет актуальную группу отпечатка либо, если прежняя
    группа уже решена, открывает новую со ссылкой reopened_from (старая не воскрешается).
    Возвращает (идентификатор группы, новая ли группа)."""
    key = fingerprint(verdict)
    prev = _groups.get(_active.get(key, ""))
    g = prev if (prev and prev.get("lifecycle") not in RESOLVED) else None
    new = g is None
    if new:
        # Идентификатор уникален на группу: отпечаток, момент открытия и порядковый номер
        # (защита от совпадения миллисекунды). Переоткрытая группа получает свой номер INC,
        # старая остаётся в истории. При повторе журнала порядок тот же, номера те же.
        seed = f"{key}|{ts}|{len(_groups)}"
        gid = "INC-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8].upper()
        g = {
            "key": key,
            "id": gid,
            "title": verdict.get("root_cause") or "Инцидент без классифицированной причины",
            "status": verdict.get("status"),
            "band": verdict.get("band"),
            "detectors": verdict.get("detectors") or [],
            "count": 0,
            "first_seen": ts,
            "last_seen": ts,
            "unread": True,
            "last_verdict": verdict,
            # Жизненный цикл: новая группа всегда начинается с new.
            "lifecycle": "new",
            "resolved_by": None,      # кто решил: имя оператора или agent
            "resolved_action": None,  # каким действием решено
            "resolved_at": None,
            "acked_by": None,         # кто взял в работу
            "reopened_from": prev["id"] if prev else None,
        }
        _groups[gid] = g
        _active[key] = gid
    g["count"] += 1
    g["last_seen"] = ts
    g["status"] = verdict.get("status")
    g["band"] = verdict.get("band")
    g["last_verdict"] = verdict
    g["unread"] = True
    return g["id"], new


def _apply_lifecycle(rec: dict) -> None:
    """Повторяет событие смены жизненного цикла при восстановлении и при записи."""
    g = _groups.get(rec.get("id", ""))
    lc = rec.get("lifecycle")
    if not g or lc not in LIFECYCLES:
        return
    g["lifecycle"] = lc
    if lc in RESOLVED:
        g["resolved_by"] = rec.get("by")
        g["resolved_action"] = rec.get("action")
        g["resolved_at"] = rec.get("ts")
        g["unread"] = False
    if lc == "acknowledged":
        g["acked_by"] = rec.get("by")


def upsert(verdict: dict) -> tuple:
    """Регистрирует инцидент и пишет событие в помесячный журнал.
    Возвращает (идентификатор группы, новая ли группа). Всё под блокировкой: изменение
    разделяемых словарей групп и дозапись в файл атомарны относительно других потоков."""
    with _LOCK:
        ts = _now()
        gid, new = _apply(verdict, ts)
        _append({"ts": ts, "verdict": verdict})
        return gid, new


def set_lifecycle(ident: str, lifecycle: str, by: str | None = None,
                  action: str | None = None) -> dict | None:
    """Переводит группу в новый статус жизненного цикла и пишет событие в журнал.
    ident принимает идентификатор группы (INC-...) или ключ отпечатка."""
    with _LOCK:
        g = get_group(ident)
        if not g or lifecycle not in LIFECYCLES:
            return None
        rec = {"ts": _now(), "event": "lifecycle", "id": g["id"], "lifecycle": lifecycle,
               "by": by, "action": action}
        _apply_lifecycle(rec)
        _append(rec)
        return g


def acknowledge(ident: str, operator: str) -> dict | None:
    """Оператор взял инцидент в работу (кнопка «В работу»)."""
    return set_lifecycle(ident, "acknowledged", by=operator)


def resolve_operator(ident: str, operator: str, action: str | None = None) -> dict | None:
    """Оператор устранил инцидент кнопкой «Решить»: фиксируем, кто и каким действием."""
    return set_lifecycle(ident, "resolved_operator", by=operator, action=action)


def _apply_note(rec: dict) -> None:
    """Повторяет системную запись агента в группе (лента попыток) при восстановлении
    и при записи. Храним хвост из 20 записей: полная история остаётся в журнале."""
    g = _groups.get(rec.get("id", ""))
    if not g:
        return
    g.setdefault("notes", []).append({"ts": rec.get("ts"), "by": rec.get("by"),
                                      "text": rec.get("text", "")})
    del g["notes"][:-20]


def add_note(ident: str, by: str, text: str) -> dict | None:
    """Системная запись в карточке группы (ADR-0038, этап 3): агент фиксирует, что
    заметил, что сделал (или что БЫ сделал в сухом прогоне) и чем кончилось. Запись
    append-only в тот же помесячный журнал, переживает перезапуск."""
    with _LOCK:
        g = get_group(ident)
        if not g:
            return None
        rec = {"ts": _now(), "event": "note", "id": g["id"], "by": by, "text": text}
        _apply_note(rec)
        _append(rec)
        return g


def _replay_line(line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        rec = json.loads(line)
    except ValueError:
        return
    if rec.get("event") == "lifecycle":
        _apply_lifecycle(rec)
    elif rec.get("event") == "note":
        _apply_note(rec)
    else:
        _apply(rec.get("verdict", {}) or {}, rec.get("ts") or _now())


def load() -> None:
    """Восстанавливает ленту при старте повтором событий без повторной записи: сначала
    старый единый файл (совместимость), затем все помесячные файлы в хронологическом
    порядке имён. Под блокировкой, чтобы восстановление не пересекалось с записью из другого
    потока."""
    with _LOCK:
        _groups.clear()
        _active.clear()
        if STORE_PATH.exists():
            for line in STORE_PATH.read_text(encoding="utf-8").splitlines():
                _replay_line(line)
        if STORE_DIR.exists():
            for p in sorted(STORE_DIR.glob("incidents-????-??.log.jsonl")):
                for line in p.read_text(encoding="utf-8").splitlines():
                    _replay_line(line)


# Детекторы подтверждённого сигнала (не шум): сетевой сбой, всплеск ошибок и 5xx, радиус
# влияния. Их присутствие в группе запрещает считать её шумовой при очистке purge-noise.
_SIGNAL_DETECTORS = {"D1", "D5", "D10", "D11"}


def _affected_scope(verdict: dict) -> list:
    """Затронутые цели из вердикта группы: сервисы, поды, рабочие нагрузки, которых коснулся
    инцидент. Разные схемы вердиктов кладут их под разными ключами. Пустой список означает, что
    инцидент не задел ни одной наблюдаемой цели, а значит с большой вероятностью это шум."""
    v = verdict or {}
    for key in ("affected", "affected_targets", "targets", "impacted"):
        val = v.get(key)
        if isinstance(val, (list, tuple)):
            return list(val)
    params = v.get("params") or {}
    for key in ("affected", "affected_targets", "targets"):
        val = params.get(key)
        if isinstance(val, (list, tuple)):
            return list(val)
    return []


def is_noise(g: dict) -> bool:
    """Эвристика шума: группа считается шумовой, если её полоса уверенности пуста или low, ни
    одна цель не затронута, а сработавшие детекторы не несут подтверждённого сигнала (только
    уровня note: структурные и демпферы, без сети, всплесков ошибок и радиуса влияния). Уже
    решённые и взятые в работу группы не трогаем."""
    if g.get("lifecycle") in RESOLVED or g.get("lifecycle") == "acknowledged":
        return False
    band = (g.get("band") or "")
    if band not in ("", "low"):
        return False
    v = g.get("last_verdict") or {}
    if _affected_scope(v):
        return False
    dets = set(g.get("detectors") or v.get("detectors") or [])
    if dets & _SIGNAL_DETECTORS:
        return False
    return True


def purge_noise(operator: str = "operator") -> dict:
    """Помечает шумовые группы разрешёнными по эвристике is_noise. Это ручная очистка ленты:
    нормальные состояния и слабые сигналы, попавшие инцидентами до поднятия порога, закрываются
    как resolved_operator с пометкой действия purge_noise, чтобы история осталась честной.
    Возвращает число помеченных групп и их идентификаторы."""
    with _LOCK:
        purged = []
        for g in list(_groups.values()):
            if is_noise(g):
                set_lifecycle(g["id"], "resolved_operator", by=operator, action="purge_noise")
                g["unread"] = False
                purged.append(g["id"])
        return {"purged": len(purged), "ids": purged}


def _public(g: dict) -> dict:
    """Группа для выдачи наружу: добавляет день последнего появления (для разделителей
    по дням в ленте интерфейса)."""
    out = dict(g)
    out["day"] = (g.get("last_seen") or "")[:10]
    return out


def list_groups() -> list:
    """Группы инцидентов, свежие сверху, с полями жизненного цикла и днём."""
    with _LOCK:
        return [_public(g) for g in sorted(_groups.values(),
                                           key=lambda g: g["last_seen"], reverse=True)]


def get_group(ident: str) -> dict | None:
    """Группа по идентификатору INC-... либо по ключу отпечатка (актуальная группа)."""
    with _LOCK:
        g = _groups.get(ident)
        if g:
            return g
        gid = _active.get(ident)
        return _groups.get(gid) if gid else None


def unread_count() -> int:
    with _LOCK:
        return sum(1 for g in _groups.values() if g.get("unread"))


def mark_read(ident: str | None = None) -> None:
    with _LOCK:
        _mark_read_locked(ident)


def _mark_read_locked(ident: str | None) -> None:
    if ident is None:
        for g in _groups.values():
            g["unread"] = False
        return
    g = get_group(ident)
    if g:
        g["unread"] = False
