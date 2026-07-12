"""Детерминированные ограничители автономного агента aegil. Все гарды живут вне
языковой модели и проверяются ПОСЛЕ выбора действия, поэтому модель физически не может их
обойти. Модуль состоит из чистых проверок над небольшим состоянием; состояние персистентно:
каждое событие дописывается в append-only журнал формата JSONL в каталоге данных вне рабочего
дерева, и при старте панели воспроизводится заново, поэтому лимиты переживают перезапуск.

Шесть ограничителей:
  1. не более MAX_ATTEMPTS (2) автономных попыток на один отпечаток инцидента;
  2. кулдаун FP_COOLDOWN_SECONDS (30 минут) на отпечаток после неудачной попытки;
  3. кулдаун SERVICE_COOLDOWN_SECONDS (15 минут) на сервис для перезапусков;
  4. глобальный бюджет BUDGET_PER_HOUR (6) действий в час;
  5. предохранитель: BREAKER_FAILURES (3) подряд неудачи переводят агента в режим
     «только наблюдение» на BREAKER_SECONDS (60 минут);
  6. детектор осцилляции: действие по X породило Y, действие по Y снова породило X,
     перекрёстная пара отпечатков блокируется до ручного снятия оператором.

Модуль потокобезопасен. Автопилот работает в отдельном потоке параллельно обработчикам
FastAPI, поэтому весь цикл «прочитать, изменить, записать» состояния и файла журнала
выполняется под единственной реентерабельной блокировкой _LOCK. Без неё конкурентные вызовы
record_attempt и record_result теряли бы инкременты и перемешивали строки в файле.

Каталог состояния выносится за пределы рабочего дерева агента. По умолчанию используется
каталог данных на постоянном томе (AEGIL_STATE_DIR, обычно /data), а конкретный путь к
журналу переопределяется переменной AEGIL_GUARDS. Это принципиально: если бы журнал лежал
внутри репозитория, детерминированный классификатор мог бы отнести его к безопасно удаляемым
и агент стёр бы собственные гарды. При недоступности каталога данных модуль откатывается на
временный каталог операционной системы, не прекращая работу (fail-safe).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

# Пороги ограничителей. Значения по умолчанию из спецификации, переопределяются переменными
# окружения с единым префиксом AEGIL_.
MAX_ATTEMPTS = int(os.getenv("AEGIL_MAX_ATTEMPTS", "2"))
FP_COOLDOWN_SECONDS = int(os.getenv("AEGIL_FP_COOLDOWN_SECONDS", "1800"))
SERVICE_COOLDOWN_SECONDS = int(os.getenv("AEGIL_SERVICE_COOLDOWN_SECONDS", "900"))
BUDGET_PER_HOUR = int(os.getenv("AEGIL_BUDGET_PER_HOUR", "6"))
BREAKER_FAILURES = int(os.getenv("AEGIL_BREAKER_FAILURES", "3"))
BREAKER_SECONDS = int(os.getenv("AEGIL_BREAKER_SECONDS", "3600"))
OSCILLATION_WINDOW_SECONDS = int(os.getenv("AEGIL_OSCILLATION_WINDOW_SECONDS", "1800"))

# Ограничение размера журнала. Строки старше окна удержания и превышающие предел количества
# усекаются при перезаписи, поэтому файл не растёт бесконечно, а load() перечитывает только
# релевантное окно. Окно удержания берётся с запасом относительно самого длинного гарда
# (предохранитель и кулдаун отпечатка), чтобы усечение никогда не отпускало активный лимит.
RETENTION_SECONDS = int(os.getenv("AEGIL_GUARDS_RETENTION_SECONDS",
                                  str(max(BREAKER_SECONDS, FP_COOLDOWN_SECONDS,
                                          OSCILLATION_WINDOW_SECONDS * 2) * 4)))
MAX_LOG_RECORDS = int(os.getenv("AEGIL_GUARDS_MAX_RECORDS", "5000"))
# Компакция запускается, когда число строк в файле превышает предел более чем во столько раз.
_COMPACT_FACTOR = 2


def _state_dir() -> Path:
    """Каталог данных вне рабочего дерева. По умолчанию /data (постоянный том), переопределяется
    переменной AEGIL_STATE_DIR."""
    return Path(os.getenv("AEGIL_STATE_DIR", "/data"))


def _default_state_path() -> Path:
    """Путь журнала гардов. Явный AEGIL_GUARDS имеет приоритет, иначе файл в каталоге данных.
    Ни один из вариантов не лежит внутри рабочего дерева агента, поэтому агент не может отнести
    журнал к безопасно удаляемым и стереть собственные гарды."""
    explicit = os.getenv("AEGIL_GUARDS")
    if explicit:
        return Path(explicit)
    return _state_dir() / "agent-guards.log.jsonl"


STATE_PATH = _default_state_path()

# Единственная реентерабельная блокировка на весь модуль. Реентерабельность нужна, потому что
# публичные функции вызывают друг друга (например, _record вызывает _compact_if_needed, который
# читает состояние) под уже взятой блокировкой.
_LOCK = threading.RLock()

# Память процесса, восстанавливается из журнала при load().
_state: dict = {}
# Число битых строк журнала, встреченных при последнем восстановлении. Раньше они молча
# пропускались; теперь мы их считаем и сигналим в stderr, чтобы повреждение журнала было видно.
_corrupt_lines: int = 0


def _blank() -> dict:
    return {
        "attempts": {},            # отпечаток -> число попыток
        "fp_cooldown_until": {},   # отпечаток -> момент окончания кулдауна (epoch)
        "service_until": {},       # сервис -> момент окончания кулдауна перезапуска
        "actions": [],             # моменты всех действий (для бюджета за час)
        "consecutive_failures": 0, # подряд неудачи (для предохранителя)
        "breaker_until": 0.0,      # предохранитель активен до этого момента
        "edges": {},               # отпечаток X -> {"to": Y, "ts": момент} последняя связка
        "blocked_pairs": [],       # заблокированные перекрёстные пары [[X, Y], ...]
        "log": [],                 # последние действия для карточки /agent
    }


def _ensure_writable_dir(path: Path) -> Path:
    """Гарантирует существование каталога журнала. При недоступности основного каталога данных
    (например, только-чтение или отсутствует постоянный том) откатывается на временный каталог
    операционной системы, не прекращая работу. Возвращает фактический путь к файлу журнала."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # Проверяем право записи пробным открытием на дозапись.
        with path.open("a", encoding="utf-8"):
            pass
        return path
    except OSError as exc:
        fallback = Path(tempfile.gettempdir()) / "aegil" / path.name
        print(f"guards: каталог состояния {path.parent} недоступен ({exc}); "
              f"откат на {fallback.parent}", file=sys.stderr, flush=True)
        fallback.parent.mkdir(parents=True, exist_ok=True)
        return fallback


def _append(rec: dict) -> None:
    global STATE_PATH
    STATE_PATH = _ensure_writable_dir(STATE_PATH)
    with STATE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _relevant(rec: dict, now: float) -> bool:
    """Относится ли событие к окну удержания. Всё старше RETENTION_SECONDS отбрасывается при
    компакции: активные гарды короче окна, поэтому усечение не отпускает ни одного лимита."""
    ts = float(rec.get("ts") or 0.0)
    return now - ts <= RETENTION_SECONDS


def _apply(rec: dict) -> None:
    """Применяет одно событие журнала к памяти. Общий путь записи и восстановления. Вызывается
    только под _LOCK."""
    ev = rec.get("ev")
    ts = float(rec.get("ts") or 0.0)
    s = _state
    if ev == "attempt":
        fp = rec.get("fp", "")
        s["attempts"][fp] = s["attempts"].get(fp, 0) + 1
        s["actions"].append(ts)
        svc = rec.get("service")
        if svc and rec.get("action") in ("restart", "delete_pod"):
            s["service_until"][svc] = ts + SERVICE_COOLDOWN_SECONDS
        s["log"].append({"ts": ts, "fp": fp, "action": rec.get("action"),
                         "service": svc, "outcome": "выполняется"})
        del s["log"][:-20]
    elif ev == "result":
        fp = rec.get("fp", "")
        ok = bool(rec.get("ok"))
        for row in reversed(s["log"]):
            if row["fp"] == fp and row["outcome"] == "выполняется":
                row["outcome"] = "успех" if ok else "неудача"
                break
        if ok:
            s["consecutive_failures"] = 0
        else:
            s["consecutive_failures"] += 1
            s["fp_cooldown_until"][fp] = ts + FP_COOLDOWN_SECONDS
            if s["consecutive_failures"] >= BREAKER_FAILURES:
                s["breaker_until"] = ts + BREAKER_SECONDS
    elif ev == "followup":
        # Действие по отпечатку src сопровождалось появлением отпечатка dst.
        src, dst = rec.get("src", ""), rec.get("dst", "")
        prev = s["edges"].get(dst)
        # Обратная связка признаётся осцилляцией только если она свежая (двойное окно):
        # старое совпадение месячной давности не повод блокировать пару.
        if (prev and prev.get("to") == src
                and ts - float(prev.get("ts") or 0) <= 2 * OSCILLATION_WINDOW_SECONDS):
            # Перекрёстная пара: X породил Y, Y снова породил X. Блокируем пару.
            pair = sorted([src, dst])
            if pair not in s["blocked_pairs"]:
                s["blocked_pairs"].append(pair)
        s["edges"][src] = {"to": dst, "ts": ts}
    elif ev == "unblock":
        # Ручное снятие заблокированной перекрёстной пары оператором.
        pair = sorted([rec.get("a", ""), rec.get("b", "")])
        if pair in s["blocked_pairs"]:
            s["blocked_pairs"].remove(pair)
        # Сбрасываем связки, чтобы снятая пара не заблокировалась мгновенно по старым рёбрам.
        s["edges"].pop(pair[0], None)
        s["edges"].pop(pair[1], None)


def _read_records() -> tuple[list, int]:
    """Читает журнал в список записей, считая битые строки. Вызывается только под _LOCK."""
    records: list = []
    corrupt = 0
    if not STATE_PATH.exists():
        return records, corrupt
    for line in STATE_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except ValueError:
            corrupt += 1
    return records, corrupt


def _compact_if_needed(now: float) -> None:
    """Усекает журнал по окну удержания и по пределу количества, если он разросся. Перезапись
    атомарна через временный файл и rename. Вызывается только под _LOCK."""
    global STATE_PATH
    records, _ = _read_records()
    if len(records) <= MAX_LOG_RECORDS * _COMPACT_FACTOR:
        return
    kept = [r for r in records if _relevant(r, now)]
    if len(kept) > MAX_LOG_RECORDS:
        kept = kept[-MAX_LOG_RECORDS:]
    STATE_PATH = _ensure_writable_dir(STATE_PATH)
    tmp = STATE_PATH.with_suffix(STATE_PATH.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for r in kept:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    os.replace(tmp, STATE_PATH)


def _record(rec: dict) -> None:
    """Единый путь фиксации события: под блокировкой применяет к памяти, дописывает в файл и при
    необходимости запускает компакцию."""
    with _LOCK:
        _apply(rec)
        _append(rec)
        _compact_if_needed(float(rec.get("ts") or time.time()))


def corrupt_lines() -> int:
    """Число битых строк журнала, встреченных при последнем восстановлении. Ноль в норме;
    положительное значение означает повреждение журнала и требует внимания."""
    return _corrupt_lines


def load() -> None:
    """Восстанавливает состояние гардов повтором журнала (переживает перезапуск). Битые строки
    не роняют восстановление, но считаются и сигналятся в stderr, а не глотаются молча."""
    global _state, _corrupt_lines
    with _LOCK:
        _state = _blank()
        records, corrupt = _read_records()
        for rec in records:
            _apply(rec)
        _corrupt_lines = corrupt
        if corrupt:
            print(f"guards: пропущено {corrupt} битых строк журнала {STATE_PATH}",
                  file=sys.stderr, flush=True)


load()


# ---------------------------------------------------------------------------
# Проверки (чистые функции над состоянием, читаются под блокировкой).
# ---------------------------------------------------------------------------


def check(fp: str, action: str, service: str | None = None,
          now: float | None = None) -> tuple:
    """Разрешено ли автономное действие. Возвращает (True, "") либо (False, причина).
    Порядок проверок фиксирован: предохранитель, пара осцилляции, попытки, кулдаун
    отпечатка, кулдаун сервиса, бюджет часа."""
    now = time.time() if now is None else now
    with _LOCK:
        s = _state
        if now < s["breaker_until"]:
            left = int((s["breaker_until"] - now) // 60)
            return False, f"предохранитель: только наблюдение ещё {left} мин (три подряд неудачи)"
        for a, b in s["blocked_pairs"]:
            if fp in (a, b):
                return False, "отпечаток в заблокированной паре осцилляции (чиню X, ломаю Y)"
        if s["attempts"].get(fp, 0) >= MAX_ATTEMPTS:
            return False, f"исчерпан лимит {MAX_ATTEMPTS} попыток на отпечаток"
        until = s["fp_cooldown_until"].get(fp, 0.0)
        if now < until:
            return False, f"кулдаун отпечатка после неудачи ещё {int((until - now) // 60)} мин"
        if service and action in ("restart", "delete_pod"):
            su = s["service_until"].get(service, 0.0)
            if now < su:
                return False, (f"кулдаун сервиса «{service}» ещё {int((su - now) // 60)} мин "
                               f"(не чаще раза в {SERVICE_COOLDOWN_SECONDS // 60} мин)")
        hour_ago = now - 3600
        used = sum(1 for t in s["actions"] if t > hour_ago)
        if used >= BUDGET_PER_HOUR:
            return False, f"исчерпан бюджет {BUDGET_PER_HOUR} действий в час"
        return True, ""


def attempts(fp: str) -> int:
    with _LOCK:
        return _state["attempts"].get(fp, 0)


def record_attempt(fp: str, action: str, service: str | None = None,
                   now: float | None = None) -> None:
    """Фиксирует автономную попытку: счётчик отпечатка, бюджет часа, кулдаун сервиса."""
    _record({"ev": "attempt", "ts": time.time() if now is None else now,
             "fp": fp, "action": action, "service": service})


def record_result(fp: str, ok: bool, now: float | None = None) -> None:
    """Фиксирует исход проверки: успех сбрасывает серию неудач, неудача ставит кулдаун
    на отпечаток и продвигает предохранитель."""
    _record({"ev": "result", "ts": time.time() if now is None else now, "fp": fp, "ok": ok})


def note_followup(src_fp: str, dst_fp: str, now: float | None = None) -> None:
    """Отмечает связку «после действия по src появился dst» для детектора осцилляции."""
    if not src_fp or not dst_fp or src_fp == dst_fp:
        return
    _record({"ev": "followup", "ts": time.time() if now is None else now,
             "src": src_fp, "dst": dst_fp})


def unblock_pair(fp_a: str, fp_b: str, now: float | None = None) -> bool:
    """Ручное снятие заблокированной перекрёстной пары осцилляции оператором. Без этой операции
    пара, единожды распознанная как осцилляция, блокировалась бы навсегда. Возвращает True, если
    пара была заблокирована и снята, иначе False. Событие пишется в журнал и переживает
    перезапуск."""
    pair = sorted([fp_a or "", fp_b or ""])
    with _LOCK:
        if pair not in _state["blocked_pairs"]:
            return False
    _record({"ev": "unblock", "ts": time.time() if now is None else now,
             "a": pair[0], "b": pair[1]})
    return True


def blocked_pairs() -> list:
    """Текущие заблокированные перекрёстные пары осцилляции (для карточки /agent и ручного
    снятия оператором)."""
    with _LOCK:
        return [list(p) for p in _state["blocked_pairs"]]


def pair_blocked(fp: str) -> bool:
    with _LOCK:
        return any(fp in (a, b) for a, b in _state["blocked_pairs"])


def observe_only(now: float | None = None) -> bool:
    """Активен ли режим «только наблюдение» (предохранитель или исчерпанный бюджет)."""
    now = time.time() if now is None else now
    with _LOCK:
        if now < _state["breaker_until"]:
            return True
        hour_ago = now - 3600
        return sum(1 for t in _state["actions"] if t > hour_ago) >= BUDGET_PER_HOUR


def last_success_within(window: float | None = None,
                        now: float | None = None) -> str | None:
    """Отпечаток последнего УСПЕШНОГО действия в окне осцилляции, если он был."""
    now = time.time() if now is None else now
    window = OSCILLATION_WINDOW_SECONDS if window is None else window
    with _LOCK:
        for row in reversed(_state["log"]):
            if row["outcome"] == "успех" and now - row["ts"] <= window:
                return row["fp"]
    return None


def state_summary(now: float | None = None) -> dict:
    """Сводка состояния гардов для карточки /agent."""
    now = time.time() if now is None else now
    with _LOCK:
        hour_ago = now - 3600
        used = sum(1 for t in _state["actions"] if t > hour_ago)
        cooldowns = []
        for fp, until in _state["fp_cooldown_until"].items():
            if until > now:
                cooldowns.append(f"отпечаток {fp[:40]}: ещё {int((until - now) // 60)} мин")
        for svc, until in _state["service_until"].items():
            if until > now:
                cooldowns.append(f"сервис {svc}: ещё {int((until - now) // 60)} мин")
        return {
            "budget_total": BUDGET_PER_HOUR,
            "budget_left": max(0, BUDGET_PER_HOUR - used),
            "cooldowns": cooldowns,
            "breaker_active": now < _state["breaker_until"],
            "breaker_left_min": max(0, int((_state["breaker_until"] - now) // 60)),
            "consecutive_failures": _state["consecutive_failures"],
            "blocked_pairs": [list(p) for p in _state["blocked_pairs"]],
            "last_actions": list(_state["log"][-10:]),
        }
