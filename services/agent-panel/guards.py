"""Детерминированные ограничители автономного агента (ADR-0038, раздел 2.4). Все гарды
живут вне языковой модели и проверяются ПОСЛЕ выбора действия, поэтому модель физически
не может их обойти. Модуль состоит из чистых проверок над небольшим состоянием; состояние
персистентно: каждое событие дописывается в append-only JSONL рядом с журналом инцидентов
и при старте панели воспроизводится заново, поэтому лимиты переживают перезапуск.

Шесть ограничителей:
  1. не более MAX_ATTEMPTS (2) автономных попыток на один отпечаток инцидента;
  2. кулдаун FP_COOLDOWN_SECONDS (30 минут) на отпечаток после неудачной попытки;
  3. кулдаун SERVICE_COOLDOWN_SECONDS (15 минут) на сервис для перезапусков;
  4. глобальный бюджет BUDGET_PER_HOUR (6) действий в час;
  5. предохранитель: BREAKER_FAILURES (3) подряд неудачи переводят агента в режим
     «только наблюдение» на BREAKER_SECONDS (60 минут);
  6. детектор осцилляции: действие по X породило Y, действие по Y снова породило X,
     перекрёстная пара отпечатков блокируется навсегда (до ручного вмешательства).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

# Пороги ограничителей. Значения по умолчанию из спецификации, переопределяются ENV.
MAX_ATTEMPTS = int(os.getenv("AGENT_MAX_ATTEMPTS", "2"))
FP_COOLDOWN_SECONDS = int(os.getenv("AGENT_FP_COOLDOWN_SECONDS", "1800"))
SERVICE_COOLDOWN_SECONDS = int(os.getenv("AGENT_SERVICE_COOLDOWN_SECONDS", "900"))
BUDGET_PER_HOUR = int(os.getenv("AGENT_BUDGET_PER_HOUR", "6"))
BREAKER_FAILURES = int(os.getenv("AGENT_BREAKER_FAILURES", "3"))
BREAKER_SECONDS = int(os.getenv("AGENT_BREAKER_SECONDS", "3600"))
OSCILLATION_WINDOW_SECONDS = int(os.getenv("AGENT_OSCILLATION_WINDOW_SECONDS", "1800"))

# Журнал состояния гардов: append-only JSONL рядом с журналом инцидентов.
STATE_PATH = Path(os.getenv("ADMINCHAT_GUARDS",
                            str(Path(__file__).parent / "agent-guards.log.jsonl")))

# Память процесса, восстанавливается из журнала при load().
_state: dict = {}


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


def _append(rec: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with STATE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _apply(rec: dict) -> None:
    """Применяет одно событие журнала к памяти. Общий путь записи и восстановления."""
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
        prev = _state["edges"].get(dst)
        # Обратная связка признаётся осцилляцией только если она свежая (двойное окно):
        # старое совпадение месячной давности не повод блокировать пару.
        if (prev and prev.get("to") == src
                and ts - float(prev.get("ts") or 0) <= 2 * OSCILLATION_WINDOW_SECONDS):
            # Перекрёстная пара: X породил Y, Y снова породил X. Блокируем пару.
            pair = sorted([src, dst])
            if pair not in s["blocked_pairs"]:
                s["blocked_pairs"].append(pair)
        s["edges"][src] = {"to": dst, "ts": ts}


def _record(rec: dict) -> None:
    _apply(rec)
    _append(rec)


def load() -> None:
    """Восстанавливает состояние гардов повтором журнала (переживает перезапуск)."""
    global _state
    _state = _blank()
    if STATE_PATH.exists():
        for line in STATE_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                _apply(json.loads(line))
            except ValueError:
                continue


load()


# ---------------------------------------------------------------------------
# Проверки (чистые функции над состоянием).
# ---------------------------------------------------------------------------


def check(fp: str, action: str, service: str | None = None,
          now: float | None = None) -> tuple:
    """Разрешено ли автономное действие. Возвращает (True, "") либо (False, причина).
    Порядок проверок фиксирован: предохранитель, пара осцилляции, попытки, кулдаун
    отпечатка, кулдаун сервиса, бюджет часа."""
    now = time.time() if now is None else now
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


def pair_blocked(fp: str) -> bool:
    return any(fp in (a, b) for a, b in _state["blocked_pairs"])


def observe_only(now: float | None = None) -> bool:
    """Активен ли режим «только наблюдение» (предохранитель или исчерпанный бюджет)."""
    now = time.time() if now is None else now
    if now < _state["breaker_until"]:
        return True
    hour_ago = now - 3600
    return sum(1 for t in _state["actions"] if t > hour_ago) >= BUDGET_PER_HOUR


def last_success_within(window: float | None = None,
                        now: float | None = None) -> str | None:
    """Отпечаток последнего УСПЕШНОГО действия в окне осцилляции, если он был."""
    now = time.time() if now is None else now
    window = OSCILLATION_WINDOW_SECONDS if window is None else window
    for row in reversed(_state["log"]):
        if row["outcome"] == "успех" and now - row["ts"] <= window:
            return row["fp"]
    return None


def state_summary(now: float | None = None) -> dict:
    """Сводка состояния гардов для карточки /agent."""
    now = time.time() if now is None else now
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
        "blocked_pairs": list(_state["blocked_pairs"]),
        "last_actions": list(_state["log"][-10:]),
    }
