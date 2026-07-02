"""Модульные тесты детерминированных гардов автономного агента (ADR-0038, раздел 2.4).
Без сети и без pytest. Запуск: python3 services/adminchat/test_guards.py
Покрыты все шесть ограничителей и персистентность состояния через перезапуск.
"""
import tempfile
from pathlib import Path

import guards


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def _fresh():
    tmp = Path(tempfile.mkdtemp())
    guards.STATE_PATH = tmp / "agent-guards.log.jsonl"
    guards.load()
    return tmp


T0 = 1_000_000.0


def test_attempt_limit():
    _fresh()
    fp = "incident|A2|очередь"
    ok, _ = guards.check(fp, "requeue", now=T0)
    _eq("первая попытка разрешена", ok, True)
    guards.record_attempt(fp, "requeue", now=T0)
    guards.record_attempt(fp, "restart", "worker", now=T0 + 10)
    ok, reason = guards.check(fp, "requeue", now=T0 + 20)
    _eq("третьей попытки не бывает", ok, False)
    assert "лимит" in reason, reason
    _eq("счётчик попыток", guards.attempts(fp), 2)
    print("гард 1 (лимит попыток): ok")


def test_fp_cooldown():
    _fresh()
    fp = "incident|A5|5xx"
    guards.record_attempt(fp, "restart", "web", now=T0)
    guards.record_result(fp, False, now=T0 + 200)
    ok, reason = guards.check(fp, "restart", "asr", now=T0 + 300)
    _eq("кулдаун отпечатка после неудачи", ok, False)
    assert "кулдаун отпечатка" in reason, reason
    # Через 30 минут после неудачи кулдаун отпущен (остальные гарды не мешают).
    ok, reason = guards.check(fp, "restart", "asr",
                              now=T0 + 200 + guards.FP_COOLDOWN_SECONDS + 1)
    _eq("кулдаун отпечатка истёк", ok, True)
    print("гард 3 (кулдаун отпечатка 30 мин): ok")


def test_service_cooldown():
    _fresh()
    guards.record_attempt("fp-x", "restart", "asr", now=T0)
    # Другой инцидент указывает на тот же сервис: перезапуск чаще раза в 15 минут запрещён.
    ok, reason = guards.check("fp-y", "restart", "asr", now=T0 + 60)
    _eq("кулдаун сервиса", ok, False)
    assert "кулдаун сервиса" in reason, reason
    # Действие без перезапуска сервиса кулдауном сервиса не ограничено.
    ok, _ = guards.check("fp-y", "requeue", now=T0 + 60)
    _eq("requeue не сервисное действие", ok, True)
    ok, _ = guards.check("fp-y", "restart", "asr",
                         now=T0 + guards.SERVICE_COOLDOWN_SECONDS + 1)
    _eq("кулдаун сервиса истёк", ok, True)
    print("гард 4 (кулдаун сервиса 15 мин): ok")


def test_hour_budget():
    _fresh()
    for i in range(guards.BUDGET_PER_HOUR):
        guards.record_attempt(f"fp-{i}", "requeue", now=T0 + i)
    ok, reason = guards.check("fp-new", "requeue", now=T0 + 100)
    _eq("бюджет часа исчерпан", ok, False)
    assert "бюджет" in reason, reason
    _eq("только наблюдение при пустом бюджете", guards.observe_only(now=T0 + 100), True)
    # Через час окно бюджета очищается.
    ok, _ = guards.check("fp-new", "requeue", now=T0 + 3700)
    _eq("бюджет восстановлен", ok, True)
    print("гард 5 (бюджет 6 действий в час): ok")


def test_circuit_breaker():
    _fresh()
    for i in range(guards.BREAKER_FAILURES):
        fp = f"fp-b{i}"
        guards.record_attempt(fp, "requeue", now=T0 + i * 10)
        guards.record_result(fp, False, now=T0 + i * 10 + 5)
    ok, reason = guards.check("fp-other", "requeue", now=T0 + 100)
    _eq("предохранитель сработал", ok, False)
    assert "предохранитель" in reason, reason
    _eq("режим только наблюдение", guards.observe_only(now=T0 + 100), True)
    # Успех сбрасывает серию: новый отказ после успеха не открывает предохранитель.
    ok, _ = guards.check("fp-other", "requeue", now=T0 + 25 + guards.BREAKER_SECONDS + 1)
    _eq("предохранитель отпущен через час", ok, True)
    guards.record_attempt("fp-ok", "requeue", now=T0 + guards.BREAKER_SECONDS + 4000)
    guards.record_result("fp-ok", True, now=T0 + guards.BREAKER_SECONDS + 4001)
    _eq("успех сбрасывает серию", guards._state["consecutive_failures"], 0)
    print("гард 6 (предохранитель после 3 неудач): ok")


def test_oscillation():
    _fresh()
    x, y = "fp-X", "fp-Y"
    # Действие по X породило Y: связка запоминается, пары ещё нет.
    guards.note_followup(x, y, now=T0)
    _eq("пары ещё нет", guards.pair_blocked(x), False)
    # Действие по Y снова породило X: перекрёстная пара блокируется.
    guards.note_followup(y, x, now=T0 + 600)
    _eq("пара X заблокирована", guards.pair_blocked(x), True)
    _eq("пара Y заблокирована", guards.pair_blocked(y), True)
    ok, reason = guards.check(x, "requeue", now=T0 + 700)
    _eq("действие по паре запрещено", ok, False)
    assert "осцилляции" in reason, reason
    # Чужой отпечаток пара не задевает.
    ok, _ = guards.check("fp-Z", "requeue", now=T0 + 700)
    _eq("чужой отпечаток свободен", ok, True)
    print("гард 7 (детектор осцилляции): ok")


def test_oscillation_stale_edge():
    _fresh()
    # Обратная связка старше двойного окна не считается осцилляцией.
    guards.note_followup("fp-Y", "fp-X", now=T0)
    guards.note_followup("fp-X", "fp-Y",
                         now=T0 + 2 * guards.OSCILLATION_WINDOW_SECONDS + 100)
    _eq("старая связка не блокирует", guards.pair_blocked("fp-X"), False)
    print("осцилляция (старая связка): ok")


def test_persistence():
    tmp = _fresh()
    fp = "fp-persist"
    guards.record_attempt(fp, "restart", "asr", now=T0)
    guards.record_result(fp, False, now=T0 + 10)
    guards.note_followup("fp-A", "fp-B", now=T0)
    guards.note_followup("fp-B", "fp-A", now=T0 + 20)
    # Перезапуск панели: состояние восстанавливается из журнала целиком.
    guards.load()
    _eq("попытки пережили перезапуск", guards.attempts(fp), 1)
    ok, reason = guards.check(fp, "restart", "asr", now=T0 + 60)
    _eq("кулдаун пережил перезапуск", ok, False)
    _eq("пара осцилляции пережила перезапуск", guards.pair_blocked("fp-A"), True)
    _eq("серия неудач пережила перезапуск", guards._state["consecutive_failures"], 1)
    assert (tmp / "agent-guards.log.jsonl").exists(), "журнал гардов не создан"
    # Сводка для карточки /agent согласована с состоянием.
    s = guards.state_summary(now=T0 + 60)
    _eq("бюджет в сводке", s["budget_left"], guards.BUDGET_PER_HOUR - 1)
    assert s["cooldowns"], "кулдауны не попали в сводку"
    print("персистентность гардов: ok")


if __name__ == "__main__":
    test_attempt_limit()
    test_fp_cooldown()
    test_service_cooldown()
    test_hour_budget()
    test_circuit_breaker()
    test_oscillation()
    test_oscillation_stale_edge()
    test_persistence()
    print("guards: all tests passed")
