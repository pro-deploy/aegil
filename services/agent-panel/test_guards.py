"""Модульные тесты детерминированных гардов автономного агента kube-sentinel.

Собираемый pytest-вид (функции с префиксом test_), без сети. Запуск:
    cd services/agent-panel && python3 -m pytest -q test_guards.py

Покрыты все шесть ограничителей, персистентность через перезапуск, конкурентный доступ
(гонки record_attempt/record_result), ротация журнала по окну удержания и пределу количества,
вынос пути состояния в каталог данных вне рабочего дерева, ручное снятие заблокированной пары
осцилляции и учёт битых строк журнала.
"""
import json
import tempfile
import threading
from pathlib import Path

import guards


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def _fresh() -> Path:
    """Свежий журнал в изолированном временном каталоге. Возвращает каталог."""
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


def test_fp_cooldown():
    _fresh()
    fp = "incident|A5|5xx"
    guards.record_attempt(fp, "restart", "web", now=T0)
    guards.record_result(fp, False, now=T0 + 200)
    ok, reason = guards.check(fp, "restart", "cache", now=T0 + 300)
    _eq("кулдаун отпечатка после неудачи", ok, False)
    assert "кулдаун отпечатка" in reason, reason
    # Через 30 минут после неудачи кулдаун отпущен (остальные гарды не мешают).
    ok, reason = guards.check(fp, "restart", "cache",
                              now=T0 + 200 + guards.FP_COOLDOWN_SECONDS + 1)
    _eq("кулдаун отпечатка истёк", ok, True)


def test_service_cooldown():
    _fresh()
    guards.record_attempt("fp-x", "restart", "cache", now=T0)
    # Другой инцидент указывает на тот же сервис: перезапуск чаще раза в 15 минут запрещён.
    ok, reason = guards.check("fp-y", "restart", "cache", now=T0 + 60)
    _eq("кулдаун сервиса", ok, False)
    assert "кулдаун сервиса" in reason, reason
    # Действие без перезапуска сервиса кулдауном сервиса не ограничено.
    ok, _ = guards.check("fp-y", "requeue", now=T0 + 60)
    _eq("requeue не сервисное действие", ok, True)
    ok, _ = guards.check("fp-y", "restart", "cache",
                         now=T0 + guards.SERVICE_COOLDOWN_SECONDS + 1)
    _eq("кулдаун сервиса истёк", ok, True)


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
    # Предохранитель отпущен через час.
    ok, _ = guards.check("fp-other", "requeue", now=T0 + 25 + guards.BREAKER_SECONDS + 1)
    _eq("предохранитель отпущен через час", ok, True)
    # Успех сбрасывает серию.
    guards.record_attempt("fp-ok", "requeue", now=T0 + guards.BREAKER_SECONDS + 4000)
    guards.record_result("fp-ok", True, now=T0 + guards.BREAKER_SECONDS + 4001)
    s = guards.state_summary(now=T0 + guards.BREAKER_SECONDS + 4002)
    _eq("успех сбрасывает серию", s["consecutive_failures"], 0)


def test_oscillation():
    _fresh()
    x, y = "fp-X", "fp-Y"
    guards.note_followup(x, y, now=T0)
    _eq("пары ещё нет", guards.pair_blocked(x), False)
    guards.note_followup(y, x, now=T0 + 600)
    _eq("пара X заблокирована", guards.pair_blocked(x), True)
    _eq("пара Y заблокирована", guards.pair_blocked(y), True)
    ok, reason = guards.check(x, "requeue", now=T0 + 700)
    _eq("действие по паре запрещено", ok, False)
    assert "осцилляции" in reason, reason
    # Чужой отпечаток пара не задевает.
    ok, _ = guards.check("fp-Z", "requeue", now=T0 + 700)
    _eq("чужой отпечаток свободен", ok, True)


def test_oscillation_stale_edge():
    _fresh()
    guards.note_followup("fp-Y", "fp-X", now=T0)
    guards.note_followup("fp-X", "fp-Y",
                         now=T0 + 2 * guards.OSCILLATION_WINDOW_SECONDS + 100)
    _eq("старая связка не блокирует", guards.pair_blocked("fp-X"), False)


def test_unblock_pair():
    """Ручное снятие заблокированной пары осцилляции: без него пара блокировалась бы навсегда."""
    tmp = _fresh()
    x, y = "fp-P", "fp-Q"
    guards.note_followup(x, y, now=T0)
    guards.note_followup(y, x, now=T0 + 600)
    _eq("пара заблокирована", guards.pair_blocked(x), True)
    assert [x, y] in [sorted(p) for p in guards.blocked_pairs()] or \
           [y, x] in [sorted(p) for p in guards.blocked_pairs()]
    # Снятие несуществующей пары возвращает False.
    _eq("снятие чужой пары", guards.unblock_pair("fp-A", "fp-B", now=T0 + 700), False)
    # Снятие реальной пары возвращает True и освобождает оба отпечатка.
    _eq("снятие реальной пары", guards.unblock_pair(x, y, now=T0 + 700), True)
    _eq("пара X снята", guards.pair_blocked(x), False)
    _eq("пара Y снята", guards.pair_blocked(y), False)
    ok, _ = guards.check(x, "requeue", now=T0 + 800)
    _eq("действие после снятия разрешено", ok, True)
    # Снятие переживает перезапуск: событие записано в журнал.
    guards.STATE_PATH = tmp / "agent-guards.log.jsonl"
    guards.load()
    _eq("снятие пережило перезапуск", guards.pair_blocked(x), False)


def test_persistence():
    tmp = _fresh()
    fp = "fp-persist"
    guards.record_attempt(fp, "restart", "cache", now=T0)
    guards.record_result(fp, False, now=T0 + 10)
    guards.note_followup("fp-A", "fp-B", now=T0)
    guards.note_followup("fp-B", "fp-A", now=T0 + 20)
    # Перезапуск панели: состояние восстанавливается из журнала целиком.
    guards.load()
    _eq("попытки пережили перезапуск", guards.attempts(fp), 1)
    ok, reason = guards.check(fp, "restart", "cache", now=T0 + 60)
    _eq("кулдаун пережил перезапуск", ok, False)
    _eq("пара осцилляции пережила перезапуск", guards.pair_blocked("fp-A"), True)
    _eq("серия неудач пережила перезапуск",
        guards.state_summary(now=T0 + 60)["consecutive_failures"], 1)
    assert (tmp / "agent-guards.log.jsonl").exists(), "журнал гардов не создан"
    s = guards.state_summary(now=T0 + 60)
    _eq("бюджет в сводке", s["budget_left"], guards.BUDGET_PER_HOUR - 1)
    assert s["cooldowns"], "кулдауны не попали в сводку"


def test_state_path_outside_worktree(monkeypatch):
    """Путь состояния по умолчанию лежит в каталоге данных вне рабочего дерева агента, а не
    внутри каталога модуля, иначе агент мог бы стереть собственные гарды как чистку путей."""
    monkeypatch.delenv("SENTINEL_GUARDS", raising=False)
    monkeypatch.setenv("SENTINEL_STATE_DIR", "/data")
    path = guards._default_state_path()
    _eq("путь в каталоге данных", str(path), "/data/agent-guards.log.jsonl")
    module_dir = str(Path(guards.__file__).resolve().parent)
    assert not str(path).startswith(module_dir), \
        f"журнал гардов внутри рабочего дерева: {path}"
    # Явный SENTINEL_GUARDS имеет приоритет.
    monkeypatch.setenv("SENTINEL_GUARDS", "/data/custom-guards.jsonl")
    _eq("явный путь", str(guards._default_state_path()), "/data/custom-guards.jsonl")


def test_state_dir_failsafe(monkeypatch):
    """При недоступном каталоге данных запись откатывается на временный каталог, не роняя агента."""
    unwritable = "/proc/nonexistent-kube-sentinel/state"
    guards.STATE_PATH = Path(unwritable) / "agent-guards.log.jsonl"
    guards.load()
    # Запись должна пройти без исключения, путь откатится на временный каталог.
    guards.record_attempt("fp-failsafe", "requeue", now=T0)
    assert guards.STATE_PATH.exists(), "fail-safe путь не создан"
    assert tempfile.gettempdir() in str(guards.STATE_PATH), \
        f"откат ушёл не во временный каталог: {guards.STATE_PATH}"
    _eq("попытка зафиксирована на fail-safe пути", guards.attempts("fp-failsafe"), 1)


def test_log_rotation():
    """Журнал усекается по пределу количества и окну удержания, не растёт бесконечно, а свежие
    события переживают компакцию, тогда как старые за окном удержания уходят."""
    tmp = _fresh()
    path = tmp / "agent-guards.log.jsonl"
    guards.MAX_LOG_RECORDS = 50
    try:
        cap = guards.MAX_LOG_RECORDS * guards._COMPACT_FACTOR
        old = T0
        recent = T0 + guards.RETENTION_SECONDS + 1_000_000
        # Много старых событий далеко за окном удержания.
        for i in range(cap + 50):
            guards.record_attempt(f"fp-old-{i}", "requeue", now=old + i)
        # Рост ограничен: файл никогда не превышает предел количества с коэффициентом компакции.
        after_old = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(after_old) <= cap, f"журнал не ограничен: {len(after_old)} строк"
        # Достаточно свежих записей, чтобы компакция сработала уже при recent-времени и вымела
        # старые события за окном удержания.
        for i in range(cap + 1):
            guards.record_attempt(f"fp-recent-{i}", "requeue", now=recent + i)
        lines = [l for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
        assert len(lines) <= cap, f"журнал не усечён: {len(lines)} строк"
        parsed = [json.loads(l) for l in lines]
        # Свежие записи присутствуют, старые за окном удержания вымыты компакцией.
        assert any(r.get("fp", "").startswith("fp-recent") for r in parsed), \
            "свежие записи потеряны при компакции"
        assert not any(r.get("fp", "").startswith("fp-old") for r in parsed), \
            "старые записи за окном удержания не вымыты"
    finally:
        guards.MAX_LOG_RECORDS = 5000


def test_corrupt_lines_counted():
    """Битые строки журнала не роняют восстановление, но считаются, а не глотаются молча."""
    tmp = _fresh()
    guards.record_attempt("fp-good", "requeue", now=T0)
    path = tmp / "agent-guards.log.jsonl"
    with path.open("a", encoding="utf-8") as f:
        f.write("{битый json не парсится\n")
        f.write("ещё мусор\n")
    guards.load()
    _eq("две битые строки посчитаны", guards.corrupt_lines(), 2)
    _eq("валидное событие восстановлено", guards.attempts("fp-good"), 1)


def test_concurrent_attempts_no_lost_increments():
    """Гонка: конкурентные record_attempt из многих потоков не теряют инкременты и не мешают
    строки в журнале. Без блокировки чтение-изменение-запись состояния теряла бы события."""
    tmp = _fresh()
    threads_count = 16
    per_thread = 25
    barrier = threading.Barrier(threads_count)

    def worker(tid: int):
        barrier.wait()
        for i in range(per_thread):
            guards.record_attempt(f"fp-{tid}-{i}", "requeue", now=T0 + tid)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    expected = threads_count * per_thread
    # В памяти столько же уникальных отпечатков, сколько записей.
    lines = [l for l in (tmp / "agent-guards.log.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    _eq("все записи в журнале", len(lines), expected)
    # Каждая строка валидна: строки не перемешаны.
    for l in lines:
        json.loads(l)
    # Все отпечатки видны в состоянии.
    guards.load()
    seen = sum(guards.attempts(f"fp-{t}-{i}")
               for t in range(threads_count) for i in range(per_thread))
    _eq("все инкременты сохранены", seen, expected)
