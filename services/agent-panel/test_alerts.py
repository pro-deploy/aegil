"""Модульные тесты каталога алертов этапов 4 и 5 (ADR-0038): A3 (уровень B), A6, A8, A9,
A10, A11, A12 на синтетических данных, плюс команда отчёта /report. Без сети и без pytest.
Запуск: python3 services/adminchat/test_alerts.py
"""
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import alerts
import guards
import incidents
import status as status_cards


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


# ---------------------------------------------------------------------------
# A6: деградация латентности распознавания.
# ---------------------------------------------------------------------------


def test_a6():
    # Ниже порога предупреждения: молчит.
    facts = {"latency_by_target": {"asr": {"p95_ms": alerts.LATENCY_ASR_P95_WARN_MS - 1}}}
    _eq("A6 ниже порога молчит", alerts.check_a6(facts, None), [])
    # Между порогами: предупреждение.
    facts = {"latency_by_target": {"asr": {"p95_ms": alerts.LATENCY_ASR_P95_WARN_MS + 1}}}
    out = alerts.check_a6(facts, {"queue": {"processing": 0}})
    _eq("A6 предупреждение", [a["severity"] for a in out], ["warning"])
    _eq("A6 нагрузка низкая", out[0]["params"]["load_high"], False)
    # Выше критического порога с высокой нагрузкой: high и признак роста параллелизма.
    facts = {"latency_by_target": {"asr": {"p95_ms": alerts.LATENCY_ASR_P95_CRIT_MS + 1}}}
    out = alerts.check_a6(facts, {"queue": {"processing": alerts.LOAD_PROCESSING_HINT}})
    _eq("A6 критично", out[0]["severity"], "high")
    _eq("A6 нагрузка высокая", out[0]["params"]["load_high"], True)
    # Нет данных латентности по asr: молчит.
    _eq("A6 без данных", alerts.check_a6({"latency_by_target": {}}, None), [])
    print("A6: ok")


# ---------------------------------------------------------------------------
# A8: молчание сервиса.
# ---------------------------------------------------------------------------


def test_a8():
    pods = [{"name": "worker-1-2", "phase": "Running", "waiting_reason": None},
            {"name": "api-3-4", "phase": "Running", "waiting_reason": None}]
    # worker молчит (0 строк), api пишет: один алерт по worker.
    out = alerts.check_a8(pods, {"by_service": {"worker": 0, "api": 42}})
    _eq("A8 молчит worker", [a["params"]["service"] for a in out], ["worker"])
    _eq("A8 предупреждение", out[0]["severity"], "warning")
    # Оба пишут: тихо.
    _eq("A8 оба пишут", alerts.check_a8(pods, {"by_service": {"worker": 5, "api": 42}}), [])
    # Под не Running: не диагностируем молчание (его видят другие алерты).
    pods_bad = [{"name": "worker-1-2", "phase": "Pending", "waiting_reason": None}]
    _eq("A8 не Running пропущен", alerts.check_a8(pods_bad, {"by_service": {}}), [])
    # Без фактов окна молчание не диагностируется.
    _eq("A8 без фактов", alerts.check_a8(pods, None), [])
    print("A8: ok")


# ---------------------------------------------------------------------------
# A9: живой режим у потолка.
# ---------------------------------------------------------------------------


def test_a9():
    # Выше порога занятости: предупреждение с процентом.
    ov = {"live": {"active": 9, "capacity": 10}}
    out = alerts.check_a9(ov)
    _eq("A9 у потолка", [a["severity"] for a in out], ["warning"])
    _eq("A9 процент", out[0]["params"]["pct"], 90)
    # Ниже порога: тихо.
    _eq("A9 запас", alerts.check_a9({"live": {"active": 1, "capacity": 10}}), [])
    # Потолок неизвестен: тихо (не делим на ноль).
    _eq("A9 без потолка", alerts.check_a9({"live": {"active": 5, "capacity": 0}}), [])
    print("A9: ok")


# ---------------------------------------------------------------------------
# A10: сертификат TLS истекает.
# ---------------------------------------------------------------------------


def test_a10():
    _eq("A10 запас далеко", alerts.check_a10(alerts.TLS_WARN_DAYS + 1), [])
    out = alerts.check_a10(alerts.TLS_WARN_DAYS)
    _eq("A10 предупреждение", [a["severity"] for a in out], ["warning"])
    out = alerts.check_a10(alerts.TLS_HIGH_DAYS)
    _eq("A10 высокая", out[0]["severity"], "high")
    _eq("A10 нет данных", alerts.check_a10(None), [])
    print("A10: ok")


# ---------------------------------------------------------------------------
# A11: почта не уходит.
# ---------------------------------------------------------------------------


def test_a11():
    # Ошибки stalwart, часть сетевые (по сигналам), часть отказы получателей.
    facts = {"by_service_errors": {"stalwart": 5},
             "error_signals": {"connection_refused": 2}}
    out = alerts.check_a11(facts)
    _eq("A11 сработал", len(out), 1)
    _eq("A11 сетевые отделены", out[0]["params"]["network_errors"], 2)
    _eq("A11 отказы получателей", out[0]["params"]["recipient_errors"], 3)
    # Нет ошибок stalwart: тихо.
    _eq("A11 без ошибок", alerts.check_a11({"by_service_errors": {"api": 3}}), [])
    print("A11: ok")


# ---------------------------------------------------------------------------
# A12: ошибки биллинга и квот.
# ---------------------------------------------------------------------------


def test_a12():
    out = alerts.check_a12({"event_counts": {"billing.error": 3, "http.request": 100}})
    _eq("A12 сработал", [a["severity"] for a in out], ["high"])
    _eq("A12 счёт событий", out[0]["params"]["events"], 3)
    _eq("A12 без биллинга", alerts.check_a12({"event_counts": {"http.request": 100}}), [])
    print("A12: ok")


# ---------------------------------------------------------------------------
# A3 уровень B: несёт признак критичности для плейбука.
# ---------------------------------------------------------------------------


def test_a3_crit_flag():
    node = {"name": "control", "ready": True, "capacity": {"cpu": "4", "memory": "8Gi"}}
    out = alerts.check_a3([node], {"control": {"node": {"fs": {"usedBytes": 85, "capacityBytes": 100}}}})
    _eq("A3 warn не критично", out[0]["params"]["crit"], False)
    out = alerts.check_a3([node], {"control": {"node": {"fs": {"usedBytes": 95, "capacityBytes": 100}}}})
    _eq("A3 crit флаг", out[0]["params"]["crit"], True)
    print("A3 уровень B флаг: ok")


# ---------------------------------------------------------------------------
# detect_all прогоняет весь каталог и не падает на пустых фактах.
# ---------------------------------------------------------------------------


def test_detect_all_smoke():
    _eq("detect_all на пустых фактах", alerts.detect_all({}), [])
    # Сборный набор фактов, дающий сразу несколько алертов этапов 4 и 5.
    facts = {
        "nodes": [{"name": "control", "ready": True, "capacity": {"cpu": "4", "memory": "8Gi"}}],
        "stats_by_node": {"control": {"node": {"fs": {"usedBytes": 95, "capacityBytes": 100}}}},
        "pods": [{"name": "worker-1-2", "phase": "Running", "waiting_reason": None}],
        "overview": {"queue": {"processing": 0}, "live": {"active": 9, "capacity": 10}},
        "rca_facts": {"by_service": {"worker": 0},
                      "latency_by_target": {"asr": {"p95_ms": 20000}},
                      "by_service_errors": {"stalwart": 4},
                      "error_signals": {"timeout": 1},
                      "event_counts": {"quota.exceeded": 2}},
        "tls_days": 5,
        "gpu_node": "gooseek",
    }
    codes = sorted({a["code"] for a in alerts.detect_all(facts)})
    for expected in ("A3", "A6", "A8", "A9", "A10", "A11", "A12"):
        assert expected in codes, (expected, codes)
    print("detect_all сборный: ok")


# ---------------------------------------------------------------------------
# Команда /report: отчёт агента за сутки.
# ---------------------------------------------------------------------------


def _now_iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"


def test_report_card():
    tmp = Path(tempfile.mkdtemp())
    incidents.STORE_PATH = tmp / "incidents.log.jsonl"
    incidents.STORE_DIR = tmp
    incidents._groups.clear()
    incidents._active.clear()
    now = datetime(2026, 7, 2, 12, 0, 0, tzinfo=timezone.utc)

    # Синтетические группы за окно: одна решена агентом, одна эскалирована, одна повторная.
    groups = [
        {"id": "INC-1", "title": "очередь стоит", "count": 4,
         "last_seen": _now_iso(now - timedelta(hours=1)), "lifecycle": "resolved_auto",
         "reopened_from": None},
        {"id": "INC-2", "title": "postgres недоступен", "count": 1,
         "last_seen": _now_iso(now - timedelta(hours=2)), "lifecycle": "escalated",
         "reopened_from": None},
        {"id": "INC-3", "title": "диск полон", "count": 2,
         "last_seen": _now_iso(now - timedelta(hours=3)), "lifecycle": "resolved_auto",
         "reopened_from": "INC-0"},
        # Вне окна: не учитывается.
        {"id": "INC-OLD", "title": "старое", "count": 9,
         "last_seen": _now_iso(now - timedelta(hours=48)), "lifecycle": "escalated",
         "reopened_from": None},
    ]
    guard_state = {
        "budget_total": 6, "budget_left": 4, "breaker_active": False,
        "consecutive_failures": 0,
        "last_actions": [
            {"ts": 1.0, "action": "requeue", "outcome": "успех"},
            {"ts": 2.0, "action": "restart", "outcome": "неудача"},
            {"ts": 3.0, "action": "cleanup_temp", "outcome": "успех"},
        ],
    }
    card = status_cards.build_report_card(groups, guard_state, now=now)
    assert "инцидентов за окно: 3" in card, card
    assert "решил сам (resolved_auto): 2" in card, card
    assert "эскалировал: 1" in card, card
    assert "переоткрытий (хронические): 1" in card, card
    assert "INC-1" in card and "старое" not in card, card
    assert "requeue" in card and "cleanup_temp" in card, card
    assert "бюджет действий: осталось 4 из 6" in card, card
    print("отчёт /report: ok")


if __name__ == "__main__":
    test_a6()
    test_a8()
    test_a9()
    test_a10()
    test_a11()
    test_a12()
    test_a3_crit_flag()
    test_detect_all_smoke()
    test_report_card()
    print("alerts: all tests passed")
