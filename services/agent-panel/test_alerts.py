"""Модульные тесты универсального каталога симптомов Kubernetes (alerts.py) и статусных сводок
(status.py). Проверяют правильность поведения на синтетических данных без выхода в сеть: детекторы
срабатывают на нейтральные симптомы кластера без имён приложения, пороги и границы соблюдаются,
разбор фаз подов и сводки узлов корректны. Собирается стандартным сборщиком pytest (функции с
префиксом test_)."""
import os

os.environ.setdefault("AEGIL_RESTART_ALLOWLIST", "web,api,worker")

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import alerts
import incidents
import status as status_cards


NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


def _codes(out):
    return sorted({a["code"] for a in out})


# ---------------------------------------------------------------------------
# Симптомы уровня подов.
# ---------------------------------------------------------------------------


def test_crashloop_one_per_service():
    pods = [
        {"name": "web-6b9f7-x2x1c", "phase": "Running", "waiting_reason": "CrashLoopBackOff"},
        {"name": "web-6b9f7-y3y2d", "phase": "Running", "waiting_reason": "CrashLoopBackOff"},
        {"name": "api-1a2b3-cccc3", "phase": "Running", "waiting_reason": None},
    ]
    out = alerts.check_crashloop(pods)
    assert [a["params"]["service"] for a in out] == ["web"], out
    assert out[0]["severity"] == "high"
    assert alerts.check_crashloop([]) == []


def test_image_pull_reasons():
    for reason in alerts._IMAGE_PULL_REASONS:
        pods = [{"name": "api-1-2", "phase": "Pending", "waiting_reason": reason}]
        out = alerts.check_image_pull(pods)
        assert len(out) == 1 and out[0]["params"]["reason"] == reason, (reason, out)
    assert alerts.check_image_pull([{"name": "api-1-2", "waiting_reason": "CrashLoopBackOff"}]) == []


def test_oom_killed():
    pods = [{"name": "worker-1-2", "phase": "Running", "waiting_reason": None, "oom_killed": True}]
    out = alerts.check_oom(pods)
    assert out and out[0]["code"] == "oom_killed" and out[0]["params"]["service"] == "worker"
    assert alerts.check_oom([{"name": "worker-1-2", "oom_killed": False}]) == []


def test_pending_over_age():
    old = (NOW - timedelta(seconds=alerts.PENDING_AGE_SECONDS + 60)).isoformat()
    fresh = (NOW - timedelta(seconds=10)).isoformat()
    # Долго Pending: срабатывает.
    out = alerts.check_pending([{"name": "api-1-2", "phase": "Pending",
                                 "creation_timestamp": old}], NOW)
    assert out and out[0]["code"] == "pending", out
    # Недавно Pending без признака неразмещаемости: молчит.
    assert alerts.check_pending([{"name": "api-1-2", "phase": "Pending",
                                  "creation_timestamp": fresh}], NOW) == []
    # Явная неразмещаемость без метки времени: срабатывает.
    out = alerts.check_pending([{"name": "api-1-2", "phase": "Pending",
                                 "waiting_reason": "Unschedulable"}], NOW)
    assert out and out[0]["params"]["reason"] == "Unschedulable", out


def test_restart_storm_within_window():
    recent = (NOW - timedelta(seconds=60)).isoformat()
    old = (NOW - timedelta(seconds=alerts.RESTART_WINDOW_SECONDS + 60)).isoformat()
    pods = [{"name": "web-1-2", "phase": "Running", "waiting_reason": None, "oom_killed": False,
             "restarts": alerts.RESTART_STORM_THRESHOLD, "last_restart_at": recent}]
    out = alerts.check_restart_storm(pods, NOW)
    assert out and out[0]["code"] == "restart_storm", out
    # За окном наблюдения: молчит.
    pods[0]["last_restart_at"] = old
    assert alerts.check_restart_storm(pods, NOW) == []
    # CrashLoopBackOff покрыт отдельным детектором, тут не дублируется.
    pods[0]["last_restart_at"] = recent
    pods[0]["waiting_reason"] = "CrashLoopBackOff"
    assert alerts.check_restart_storm(pods, NOW) == []


# ---------------------------------------------------------------------------
# Симптомы уровня деплойментов.
# ---------------------------------------------------------------------------


def test_deploy_unavailable():
    deps = [
        {"name": "web", "desired": 3, "ready": 1},
        {"name": "api", "desired": 2, "ready": 0},
        {"name": "worker", "desired": 2, "ready": 2},
    ]
    out = alerts.check_deploy_unavailable(deps)
    got = {a["params"]["deployment"]: a["severity"] for a in out}
    assert got == {"web": "high", "api": "critical"}, got
    assert alerts.check_deploy_unavailable([]) == []


# ---------------------------------------------------------------------------
# Симптомы уровня узлов.
# ---------------------------------------------------------------------------


def _node(name="node-a", **kw):
    base = {"name": name, "ready": True, "memory_pressure": False, "disk_pressure": False,
            "capacity": {"cpu": "4", "memory": "8Gi"}}
    base.update(kw)
    return base


def test_node_disk_thresholds():
    node = _node()
    warn = {"node": {"fs": {"usedBytes": alerts.DISK_WARN_PCT, "capacityBytes": 100}}}
    out = alerts.check_node_disk([node], {"node-a": warn})
    assert out and out[0]["severity"] == "warning" and out[0]["params"]["crit"] is False, out
    crit = {"node": {"fs": {"usedBytes": alerts.DISK_CRIT_PCT, "capacityBytes": 100}}}
    out = alerts.check_node_disk([node], {"node-a": crit})
    assert out[0]["severity"] == "critical" and out[0]["params"]["crit"] is True, out
    ok = {"node": {"fs": {"usedBytes": 10, "capacityBytes": 100}}}
    assert alerts.check_node_disk([node], {"node-a": ok}) == []


def test_node_memory_and_pressure():
    node = _node()
    hot = {"node": {"memory": {"workingSetBytes": alerts.MEM_WARN_PCT, "availableBytes":
                               100 - alerts.MEM_WARN_PCT}}}
    out = alerts.check_node_memory([node], {"node-a": hot})
    assert out and out[0]["code"] == "node_memory", out
    # Условия узла: не Ready критично, давления высоки.
    out = alerts.check_node_pressure([_node(ready=False),
                                      _node(name="node-b", memory_pressure=True),
                                      _node(name="node-c", disk_pressure=True)])
    codes = _codes(out)
    assert "node_not_ready" in codes and "node_pressure" in codes, codes
    assert any(a["severity"] == "critical" for a in out), out


# ---------------------------------------------------------------------------
# Симптомы уровня событий кластера.
# ---------------------------------------------------------------------------


def test_warning_events_grouped():
    events = [
        {"type": "Warning", "reason": "FailedScheduling", "object": "api-1", "count": 3,
         "message": "no nodes available"},
        {"type": "Warning", "reason": "FailedScheduling", "object": "api-2", "count": 2,
         "message": "no nodes available"},
        {"type": "Warning", "reason": "FailedMount", "object": "db-0", "count": 1,
         "message": "timed out"},
        {"type": "Normal", "reason": "Scheduled", "object": "api-3", "count": 1, "message": "ok"},
    ]
    out = alerts.check_warning_events(events)
    by_reason = {a["params"]["reason"]: a for a in out}
    assert set(by_reason) == {"FailedScheduling", "FailedMount"}, by_reason
    assert by_reason["FailedScheduling"]["params"]["count"] == 5, by_reason
    assert by_reason["FailedScheduling"]["params"]["objects"] == ["api-1", "api-2"], by_reason


def test_tls_expiry():
    assert alerts.check_tls_expiry(None) == []
    assert alerts.check_tls_expiry(alerts.TLS_WARN_DAYS + 1) == []
    assert alerts.check_tls_expiry(alerts.TLS_WARN_DAYS)[0]["severity"] == "warning"
    assert alerts.check_tls_expiry(alerts.TLS_HIGH_DAYS)[0]["severity"] == "high"


# ---------------------------------------------------------------------------
# Прогон всего каталога.
# ---------------------------------------------------------------------------


def test_detect_all_empty_is_silent():
    # Пустые факты (все источники None) НЕ дают ложных симптомов: различение слепоты и здоровья
    # выполняет автопилот, а каталог просто молчит.
    assert alerts.detect_all({}) == []
    assert alerts.detect_all({"pods": None, "nodes": None, "deployments": None,
                              "events": None, "stats_by_node": {}}) == []


def test_detect_all_universal_symptoms():
    facts = {
        "now": NOW,
        "nodes": [_node(disk_pressure=True)],
        "stats_by_node": {"node-a": {"node": {"fs": {"usedBytes": 95, "capacityBytes": 100}}}},
        "pods": [
            {"name": "web-1-2", "phase": "Running", "waiting_reason": "CrashLoopBackOff"},
            {"name": "api-3-4", "phase": "Pending", "waiting_reason": "ImagePullBackOff"},
            {"name": "worker-5-6", "phase": "Running", "waiting_reason": None, "oom_killed": True},
        ],
        "deployments": [{"name": "web", "desired": 3, "ready": 0}],
        "events": [{"type": "Warning", "reason": "FailedScheduling", "object": "api-3",
                    "count": 1, "message": "no nodes"}],
        "tls_days": 5,
    }
    codes = _codes(alerts.detect_all(facts))
    for expected in ("crashloop", "image_pull", "oom_killed", "deploy_unavailable",
                     "node_disk", "node_pressure", "warning_event", "tls_expiry"):
        assert expected in codes, (expected, codes)
    # Никаких доменных кодов наследной платформы (A1..A12) не осталось.
    assert not any(c.startswith("A") and c[1:].isdigit() for c in codes), codes


# ---------------------------------------------------------------------------
# Статусные сводки: домен-нейтральность и корректность.
# ---------------------------------------------------------------------------


def test_pods_by_phase():
    pods = [{"name": "a", "phase": "Running"}, {"name": "b", "phase": "Running"},
            {"name": "c", "phase": "Pending"}]
    assert status_cards.pods_by_phase(pods) == {"Running": 2, "Pending": 1}


def test_status_card_neutral_and_unavailable():
    # Слепота: карточка честно сообщает о недоступности, а не выдумывает здоровье.
    card = status_cards.build_status_card(None, None, {}, None, None, None, now=NOW)
    assert "недоступно" in card
    # Наполненная карточка домен-нейтральна и не содержит наследных упоминаний.
    nodes = [_node()]
    pods = [{"name": "web-1-2", "phase": "Running", "waiting_reason": None, "restarts": 0}]
    deps = [{"name": "web", "desired": 2, "ready": 1}]
    events = [{"type": "Warning", "reason": "FailedMount", "object": "db-0", "count": 1,
               "message": "timeout"}]
    card = status_cards.build_status_card(nodes, pods, {"node-a": {"node": {}}}, deps, events,
                                          10, now=NOW)
    for banned in ("krokki", "asr", "diarize", "stalwart", "транскрибац", "YooKassa", "биллинг"):
        assert banned.lower() not in card.lower(), (banned, card)
    assert "готово 1 из 2" in card
    assert "FailedMount" in card
    assert "Сертификат TLS: осталось 10" in card


def test_report_card():
    tmp = Path(tempfile.mkdtemp())
    incidents.STORE_DIR = tmp
    incidents._groups.clear()
    incidents._active.clear()

    def iso(dt):
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000Z"

    groups = [
        {"id": "INC-1", "title": "web в CrashLoopBackOff", "count": 4,
         "last_seen": iso(NOW - timedelta(hours=1)), "lifecycle": "resolved_auto",
         "reopened_from": None},
        {"id": "INC-2", "title": "узел не Ready", "count": 1,
         "last_seen": iso(NOW - timedelta(hours=2)), "lifecycle": "escalated",
         "reopened_from": None},
        {"id": "INC-3", "title": "диск полон", "count": 2,
         "last_seen": iso(NOW - timedelta(hours=3)), "lifecycle": "resolved_auto",
         "reopened_from": "INC-0"},
        {"id": "INC-OLD", "title": "старое", "count": 9,
         "last_seen": iso(NOW - timedelta(hours=48)), "lifecycle": "escalated",
         "reopened_from": None},
    ]
    guard_state = {"budget_total": 6, "budget_left": 4, "breaker_active": False,
                   "consecutive_failures": 0,
                   "last_actions": [{"ts": 1.0, "action": "investigate", "outcome": "успех"}]}
    card = status_cards.build_report_card(groups, guard_state, now=NOW)
    assert "инцидентов за окно: 3" in card, card
    assert "решил сам (resolved_auto): 2" in card, card
    assert "эскалировал: 1" in card, card
    assert "переоткрытий (хронические): 1" in card, card
    assert "INC-1" in card and "старое" not in card, card
    assert "бюджет действий: осталось 4 из 6" in card, card
