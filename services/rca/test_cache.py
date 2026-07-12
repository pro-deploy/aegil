"""Тесты ограниченного кэша с вытеснением и тревогой. Собираемый вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_cache.py
"""
from cache import BoundedCache


def _make(alarms):
    now = [0.0]
    c = BoundedCache(capacity=3, ttl_seconds=10, on_alarm=lambda n, cap: alarms.append((n, cap)),
                     alarm_ratio=0.8, clock=lambda: now[0])
    return c, now


def test_get_set_and_alarm():
    alarms = []
    c, _ = _make(alarms)
    c.set("a", 1)
    c.set("b", 2)
    assert c.get("a") == 1
    assert alarms == []           # 2/3 = 0.67 < 0.8
    c.set("c", 3)                 # 3/3 = 1.0 >= 0.8 -> тревога один раз
    assert alarms == [(3, 3)]


def test_lru_eviction():
    alarms = []
    c, _ = _make(alarms)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)
    c.get("a")                    # обращение делает "a" свежим
    c.set("d", 4)                 # переполнение вытесняет наименее недавний ("b")
    assert len(c) == 3
    assert c.get("b") is None
    assert c.get("a") == 1
    assert c.get("d") == 4


def test_ttl_eviction():
    alarms = []
    c, now = _make(alarms)
    c.set("a", 1)
    c.set("c", 3)
    c.set("d", 4)
    now[0] = 100.0                # сдвиг за пределы времени жизни
    assert c.get("a") is None
    assert c.get("c") is None
    assert c.get("d") is None
    assert len(c) == 0
