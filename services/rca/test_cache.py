"""Модульный тест ограниченного кэша (ADR-0032, Часть A завершающая).
Запуск без зависимостей: python3 services/rca/test_cache.py
"""
from cache import BoundedCache


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def main() -> None:
    now = [0.0]
    clock = lambda: now[0]
    alarms = []

    c = BoundedCache(capacity=3, ttl_seconds=10, on_alarm=lambda n, cap: alarms.append((n, cap)),
                     alarm_ratio=0.8, clock=clock)

    c.set("a", 1)
    c.set("b", 2)
    _eq("get a", c.get("a"), 1)
    _eq("no alarm yet", alarms, [])   # 2/3 = 0.67 < 0.8

    c.set("c", 3)                      # 3/3 = 1.0 >= 0.8 → тревога один раз
    _eq("alarm fired", alarms, [(3, 3)])

    # Вытеснение по давности: обращение к "a" делает его свежим, вытеснится "b".
    c.get("a")
    c.set("d", 4)                      # переполнение → вытесняется наименее недавний ("b")
    _eq("len capped", len(c), 3)
    _eq("b evicted", c.get("b"), None)
    _eq("a kept", c.get("a"), 1)
    _eq("d kept", c.get("d"), 4)

    # Вытеснение по времени жизни (ленивое, при обращении): сдвигаем часы за TTL.
    now[0] = 100.0
    _eq("a expired", c.get("a"), None)
    _eq("c expired", c.get("c"), None)
    _eq("d expired", c.get("d"), None)
    _eq("empty after ttl", len(c), 0)

    print("cache: all asserts passed")


if __name__ == "__main__":
    main()
