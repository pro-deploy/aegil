"""Модульный тест нормализации шаблонов (ADR-0032, Часть B).
Запуск без зависимостей: python3 services/rca/test_normalize.py
"""
from normalize import template


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def main() -> None:
    _eq("num", template("Failed order 12345 after 30s"), "Failed order <num> after <num>s")
    _eq("uuid", template("job 3f8a1c20-dead-beef-0000-111122223333 done"), "job <uuid> done")
    _eq("ip+port", template("connect to 10.100.5.23:5432 refused"), "connect to <ip>:<num> refused")
    _eq("hex", template("trace 3f8a1c20deadbeef3f8a1c20deadbeef closed"), "trace <hex> closed")
    _eq("empty", template(""), "")
    # Кластеризация: две строки с разными переменными дают один шаблон.
    _eq("cluster", template("order 1 failed") == template("order 999 failed"), True)
    print("normalize: all asserts passed")


if __name__ == "__main__":
    main()
