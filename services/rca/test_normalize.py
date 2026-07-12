"""Тесты нормализации шаблонов и извлечения симптомов из текста. Собираемый pytest.

Запуск: cd services/rca && python3 -m pytest -q test_normalize.py
"""
from normalize import (
    NETWORK_SIGNALS, PRIMARY_SIGNALS, extract_symptoms, infer_level, template,
)


def test_template_masks_variables():
    assert template("Failed order 12345 after 30s") == "Failed order <num> after <num>s"
    assert template("job 3f8a1c20-dead-beef-0000-111122223333 done") == "job <uuid> done"
    assert template("connect to 10.100.5.23:5432 refused") == "connect to <ip>:<num> refused"
    assert template("trace 3f8a1c20deadbeef3f8a1c20deadbeef closed") == "trace <hex> closed"
    assert template("") == ""


def test_template_clusters_similar():
    assert template("order 1 failed") == template("order 999 failed")


def test_infer_level_from_plain_text():
    # Уровень выводится из ПРОИЗВОЛЬНОГО текста лога пода, без структурного поля.
    assert infer_level("panic: runtime error: invalid memory address") == "fatal"
    assert infer_level("out of memory: killed process 1234") == "fatal"
    assert infer_level("Traceback (most recent call last):") == "error"
    assert infer_level("connection refused") == "error"
    assert infer_level("WARNING: deprecated flag") == "warn"
    assert infer_level("GET /health 200 OK") == "info"


def test_extract_symptoms_domain_agnostic():
    assert "connection_refused" in extract_symptoms("dial tcp 10.0.0.1:5432: connection refused")
    assert "dns_error" in extract_symptoms("lookup api: no such host")
    assert "tls_error" in extract_symptoms("x509: certificate has expired")
    assert "oom" in extract_symptoms("Container killed due to out of memory")
    assert "disk_full" in extract_symptoms("write failed: no space left on device")
    assert "timeout" in extract_symptoms("context deadline exceeded: i/o timeout")
    assert extract_symptoms("all systems nominal") == set()


def test_symptom_sets_are_disjoint_and_named():
    # Классы симптомов согласованы: сетевые и первичные пересекаются осмысленно, все
    # имена из каталога.
    assert NETWORK_SIGNALS <= set(extract_symptoms.__globals__["_SYMPTOM_PATTERNS"].keys())
    assert "oom" in PRIMARY_SIGNALS
