"""Тесты модуля записи исходов ремонтов outcomes. Собираемый вид pytest, без сети.

Клиент сервиса разбора первопричин подменяется подделкой через monkeypatch, каталог локального
журнала переводится во временную папку переменной AEGIL_STATE_DIR, поэтому проверки идут офлайн
и не трогают постоянный том. Проверяется, что разрешённый инцидент оставляет оба следа: строку
локального журнала формата JSON и push в сервис разбора первопричин.

Запуск: cd services/agent-panel && python3 -m pytest -q test_outcomes.py
"""
import json

import pytest

import outcomes


@pytest.fixture
def journal_dir(tmp_path, monkeypatch):
    # Каталог состояния во временную папку: journal_path вычисляется при каждом вызове, поэтому
    # переопределение переменной вступает в силу немедленно.
    monkeypatch.setenv("AEGIL_STATE_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def captured_push(monkeypatch):
    # Подделка клиента: фиксирует адрес и тело push, не ходит в сеть.
    calls = []

    def _rec(rca_url, payload):
        calls.append((rca_url, payload))
        return True

    monkeypatch.setattr(outcomes.rca_client, "record_outcome", _rec)
    return calls


def _read_journal(path):
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


def test_record_writes_journal_line(journal_dir, captured_push, monkeypatch):
    # Первый след: строка локального журнала с отпечатком, статусом, первопричиной, действием и
    # признаком устранения, плюс метка времени.
    monkeypatch.setattr(outcomes.config, "RCA_URL", "http://rca:9107")
    verdict = {"status": "incident", "root_cause": "out_of_memory",
               "detectors": ["oom"], "fingerprint": "incident|oom|out_of_memory"}
    outcomes.record(verdict, action="restart", resolved=True)

    entries = _read_journal(outcomes.journal_path())
    assert len(entries) == 1
    e = entries[0]
    assert e["fingerprint"] == "incident|oom|out_of_memory"
    assert e["status"] == "incident"
    assert e["root_cause"] == "out_of_memory"
    assert e["action"] == "restart"
    assert e["resolved"] is True
    assert e["ts"]


def test_record_pushes_to_rca(journal_dir, captured_push, monkeypatch):
    # Второй след: push в сервис разбора первопричин по адресу из config.RCA_URL с телом исхода без
    # служебной метки времени.
    monkeypatch.setattr(outcomes.config, "RCA_URL", "http://rca:9107")
    verdict = {"status": "incident", "root_cause": "disk_full", "detectors": ["disk"]}
    outcomes.record(verdict, action="cleanup", resolved=True)

    assert len(captured_push) == 1
    url, payload = captured_push[0]
    assert url == "http://rca:9107"
    assert payload["action"] == "cleanup"
    assert payload["resolved"] is True
    assert "ts" not in payload


def test_record_explicit_rca_url_overrides_config(journal_dir, captured_push, monkeypatch):
    # Явный адрес имеет приоритет над config.RCA_URL.
    monkeypatch.setattr(outcomes.config, "RCA_URL", "http://default:9107")
    outcomes.record({"status": "degraded"}, action="noop", resolved=False,
                    rca_url="http://explicit:9107")
    assert captured_push[0][0] == "http://explicit:9107"


def test_fingerprint_computed_when_absent(journal_dir, captured_push, monkeypatch):
    # Без готового поля fingerprint отпечаток вычисляется из статуса, детекторов и первопричины тем
    # же способом, что и в модуле инцидентов.
    monkeypatch.setattr(outcomes.config, "RCA_URL", "http://rca:9107")
    verdict = {"status": "incident", "root_cause": "network", "detectors": ["net", "dns"]}
    outcomes.record(verdict, action="restart", resolved=True)
    fp = captured_push[0][1]["fingerprint"]
    assert fp == "incident|dns,net|network"


def test_record_survives_push_failure(journal_dir, monkeypatch):
    # Отказ второго следа (push бросает) не роняет вызывающего и не отменяет первый след.
    monkeypatch.setattr(outcomes.config, "RCA_URL", "http://rca:9107")

    def _boom(rca_url, payload):
        raise RuntimeError("клиент сломался")

    monkeypatch.setattr(outcomes.rca_client, "record_outcome", _boom)
    outcomes.record({"status": "incident", "fingerprint": "fp"}, action="a", resolved=True)
    entries = _read_journal(outcomes.journal_path())
    assert len(entries) == 1
    assert entries[0]["fingerprint"] == "fp"


def test_journal_falls_back_on_unwritable_dir(captured_push, monkeypatch, tmp_path):
    # Недоступный основной каталог: запись откатывается на временный каталог, сигнал уходит в
    # stderr, вызывающий не падает.
    import tempfile

    monkeypatch.setenv("AEGIL_STATE_DIR", "/proc/nonexistent/aegil-outcomes")
    monkeypatch.setattr(outcomes.config, "RCA_URL", "http://rca:9107")
    fallback = tmp_path / "fallback"
    fallback.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(fallback))
    monkeypatch.setattr(outcomes.tempfile, "gettempdir", lambda: str(fallback))

    outcomes.record({"status": "incident", "fingerprint": "fp"}, action="a", resolved=True)
    fb_file = fallback / "outcomes.jsonl"
    assert fb_file.exists()
    entries = _read_journal(fb_file)
    assert entries[0]["fingerprint"] == "fp"


def test_journal_appends_multiple(journal_dir, captured_push, monkeypatch):
    # Несколько исходов дозаписываются строками, а не перетирают файл.
    monkeypatch.setattr(outcomes.config, "RCA_URL", "http://rca:9107")
    outcomes.record({"status": "incident", "fingerprint": "a"}, action="x", resolved=True)
    outcomes.record({"status": "incident", "fingerprint": "b"}, action="y", resolved=False)
    entries = _read_journal(outcomes.journal_path())
    assert [e["fingerprint"] for e in entries] == ["a", "b"]
    assert [e["resolved"] for e in entries] == [True, False]
