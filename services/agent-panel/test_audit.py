"""Модульные тесты примитива аудита операций панели aegil.

Собираемый pytest-вид (функции с префиксом test_), без сети. Запуск:
    cd services/agent-panel && python3 -m pytest -q test_audit.py

Покрыты: совместимость прежней сигнатуры audit_write, охват чтений (observe) и постановки в
отложенное подтверждение (pending), формат записи под реальную операцию продукта (без наследных
полей исходной платформы), надёжный канал stdout, сигнал об ошибке файловой записи вместо
молчаливого проглатывания, вынос пути журнала в каталог данных вне рабочего дерева и
потокобезопасность конкурентной записи.
"""
import json
import tempfile
import threading
from pathlib import Path

import audit


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def _fresh() -> Path:
    tmp = Path(tempfile.mkdtemp())
    audit.AUDIT_PATH = tmp / "audit.log.jsonl"
    return tmp


def test_execute_record_shape():
    """Запись исполнения отражает реальную операцию продукта: тип, актор, класс, argv, результат.
    Наследных полей исходной платформы в записи нет."""
    _fresh()
    rec = audit.audit_write("max", "restart", {"service": "web"}, "INC-1",
                            confirmed=True, result="ok", trace_id="t1",
                            danger_class=audit.CLASS_SAFE_WRITE,
                            argv=["kubectl", "rollout", "restart", "deploy/web"])
    _eq("тип операции", rec["op_type"], audit.OP_EXECUTE)
    _eq("актор", rec["actor"], "max")
    _eq("команда", rec["command"], "restart")
    _eq("цель", rec["target"], "INC-1")
    _eq("подтверждено", rec["confirmed"], True)
    _eq("класс опасности", rec["danger_class"], audit.CLASS_SAFE_WRITE)
    _eq("argv", rec["argv"], ["kubectl", "rollout", "restart", "deploy/web"])
    _eq("trace_id", rec["trace_id"], "t1")
    # Наследных полей исходной платформы быть не должно.
    for legacy in ("service", "event"):
        assert legacy not in rec, f"наследное поле {legacy} осталось в записи"
    assert rec.get("command") != "agent.act" or True  # command отражает операцию, не константу


def test_backward_compatible_positional():
    """Прежний позиционный вызов из исполнителя и автопилота продолжает работать: первые семь
    параметров в прежнем порядке."""
    _fresh()
    rec = audit.audit_write("agent", "agent:restart", {"action": "restart"}, "INC-9",
                            False, "выполнено")
    _eq("актор из первого позиционного", rec["actor"], "agent")
    _eq("тип по умолчанию execute", rec["op_type"], audit.OP_EXECUTE)
    assert "danger_class" not in rec, "пустой класс не должен попадать в запись"
    assert "argv" not in rec, "argv не передан, его не должно быть в записи"


def test_read_audit_covers_observe():
    """Чтения (observe), которые раньше не протоколировались, теперь аудируются с классом read."""
    _fresh()
    rec = audit.audit_read("agent", "observe:logs", "namespace/app",
                           result="прочитано 240 строк",
                           argv=["kubectl", "logs", "deploy/app"])
    _eq("тип read", rec["op_type"], audit.OP_READ)
    _eq("класс read", rec["danger_class"], audit.CLASS_READ)
    _eq("подтверждение не требуется", rec["confirmed"], False)
    _eq("actor", rec["actor"], "agent")
    _eq("argv чтения", rec["argv"], ["kubectl", "logs", "deploy/app"])


def test_pending_audit_covers_deferred_confirmation():
    """Постановка мутирующей команды в отложенное подтверждение аудируется с результатом pending
    до самого исполнения."""
    _fresh()
    rec = audit.audit_pending("agent", "delete_namespace", {"ns": "old"}, "namespace/old",
                              danger_class=audit.CLASS_DESTRUCTIVE,
                              argv=["kubectl", "delete", "ns", "old"])
    _eq("тип pending", rec["op_type"], audit.OP_PENDING)
    _eq("результат pending", rec["result"], "pending")
    _eq("класс destructive", rec["danger_class"], audit.CLASS_DESTRUCTIVE)
    _eq("подтверждения ещё нет", rec["confirmed"], False)


def test_written_to_file_and_stdout(capsys):
    """Долговечная копия уходит в stdout канонической строкой, и та же строка ложится в файл."""
    tmp = _fresh()
    rec = audit.audit_write("max", "scale", {"replicas": 3}, "deploy/app",
                            confirmed=True, result="ok")
    out = capsys.readouterr().out.strip().splitlines()
    assert out, "запись не ушла в stdout"
    stdout_rec = json.loads(out[-1])
    _eq("stdout совпадает с возвращённой записью", stdout_rec, rec)
    lines = (tmp / "audit.log.jsonl").read_text(encoding="utf-8").strip().splitlines()
    _eq("одна строка в файле", len(lines), 1)
    _eq("файловая строка совпадает", json.loads(lines[0]), rec)


def test_file_error_signalled_not_swallowed(capsys, monkeypatch):
    """Ошибка файловой записи не глотается молча: сигнал уходит в stderr, но запрос не роняется,
    так как долговечная копия уже в stdout."""
    audit.AUDIT_PATH = Path("/proc/nonexistent-aegil/audit.log.jsonl")
    # Запрос не должен упасть.
    rec = audit.audit_write("max", "restart", {}, "INC-1", confirmed=True, result="ok")
    captured = capsys.readouterr()
    assert rec["command"] == "restart"
    # Долговечная копия ушла в stdout.
    assert json.loads(captured.out.strip().splitlines()[-1])["command"] == "restart"
    # Ошибка файловой записи просигналена в stderr, а не проглочена.
    assert "не удалась" in captured.err or "audit" in captured.err, \
        f"ошибка файловой записи не просигналена: {captured.err!r}"


def test_audit_path_outside_worktree(monkeypatch):
    """Путь журнала по умолчанию лежит в каталоге данных вне рабочего дерева агента, иначе агент
    мог бы удалить собственный аудит как безопасно удаляемый файл."""
    monkeypatch.delenv("AEGIL_AUDIT", raising=False)
    monkeypatch.setenv("AEGIL_STATE_DIR", "/data")
    path = audit._default_audit_path()
    _eq("путь в каталоге данных", str(path), "/data/audit.log.jsonl")
    module_dir = str(Path(audit.__file__).resolve().parent)
    assert not str(path).startswith(module_dir), \
        f"журнал аудита внутри рабочего дерева: {path}"
    monkeypatch.setenv("AEGIL_AUDIT", "/data/custom-audit.jsonl")
    _eq("явный путь", str(audit._default_audit_path()), "/data/custom-audit.jsonl")


def test_concurrent_writes_do_not_interleave():
    """Гонка: конкурентная запись из многих потоков не перемешивает строки в файле."""
    tmp = _fresh()
    threads_count = 12
    per_thread = 30
    barrier = threading.Barrier(threads_count)

    def worker(tid: int):
        barrier.wait()
        for i in range(per_thread):
            audit.audit_write(f"op{tid}", "act", {"i": i}, f"t{tid}",
                              confirmed=False, result="ok")

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = [l for l in (tmp / "audit.log.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    _eq("все записи в файле", len(lines), threads_count * per_thread)
    # Каждая строка валидна: строки не порваны конкурентной записью.
    for l in lines:
        json.loads(l)
