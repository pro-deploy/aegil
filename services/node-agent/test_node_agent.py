"""Тесты node-agent продукта kube-sentinel. Собираются стандартным сборщиком pytest, сети не требуют.

Запуск: cd services/node-agent && python3 -m pytest -q

Проверяются: валидация тела /run (пустой argv, некорректный timeout, превышение лимитов ведут к
ошибке); корректная сборка команды nsenter (argv остаётся списком аргументов и НЕ превращается в
строку оболочки); отсечение разделителем -- попытки подсунуть в argv флаги самого nsenter; обрезка
слишком длинного вывода; маскирование секретов в логах; очистка окружения дочернего процесса от
секретов агента; fail-closed отказ без валидного токена; и на HTTP-уровне порядок «аутентификация
до чтения тела»: POST /run без заголовка и с неверным токеном возвращает 401 и НИЧЕГО не исполняет.
subprocess мокается, реальный nsenter не вызывается.

В коде тестов не должно быть длинного тире и стрелок. Там, где запрещённый символ нужен как данные
(например метасимволы оболочки в проверке инъекции), он записан обычными ASCII-символами.
"""
import http.client
import os
import sys
import threading
from http.server import ThreadingHTTPServer
from unittest import mock

import pytest

# Обеспечиваем предсказуемое имя узла и секрет ДО импорта модуля: значения читаются на импорте.
# Единый префикс продукта SENTINEL_.
os.environ.setdefault("SENTINEL_NODE_NAME", "test-node")
os.environ.setdefault("SENTINEL_NODEAGENT_TOKEN", "s3cr3t-token")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app  # noqa: E402


# --- Валидация тела ---------------------------------------------------------------------------

def test_empty_argv_rejected():
    with pytest.raises(ValueError):
        app.validate_body({"argv": [], "timeout": 30})


def test_missing_argv_rejected():
    with pytest.raises(ValueError):
        app.validate_body({"timeout": 30})


def test_argv_must_be_list_of_strings():
    with pytest.raises(ValueError):
        app.validate_body({"argv": ["df", 5], "timeout": 30})


def test_bad_timeout_too_small():
    with pytest.raises(ValueError):
        app.validate_body({"argv": ["df", "-h"], "timeout": 0})


def test_bad_timeout_too_large():
    with pytest.raises(ValueError):
        app.validate_body({"argv": ["df", "-h"], "timeout": 9999})


def test_timeout_not_a_number():
    with pytest.raises(ValueError):
        app.validate_body({"argv": ["df", "-h"], "timeout": "быстро"})


def test_bool_is_not_a_valid_timeout():
    with pytest.raises(ValueError):
        app.validate_body({"argv": ["df"], "timeout": True})


def test_valid_body_defaults_timeout():
    argv, timeout = app.validate_body({"argv": ["df", "-h", "/"]})
    assert argv == ["df", "-h", "/"]
    assert timeout == 30


def test_too_many_argv_items_rejected():
    big = ["x"] * (app.MAX_ARGV_ITEMS + 1)
    with pytest.raises(ValueError):
        app.validate_body({"argv": big, "timeout": 30})


def test_too_large_argv_total_rejected():
    # Один длинный аргумент сверх суммарного лимита длины отклоняется.
    huge = "a" * (app.MAX_ARGV_TOTAL_BYTES + 1)
    with pytest.raises(ValueError):
        app.validate_body({"argv": ["echo", huge], "timeout": 30})


# --- Сборка команды и разделитель -- ----------------------------------------------------------

def test_nsenter_prefix_and_argv_as_list():
    argv = ["df", "-h", "/"]
    cmd = app.build_command(argv)
    # Команда обязана быть списком, начинаться с nsenter и заканчиваться исходным argv без какого-либо
    # склеивания в строку.
    assert isinstance(cmd, list)
    assert cmd[:8] == ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--"]
    assert cmd[8:] == argv


def test_no_shell_injection_metacharacters_are_literal():
    # Метасимволы оболочки внутри argv должны остаться отдельным литеральным аргументом, а не
    # интерпретироваться: подтверждение того, что оболочка не участвует.
    payload = "; rm -rf / #"
    cmd = app.build_command(["echo", payload])
    assert payload in cmd
    assert "sh" not in cmd
    assert "-c" not in cmd
    assert len(cmd) == len(app.NSENTER_PREFIX) + 2


def test_double_dash_isolates_nsenter_flags():
    # Попытка подсунуть в argv флаги самого nsenter (например -t 999 для входа в чужой процесс, или
    # --preserve-credentials) обязана оказаться ПОСЛЕ разделителя --, то есть быть аргументами
    # исполняемой программы, а не опциями nsenter. Проверяем, что -- стоит ровно один раз и все
    # переданные пользователем элементы лежат строго после него.
    hostile = ["-t", "999", "--preserve-credentials", "sh"]
    cmd = app.build_command(hostile)
    idx = cmd.index("--")
    # После разделителя идут ровно враждебные элементы, до него только доверенный префикс nsenter.
    assert cmd[idx + 1:] == hostile
    assert "--" not in cmd[idx + 1:]
    # Ни один из враждебных флагов не попал в позицию опций nsenter (до разделителя).
    assert cmd[:idx] == app.NSENTER_PREFIX[:-1]


# --- Исполнение -------------------------------------------------------------------------------

def _fake_popen(returncode=0, stdout=b"", stderr=b""):
    """Собрать мок subprocess.Popen: communicate возвращает (stdout, stderr), returncode задан."""
    fake = mock.Mock()
    fake.pid = 4242
    fake.returncode = returncode
    fake.communicate = mock.Mock(return_value=(stdout, stderr))
    return fake


def test_uses_list_argv_without_shell():
    fake = _fake_popen(returncode=0, stdout=b"ok", stderr=b"")
    with mock.patch.object(app.subprocess, "Popen", return_value=fake) as popen:
        result = app.run_host_command(["df", "-h", "/"], 30)
    called_args, called_kwargs = popen.call_args
    # Первый позиционный аргумент Popen это список, а не строка.
    assert isinstance(called_args[0], list)
    assert called_args[0][:8] == ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--"]
    # shell=True не передавался ни при каких обстоятельствах.
    assert "shell" not in called_kwargs
    # Отдельная сессия для снятия всей группы процессов по таймауту.
    assert called_kwargs.get("start_new_session") is True
    assert result["exit_code"] == 0
    assert result["stdout"] == "ok"
    assert result["node"] == "test-node"


def test_child_environment_is_scrubbed_of_agent_secrets():
    # Дочерний процесс НЕ должен получить секрет агента в окружении: иначе исполненная команда
    # прочитает его через /proc/self/environ.
    fake = _fake_popen(returncode=0, stdout=b"", stderr=b"")
    with mock.patch.dict(os.environ, {"SENTINEL_NODEAGENT_TOKEN": "s3cr3t-token", "PATH": "/usr/bin"}):
        with mock.patch.object(app.subprocess, "Popen", return_value=fake) as popen:
            app.run_host_command(["df"], 30)
    _, called_kwargs = popen.call_args
    env = called_kwargs.get("env")
    assert env is not None, "окружение дочернего процесса должно задаваться явно (env=), не наследоваться"
    assert "SENTINEL_NODEAGENT_TOKEN" not in env
    # Ни одна переменная с префиксом продукта не просачивается в дочерний процесс.
    assert not any(k.startswith("SENTINEL_") for k in env)
    # PATH при этом сохранён, чтобы утилиты находились.
    assert env.get("PATH") == "/usr/bin"


def test_output_truncation():
    big = b"a" * (app.MAX_OUTPUT_BYTES + 100)
    fake = _fake_popen(returncode=0, stdout=big, stderr=b"")
    with mock.patch.object(app.subprocess, "Popen", return_value=fake):
        result = app.run_host_command(["cat", "/big"], 30)
    assert result["stdout"].endswith(app.TRUNCATED_MARK)
    assert len(result["stdout"]) <= app.MAX_OUTPUT_BYTES + len(app.TRUNCATED_MARK)


def test_timeout_returns_124_and_kills_group():
    # По таймауту communicate бросает TimeoutExpired; обработчик обязан снять ВСЮ группу процессов
    # (killpg), а не только прямого потомка, и вернуть код 124.
    fake = mock.Mock()
    fake.pid = 4242
    fake.returncode = -9
    fake.communicate = mock.Mock(side_effect=[
        app.subprocess.TimeoutExpired(cmd=["nsenter"], timeout=5),
        (b"", b""),
    ])
    fake.wait = mock.Mock(return_value=0)
    with mock.patch.object(app.subprocess, "Popen", return_value=fake):
        with mock.patch.object(app.os, "killpg") as killpg:
            result = app.run_host_command(["sleep", "999"], 5)
    assert result["exit_code"] == app.TIMEOUT_EXIT_CODE
    assert "таймаут" in result["stderr"]
    # Группа процессов действительно снималась (killpg по идентификатору процесса потомка).
    assert killpg.called
    assert killpg.call_args_list[0].args[0] == 4242


# --- Маскирование секретов в логах ------------------------------------------------------------

def test_mask_argv_hides_value_after_password_flag():
    masked = app._mask_argv(["mysql", "-u", "root", "--password", "hunter2", "db"])
    assert "hunter2" not in masked
    assert app.MASK in masked
    # Сам флаг и прочие безобидные аргументы сохранены.
    assert "--password" in masked
    assert "root" in masked


def test_mask_argv_hides_inline_equals_form():
    masked = app._mask_argv(["curl", "--token=abcdef", "https://x"])
    assert "--token=abcdef" not in masked
    assert "--token=" + app.MASK in masked


def test_mask_argv_does_not_touch_program_name():
    # argv[0] (сама программа) не маскируется, даже если совпала бы по имени с флагом.
    masked = app._mask_argv(["-p"])
    assert masked == ["-p"]


def test_run_command_logs_only_program_and_argc_not_values(capsys):
    fake = _fake_popen(returncode=0, stdout=b"", stderr=b"")
    with mock.patch.object(app.subprocess, "Popen", return_value=fake):
        app.run_host_command(["mysql", "--password", "hunter2"], 30)
    captured = capsys.readouterr()
    # Значение секрета НЕ должно попасть в лог.
    assert "hunter2" not in captured.out
    # А имя программы и число аргументов должны.
    assert "mysql" in captured.out
    assert "argc" in captured.out


# --- Сверка токена ----------------------------------------------------------------------------

def test_reject_without_token():
    assert app.token_ok("") is False


def test_reject_wrong_token():
    assert app.token_ok("wrong") is False


def test_accept_correct_token():
    assert app.token_ok("s3cr3t-token") is True


def test_fail_closed_when_server_secret_empty():
    with mock.patch.object(app, "NODEAGENT_TOKEN", ""):
        assert app.token_ok("") is False
        assert app.token_ok("anything") is False


def test_non_ascii_token_does_not_raise():
    # Не-ASCII предъявленный токен НЕ должен ронять сверку исключением TypeError: оба значения
    # приводятся к байтам. Ожидается спокойный отказ, а не падение.
    with mock.patch.object(app, "NODEAGENT_TOKEN", "s3cr3t-token"):
        assert app.token_ok("парольнеascii") is False


# --- HTTP-уровень: аутентификация ДО чтения тела ----------------------------------------------

@pytest.fixture
def running_server():
    """Поднять реальный ThreadingHTTPServer node-agent на свободном порту в отдельном потоке."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
    server.timeout = app.SOCKET_TIMEOUT
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield host, port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _post_run(host, port, token, body=b'{"argv":["rm","-rf","/"],"timeout":30}'):
    conn = http.client.HTTPConnection(host, port, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["X-NodeAgent-Token"] = token
    conn.request("POST", "/run", body=body, headers=headers)
    resp = conn.getresponse()
    status = resp.status
    data = resp.read()
    conn.close()
    return status, data


def test_http_post_run_without_token_is_401_and_executes_nothing(running_server):
    host, port = running_server
    with mock.patch.object(app.subprocess, "Popen") as popen:
        status, _ = _post_run(host, port, token=None)
    assert status == 401
    # Ключевая проверка порядка: без токена исполнение не запускалось вообще.
    assert popen.call_count == 0


def test_http_post_run_with_wrong_token_is_401_and_executes_nothing(running_server):
    host, port = running_server
    with mock.patch.object(app.subprocess, "Popen") as popen:
        status, _ = _post_run(host, port, token="definitely-wrong")
    assert status == 401
    assert popen.call_count == 0


def test_http_post_run_with_valid_token_executes(running_server):
    host, port = running_server
    fake = _fake_popen(returncode=0, stdout=b"done", stderr=b"")
    with mock.patch.object(app.subprocess, "Popen", return_value=fake) as popen:
        status, data = _post_run(host, port, token="s3cr3t-token",
                                 body=b'{"argv":["df","-h"],"timeout":30}')
    assert status == 200
    assert popen.call_count == 1
    assert b"done" in data


def _send_oversized_declared_body(host, port):
    """Отправить запрос с завышенным Content-Length, тело не досылая, и вернуть статус ответа.

    Проверяет, что сервер отклоняет по ОБЪЯВЛЕННОМУ размеру, не дожидаясь и не читая всё тело.
    """
    huge_len = app.MAX_BODY_BYTES + 1
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.putrequest("POST", "/run")
    conn.putheader("X-NodeAgent-Token", "s3cr3t-token")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(huge_len))
    conn.endheaders()
    conn.send(b"{")
    resp = conn.getresponse()
    status = resp.status
    resp.read()
    conn.close()
    return status


def test_http_oversized_body_rejected_with_413(running_server):
    host, port = running_server
    with mock.patch.object(app.subprocess, "Popen") as popen:
        status = _send_oversized_declared_body(host, port)
    assert status == 413
    assert popen.call_count == 0


def test_http_health_needs_no_token(running_server):
    host, port = running_server
    conn = http.client.HTTPConnection(host, port, timeout=5)
    conn.request("GET", "/health")
    resp = conn.getresponse()
    status = resp.status
    data = resp.read()
    conn.close()
    assert status == 200
    assert b"ok" in data
