"""Тесты node-agent без pytest и без сети (ADR-0041). Запуск: python3 test_node_agent.py.

Проверяются: валидация тела /run (пустой argv, некорректный timeout ведут к ошибке), корректная
сборка команды nsenter (argv остаётся списком аргументов и НЕ превращается в строку оболочки),
обрезка слишком длинного вывода и fail-closed отказ без валидного токена. subprocess мокается,
реальный nsenter не вызывается.

В коде тестов не должно быть длинного тире и стрелок. Там, где запрещённый символ нужен как данные
(например метасимволы оболочки в проверке инъекции), он записан обычными ASCII-символами.
"""
import os
import sys
import unittest
from unittest import mock

# Обеспечиваем предсказуемое имя узла и секрет ДО импорта модуля: значения читаются на импорте.
os.environ.setdefault("NODE_NAME", "test-node")
os.environ.setdefault("NODEAGENT_TOKEN", "s3cr3t-token")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import app  # noqa: E402


class ValidateBodyTests(unittest.TestCase):
    def test_empty_argv_rejected(self):
        with self.assertRaises(ValueError):
            app.validate_body({"argv": [], "timeout": 30})

    def test_missing_argv_rejected(self):
        with self.assertRaises(ValueError):
            app.validate_body({"timeout": 30})

    def test_argv_must_be_list_of_strings(self):
        with self.assertRaises(ValueError):
            app.validate_body({"argv": ["df", 5], "timeout": 30})

    def test_bad_timeout_too_small(self):
        with self.assertRaises(ValueError):
            app.validate_body({"argv": ["df", "-h"], "timeout": 0})

    def test_bad_timeout_too_large(self):
        with self.assertRaises(ValueError):
            app.validate_body({"argv": ["df", "-h"], "timeout": 9999})

    def test_timeout_not_a_number(self):
        with self.assertRaises(ValueError):
            app.validate_body({"argv": ["df", "-h"], "timeout": "быстро"})

    def test_bool_is_not_a_valid_timeout(self):
        with self.assertRaises(ValueError):
            app.validate_body({"argv": ["df"], "timeout": True})

    def test_valid_body_defaults_timeout(self):
        argv, timeout = app.validate_body({"argv": ["df", "-h", "/"]})
        self.assertEqual(argv, ["df", "-h", "/"])
        self.assertEqual(timeout, 30)


class BuildCommandTests(unittest.TestCase):
    def test_nsenter_prefix_and_argv_as_list(self):
        argv = ["df", "-h", "/"]
        cmd = app.build_command(argv)
        # Команда обязана быть списком, начинаться с nsenter и заканчиваться исходным argv без
        # какого-либо склеивания в строку.
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[:8], ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--"])
        self.assertEqual(cmd[8:], argv)

    def test_no_shell_injection_metacharacters_are_literal(self):
        # Метасимволы оболочки внутри argv должны остаться отдельным литеральным аргументом, а не
        # интерпретироваться: подтверждение того, что оболочка не участвует.
        payload = "; rm -rf / #"
        cmd = app.build_command(["echo", payload])
        self.assertIn(payload, cmd)
        # Ни один элемент не является строкой sh -c, и нигде нет склейки в единую командную строку.
        self.assertNotIn("sh", cmd)
        self.assertNotIn("-c", cmd)
        joined = " ".join(cmd)
        # Полезная нагрузка присутствует как один аргумент, но команда исполнения это список, а не
        # эта строка: проверяем, что число аргументов соответствует ожиданию.
        self.assertEqual(len(cmd), len(app.NSENTER_PREFIX) + 2)


class RunHostCommandTests(unittest.TestCase):
    def test_uses_list_argv_without_shell(self):
        fake = mock.Mock()
        fake.returncode = 0
        fake.stdout = b"ok"
        fake.stderr = b""
        with mock.patch.object(app.subprocess, "run", return_value=fake) as run:
            result = app.run_host_command(["df", "-h", "/"], 30)
        # Первый позиционный аргумент subprocess.run это список, а не строка.
        called_args, called_kwargs = run.call_args
        self.assertIsInstance(called_args[0], list)
        self.assertEqual(called_args[0][:8], ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--"])
        # shell=True не передавался ни при каких обстоятельствах.
        self.assertNotIn("shell", called_kwargs)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout"], "ok")
        self.assertEqual(result["node"], "test-node")

    def test_output_truncation(self):
        big = b"a" * (app.MAX_OUTPUT_BYTES + 100)
        fake = mock.Mock()
        fake.returncode = 0
        fake.stdout = big
        fake.stderr = b""
        with mock.patch.object(app.subprocess, "run", return_value=fake):
            result = app.run_host_command(["cat", "/big"], 30)
        self.assertTrue(result["stdout"].endswith(app.TRUNCATED_MARK))
        # Длина ограничена: полезная часть не превышает лимит (плюс длина пометки).
        self.assertLessEqual(len(result["stdout"]), app.MAX_OUTPUT_BYTES + len(app.TRUNCATED_MARK))

    def test_timeout_returns_124(self):
        exc = app.subprocess.TimeoutExpired(cmd=["nsenter"], timeout=5)
        with mock.patch.object(app.subprocess, "run", side_effect=exc):
            result = app.run_host_command(["sleep", "999"], 5)
        self.assertEqual(result["exit_code"], app.TIMEOUT_EXIT_CODE)
        self.assertIn("таймаут", result["stderr"])


class TokenTests(unittest.TestCase):
    def test_reject_without_token(self):
        self.assertFalse(app.token_ok(""))

    def test_reject_wrong_token(self):
        self.assertFalse(app.token_ok("wrong"))

    def test_accept_correct_token(self):
        self.assertTrue(app.token_ok("s3cr3t-token"))

    def test_fail_closed_when_server_secret_empty(self):
        # Если серверный секрет пуст, доступ запрещён даже при совпадающем пустом предъявлении.
        with mock.patch.object(app, "NODEAGENT_TOKEN", ""):
            self.assertFalse(app.token_ok(""))
            self.assertFalse(app.token_ok("anything"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
