"""Тесты детерминированного классификатора опасности команд и гейта автономии.

Проверяют не текущее поведение как эталон, а правильность классификации, с упором на реальные
векторы обхода из ревизии: запускатели процессов, траверсал путей, SQL из файла, массовое
удаление, обёртки оболочки и запускателей. Формат собираемый стандартным pytest.
"""
import policy
from policy import READ, SAFE_WRITE, DESTRUCTIVE, AUTO, CONFIRM, PROPOSE


# --- Базовая классификация ----------------------------------------------------------------------

def test_read_binaries():
    assert policy.classify(["df", "-h"]) == READ
    assert policy.classify(["du", "-sh", "/var"]) == READ
    assert policy.classify(["kubectl", "get", "pods"]) == READ
    assert policy.classify(["kubectl", "logs", "pod/foo"]) == READ
    assert policy.classify(["docker", "ps"]) == READ
    assert policy.classify(["free", "-m"]) == READ


def test_safe_write_repair():
    assert policy.classify(["kubectl", "rollout", "restart", "deployment/foo"]) == SAFE_WRITE
    assert policy.classify(["kubectl", "scale", "deploy/foo", "--replicas=3"]) == SAFE_WRITE
    assert policy.classify(["kubectl", "delete", "pod", "foo"]) == SAFE_WRITE
    assert policy.classify(["systemctl", "restart", "kubelet"]) == SAFE_WRITE
    assert policy.classify(["docker", "system", "prune", "-f"]) == SAFE_WRITE
    assert policy.classify(["kill", "-9", "1234"]) == SAFE_WRITE


def test_destructive_devices_and_resources():
    assert policy.classify(["mkfs", "/dev/sda1"]) == DESTRUCTIVE
    assert policy.classify(["dd", "if=/dev/zero", "of=/dev/sda"]) == DESTRUCTIVE
    assert policy.classify(["kubectl", "delete", "namespace", "prod"]) == DESTRUCTIVE
    assert policy.classify(["kubectl", "delete", "pvc", "data-0"]) == DESTRUCTIVE
    assert policy.classify(["kubectl", "delete", "deploy", "api"]) == DESTRUCTIVE


# --- Векторы обхода из ревизии ------------------------------------------------------------------

def test_bypass_env_launcher():
    # env это запускатель процессов, а не чтение: вложенная команда должна классифицироваться.
    assert policy.classify(["env", "rm", "-rf", "/var/lib/postgresql/data"]) == DESTRUCTIVE
    assert policy.classify(["env", "FOO=bar", "rm", "-rf", "/var/lib/postgresql"]) == DESTRUCTIVE
    assert policy.classify(["env", "kubectl", "get", "pods"]) == READ


def test_bypass_find_delete_and_exec():
    assert policy.classify(["find", "/var/lib/postgresql", "-delete"]) == DESTRUCTIVE
    assert policy.classify(["find", "/", "-name", "*.db", "-exec", "rm", "-rf", "{}", ";"]) == DESTRUCTIVE
    assert policy.classify(["find", "/var/log", "-name", "*.log"]) == READ
    assert policy.classify(["find", "/var/log", "-mtime", "+7", "-delete"]) == SAFE_WRITE


def test_bypass_path_traversal():
    assert policy.classify(["rm", "-rf", "/tmp/../var/lib/postgresql/data"]) == DESTRUCTIVE
    assert policy.classify(["rm", "-rf", "/var/log/../lib/mysql"]) == DESTRUCTIVE
    assert policy.classify(["rm", "-rf", "/var/log/nginx/../../lib/postgresql"]) == DESTRUCTIVE


def test_bypass_sql_from_file():
    assert policy.classify(["psql", "-f", "/tmp/wipe.sql"]) == DESTRUCTIVE
    assert policy.classify(["psql", "-f", "-"]) == DESTRUCTIVE
    assert policy.classify(["psql", "-c", "SELECT count(*) FROM users"]) == READ
    assert policy.classify(["psql", "-c", "DROP TABLE users"]) == DESTRUCTIVE
    assert policy.classify(["psql", "-c", "DELETE FROM users"]) == DESTRUCTIVE
    assert policy.classify(["psql", "-c", "DELETE FROM users WHERE id=1"]) == DESTRUCTIVE
    assert policy.classify(["mysql", "-e", "TRUNCATE t"]) == DESTRUCTIVE


def test_bypass_mass_delete():
    assert policy.classify(["kubectl", "delete", "pods", "--all"]) == DESTRUCTIVE
    assert policy.classify(["kubectl", "delete", "pods", "-l", "app=api"]) == DESTRUCTIVE
    assert policy.classify(["kubectl", "delete", "pods", "--all", "-n", "prod"]) == DESTRUCTIVE


def test_bypass_shell_opaque():
    assert policy.classify(["sh", "-c", "rm -rf /"]) == DESTRUCTIVE
    assert policy.classify(["bash", "-c", "kubectl get pods"]) == DESTRUCTIVE
    assert policy.classify(["bash"]) == DESTRUCTIVE


def test_bypass_wrappers():
    assert policy.classify(["sudo", "rm", "-rf", "/srv"]) == DESTRUCTIVE
    assert policy.classify(["nsenter", "-t", "1", "-m", "--", "rm", "-rf", "/data"]) == DESTRUCTIVE
    assert policy.classify(["xargs", "rm"]) == DESTRUCTIVE
    assert policy.classify(["timeout", "30", "kubectl", "delete", "ns", "x"]) == DESTRUCTIVE
    assert policy.classify(["nice", "-n", "5", "kubectl", "rollout", "restart", "deploy/x"]) == SAFE_WRITE
    assert policy.classify(["sudo", "kubectl", "get", "pods"]) == READ


def test_bypass_state_changers_not_read():
    # mount, ip как мутаторы состояния узла, а не чтение.
    assert policy.classify(["mount", "-o", "remount,rw", "/"]) == SAFE_WRITE
    assert policy.classify(["ip", "link", "set", "eth0", "down"]) == SAFE_WRITE
    assert policy.classify(["mount"]) == READ
    assert policy.classify(["ip", "addr", "show"]) == READ


def test_system_single_file_delete():
    assert policy.classify(["rm", "/usr/bin/kubelet"]) == DESTRUCTIVE
    assert policy.classify(["rm", "/etc/kubernetes/admin.conf"]) == DESTRUCTIVE
    assert policy.classify(["rm", "-rf", "/var/log/app"]) == SAFE_WRITE


def test_basename_normalization():
    assert policy.classify(["/usr/bin/docker", "ps"]) == READ
    assert policy.classify(["/snap/bin/kubectl", "delete", "ns", "x"]) == DESTRUCTIVE


def test_k3s_wrapper():
    assert policy.classify(["k3s", "crictl", "rmi", "--prune"]) == SAFE_WRITE
    assert policy.classify(["k3s", "kubectl", "delete", "pvc", "x"]) == DESTRUCTIVE


def test_fail_safe_unknown():
    assert policy.classify(["some-unknown-tool", "--wipe-everything"]) == DESTRUCTIVE
    assert policy.classify(["ctr", "images", "ls"]) == DESTRUCTIVE  # низкоуровневый клиент, fail-safe


def test_malformed_input():
    assert policy.classify(None) == DESTRUCTIVE
    assert policy.classify("rm -rf /") == DESTRUCTIVE
    assert policy.classify([]) == DESTRUCTIVE
    assert policy.classify(["rm", ["nested"]]) == DESTRUCTIVE
    assert policy.classify([123, "get"]) == DESTRUCTIVE


# --- Защищённые ресурсы --------------------------------------------------------------------------

def test_is_protected():
    assert policy.is_protected(["kubectl", "rollout", "restart", "deploy/prod-db"], {"prod-db"})
    assert policy.is_protected(["rm", "-rf", "/data/prod"], {"/data/prod"})
    assert not policy.is_protected(["kubectl", "get", "pods"], {"prod-db"})
    assert not policy.is_protected(["kubectl", "get", "pods"], set())


# --- Гейт автономии ------------------------------------------------------------------------------

def test_gate_read_always_auto():
    assert policy.gate(["kubectl", "get", "pods"], "observe") == AUTO
    assert policy.gate(["kubectl", "get", "pods"], "safe_repair") == AUTO
    assert policy.gate(["kubectl", "get", "pods"], "full") == AUTO


def test_gate_observe_proposes_mutations():
    assert policy.gate(["kubectl", "rollout", "restart", "deploy/x"], "observe") == PROPOSE
    assert policy.gate(["kubectl", "delete", "ns", "x"], "observe") == PROPOSE


def test_gate_safe_repair():
    assert policy.gate(["kubectl", "rollout", "restart", "deploy/x"], "safe_repair") == AUTO
    assert policy.gate(["kubectl", "delete", "ns", "x"], "safe_repair") == CONFIRM


def test_gate_full():
    assert policy.gate(["kubectl", "rollout", "restart", "deploy/x"], "full") == AUTO
    assert policy.gate(["kubectl", "delete", "pvc", "x"], "full") == CONFIRM


def test_gate_protected_forces_confirm():
    patterns = {"prod-db"}
    assert policy.gate(["kubectl", "rollout", "restart", "deploy/prod-db"], "full", patterns) == CONFIRM
    assert policy.gate(["kubectl", "rollout", "restart", "deploy/prod-db"], "safe_repair", patterns) == CONFIRM
    # Без защищённого шаблона тот же безопасный ремонт исполняется автономно.
    assert policy.gate(["kubectl", "rollout", "restart", "deploy/api"], "full", patterns) == AUTO


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
