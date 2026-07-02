"""Модульные тесты детерминированного классификатора политики (ADR-0041, спецификация раздел 4).
Без сети и без pytest. Запуск: python3 services/adminchat/test_policy.py

Покрыты все четыре класса (read, safe_write, finance, destructive), устойчивость к обходу
(полный путь бинаря, сокращённые имена ресурсов Kubernetes), финансовые пути, разрушительные
паттерны и правило fail-safe (неизвестная мутирующая команда трактуется как destructive). Список
destructive и finance это критичный код, поэтому каждый его кейс здесь зафиксирован тестом.

Запрещённые правилами проекта символы (длинное тире, стрелка) экранированы в текстах: тире и
стрелка называются словами, а не рисуются знаком.
"""
import policy


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def test_read_class():
    """Класс read: чистое чтение состояния кластера, дисков, процессов, образов."""
    _eq("kubectl get pods", policy.classify(["kubectl", "get", "pods"]), policy.READ)
    _eq("kubectl describe", policy.classify(["kubectl", "describe", "pod", "asr-x"]), policy.READ)
    _eq("kubectl logs", policy.classify(["kubectl", "logs", "asr-x"]), policy.READ)
    _eq("kubectl top", policy.classify(["kubectl", "top", "nodes"]), policy.READ)
    _eq("kubectl api-resources", policy.classify(["kubectl", "api-resources"]), policy.READ)
    _eq("kubectl explain", policy.classify(["kubectl", "explain", "pod"]), policy.READ)
    _eq("df", policy.classify(["df", "-h", "/"]), policy.READ)
    _eq("du", policy.classify(["du", "-sh", "/var/lib/docker"]), policy.READ)
    _eq("free", policy.classify(["free", "-m"]), policy.READ)
    _eq("uptime", policy.classify(["uptime"]), policy.READ)
    _eq("ps", policy.classify(["ps", "aux"]), policy.READ)
    _eq("ls", policy.classify(["ls", "-la", "/tmp"]), policy.READ)
    _eq("nproc", policy.classify(["nproc"]), policy.READ)
    _eq("lscpu", policy.classify(["lscpu"]), policy.READ)
    _eq("cat proc", policy.classify(["cat", "/proc/loadavg"]), policy.READ)
    _eq("docker ps", policy.classify(["docker", "ps"]), policy.READ)
    _eq("docker images", policy.classify(["docker", "images"]), policy.READ)
    _eq("docker system df", policy.classify(["docker", "system", "df"]), policy.READ)
    _eq("crictl ps", policy.classify(["crictl", "ps"]), policy.READ)
    _eq("crictl images", policy.classify(["crictl", "images"]), policy.READ)
    _eq("crictl stats", policy.classify(["crictl", "stats"]), policy.READ)
    _eq("journalctl", policy.classify(["journalctl", "-u", "k3s", "-n", "100"]), policy.READ)
    print("read: ok")


def test_safe_write_class():
    """Класс safe_write: ремонт без разрушения данных."""
    _eq("rollout restart", policy.classify(["kubectl", "rollout", "restart", "deployment/asr"]),
        policy.SAFE_WRITE)
    _eq("delete pod", policy.classify(["kubectl", "delete", "pod", "asr-x"]), policy.SAFE_WRITE)
    _eq("delete po сокращение", policy.classify(["kubectl", "delete", "po", "asr-x"]),
        policy.SAFE_WRITE)
    _eq("scale", policy.classify(["kubectl", "scale", "deployment/asr", "--replicas=2"]),
        policy.SAFE_WRITE)
    _eq("docker system prune", policy.classify(["docker", "system", "prune", "-f"]),
        policy.SAFE_WRITE)
    _eq("docker image prune", policy.classify(["docker", "image", "prune", "-a"]),
        policy.SAFE_WRITE)
    _eq("docker builder prune", policy.classify(["docker", "builder", "prune"]),
        policy.SAFE_WRITE)
    _eq("crictl rmi prune", policy.classify(["crictl", "rmi", "--prune"]), policy.SAFE_WRITE)
    _eq("rm кеша tmp", policy.classify(["rm", "-rf", "/tmp/build-cache"]), policy.SAFE_WRITE)
    _eq("rm var cache", policy.classify(["rm", "-rf", "/var/cache/apt/archives"]),
        policy.SAFE_WRITE)
    _eq("kill процесса", policy.classify(["kill", "-9", "12345"]), policy.SAFE_WRITE)
    _eq("pkill", policy.classify(["pkill", "-f", "zombie"]), policy.SAFE_WRITE)
    _eq("systemctl restart", policy.classify(["systemctl", "restart", "containerd"]),
        policy.SAFE_WRITE)
    _eq("sync", policy.classify(["sync"]), policy.SAFE_WRITE)
    print("safe_write: ok")


def test_finance_class():
    """Класс finance: тарифы, баланс, платежи, деньги тенанта. ВСЕГДА подтверждение."""
    _eq("api tariff путь", policy.classify(["curl", "-XPOST",
        "http://api:8765/api/admin/tariff"]), policy.FINANCE)
    _eq("grant-minutes", policy.classify(["curl", "-XPOST",
        "http://api:8765/api/admin/grant-minutes"]), policy.FINANCE)
    _eq("reapply", policy.classify(["curl", "-XPOST", "http://api:8765/api/admin/reapply"]),
        policy.FINANCE)
    _eq("renew-plan", policy.classify(["curl", "http://api/renew-plan"]), policy.FINANCE)
    _eq("extend-storage", policy.classify(["curl", "http://api/extend-storage"]), policy.FINANCE)
    _eq("minute_packs таблица", policy.classify(["psql", "-c",
        "UPDATE minute_packs SET balance=0"]), policy.FINANCE)
    _eq("subscriptions таблица", policy.classify(["psql", "-c",
        "UPDATE subscriptions SET plan='pro'"]), policy.FINANCE)
    _eq("payments таблица", policy.classify(["psql", "-c", "SELECT * FROM payments"]),
        policy.FINANCE)
    _eq("слэш tariff", policy.classify(["/tariff", "abc", "pro"]), policy.FINANCE)
    print("finance: ok")


def test_destructive_class():
    """Класс destructive: необратимое. ВСЕГДА подтверждение."""
    _eq("rm -rf данных postgres", policy.classify(["rm", "-rf", "/var/lib/postgresql/data"]),
        policy.DESTRUCTIVE)
    _eq("rm -rf S3-маунт", policy.classify(["rm", "-rf", "/mnt/s3/tenant-42"]),
        policy.DESTRUCTIVE)
    _eq("rm -rf том rancher", policy.classify(["rm", "-rf",
        "/var/lib/rancher/k3s/storage/pvc-xxx"]), policy.DESTRUCTIVE)
    _eq("psql DROP", policy.classify(["psql", "-c", "DROP TABLE jobs"]), policy.DESTRUCTIVE)
    _eq("psql TRUNCATE", policy.classify(["psql", "-c", "TRUNCATE users"]), policy.DESTRUCTIVE)
    _eq("psql DELETE без WHERE", policy.classify(["psql", "-c", "DELETE FROM jobs"]),
        policy.DESTRUCTIVE)
    _eq("delete namespace", policy.classify(["kubectl", "delete", "namespace", "krokki"]),
        policy.DESTRUCTIVE)
    _eq("delete ns сокращение", policy.classify(["kubectl", "delete", "ns", "krokki"]),
        policy.DESTRUCTIVE)
    _eq("delete pvc", policy.classify(["kubectl", "delete", "pvc", "data-postgres-0"]),
        policy.DESTRUCTIVE)
    _eq("delete pv", policy.classify(["kubectl", "delete", "pv", "pvc-xxx"]), policy.DESTRUCTIVE)
    _eq("delete deployment", policy.classify(["kubectl", "delete", "deployment", "asr"]),
        policy.DESTRUCTIVE)
    _eq("delete deploy сокращение", policy.classify(["kubectl", "delete", "deploy", "asr"]),
        policy.DESTRUCTIVE)
    _eq("mkfs", policy.classify(["mkfs.ext4", "/dev/sdb1"]), policy.DESTRUCTIVE)
    _eq("wipefs", policy.classify(["wipefs", "-a", "/dev/sdb"]), policy.DESTRUCTIVE)
    _eq("dd на устройство", policy.classify(["dd", "if=/dev/zero", "of=/dev/sda"]),
        policy.DESTRUCTIVE)
    print("destructive: ok")


def test_fail_safe_unknown():
    """Неизвестная мутирующая команда падает в destructive (fail-safe), а не проскакивает."""
    _eq("неизвестный бинарь", policy.classify(["frobnicate", "--all"]), policy.DESTRUCTIVE)
    _eq("kubectl неизвестный verb", policy.classify(["kubectl", "hackthings", "x"]),
        policy.DESTRUCTIVE)
    _eq("kubectl patch", policy.classify(["kubectl", "patch", "deploy/asr", "-p", "{}"]),
        policy.DESTRUCTIVE)
    _eq("kubectl exec", policy.classify(["kubectl", "exec", "asr-x", "--", "sh"]),
        policy.DESTRUCTIVE)
    _eq("kubectl apply", policy.classify(["kubectl", "apply", "-f", "x.yaml"]),
        policy.DESTRUCTIVE)
    _eq("docker неизвестная подкоманда", policy.classify(["docker", "frobnicate"]),
        policy.DESTRUCTIVE)
    _eq("rm без пути", policy.classify(["rm", "-rf", "somedir"]), policy.DESTRUCTIVE)
    _eq("пустой argv", policy.classify([]), policy.DESTRUCTIVE)
    _eq("не список", policy.classify("kubectl get pods"), policy.DESTRUCTIVE)
    print("fail-safe: ok")


def test_bypass_resistance():
    """Устойчивость к обходу: полный путь бинаря нормализуется по basename и не меняет класс."""
    _eq("полный путь docker prune", policy.classify(["/usr/bin/docker", "system", "prune", "-f"]),
        policy.SAFE_WRITE)
    _eq("полный путь docker ps", policy.classify(["/usr/local/bin/docker", "ps"]), policy.READ)
    _eq("полный путь kubectl delete ns", policy.classify(["/snap/bin/kubectl", "delete",
        "namespace", "krokki"]), policy.DESTRUCTIVE)
    _eq("полный путь rm данных", policy.classify(["/bin/rm", "-rf", "/var/lib/postgresql"]),
        policy.DESTRUCTIVE)
    _eq("полный путь mkfs", policy.classify(["/sbin/mkfs.xfs", "/dev/sdb"]), policy.DESTRUCTIVE)
    # Финансовый путь распознаётся даже через http-клиент с полным путём бинаря.
    _eq("полный путь curl tariff", policy.classify(["/usr/bin/curl",
        "http://api/api/admin/tariff"]), policy.FINANCE)
    # Сокращение kubectl (k) даёт тот же класс.
    _eq("k delete ns", policy.classify(["k", "delete", "ns", "krokki"]), policy.DESTRUCTIVE)
    _eq("k get pods", policy.classify(["k", "get", "pods"]), policy.READ)
    print("bypass-resistance: ok")


def test_helpers():
    """Вспомогательные предикаты политики."""
    _eq("finance требует подтверждения", policy.requires_confirmation(policy.FINANCE), True)
    _eq("destructive требует подтверждения", policy.requires_confirmation(policy.DESTRUCTIVE), True)
    _eq("safe_write не требует", policy.requires_confirmation(policy.SAFE_WRITE), False)
    _eq("read не требует", policy.requires_confirmation(policy.READ), False)
    _eq("read это чтение", policy.is_read(policy.READ), True)
    _eq("safe_write это мутация", policy.is_mutation(policy.SAFE_WRITE), True)
    _eq("read не мутация", policy.is_mutation(policy.READ), False)
    print("helpers: ok")


if __name__ == "__main__":
    test_read_class()
    test_safe_write_class()
    test_finance_class()
    test_destructive_class()
    test_fail_safe_unknown()
    test_bypass_resistance()
    test_helpers()
    print("ВСЕ ТЕСТЫ policy ПРОЙДЕНЫ")
