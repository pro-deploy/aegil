"""Детерминированная классификация опасности команд и гейт автономии продукта kube-sentinel.

Классификатор живёт ВНЕ языковой модели: модель формулирует команду, а решение о том, можно ли
исполнить её автономно или требуется подтверждение оператора, принимает эта чистая функция по
спискам паттернов. Тем самым модель физически не может обойти подтверждение, потому что
классификация не зависит от её вывода, а от фактического списка аргументов.

Три универсальных класса (см. docs/CONVENTIONS.md):

  read         только чтение состояния. Исполняется автономно всегда, в бюджет гардов не считается.
  safe_write   обратимый ремонт: перезапуск сервиса, удаление пода, масштабирование, чистка кешей и
               временных путей, освобождение места, перезапуск процесса, изменение состояния узла
               без разрушения данных.
  destructive  необратимое: удаление данных, томов, пространств имён, деплойментов, наборов,
               DROP или TRUNCATE таблиц, mkfs, dd на устройство, удаление критичных системных файлов.

Дисциплина классификатора: он всегда ошибается в сторону подтверждения. НЕИЗВЕСТНАЯ мутирующая
команда трактуется как destructive (fail-safe). Классификатор устойчив к обходу: имя бинаря
нормализуется по basename (полный путь не обходит распознавание), пути нормализуются перед
сопоставлением (траверсал ``..`` не уводит из-под маркеров данных), обёртки-запускатели (``env``,
``sudo``, ``nsenter``, ``xargs`` и прочие) разворачиваются до вложенной команды, а непрозрачная
оболочка (``sh -c``) трактуется как destructive, потому что её содержимое классификатору не видно.

Наследный доменный класс finance упразднён. Его роль (всегда подтверждать чувствительное) берёт
на себя настраиваемый механизм защищённых шаблонов ``is_protected`` и ``gate``: владелец задаёт
свои защищаемые ресурсы в ``SENTINEL_PROTECTED_PATTERNS``, и действие над ними требует подтверждения
на любом уровне автономии.
"""
from __future__ import annotations

import os
import posixpath
import re

# Классы политики. Порядок строгости по возрастанию: при неоднозначности выбирается более строгий.
READ = "read"
SAFE_WRITE = "safe_write"
DESTRUCTIVE = "destructive"

# Решения гейта автономии.
AUTO = "auto"        # исполнить автономно
CONFIRM = "confirm"  # требуется подтверждение оператора
PROPOSE = "propose"  # только предложить оператору, агент сам не действует (уровень observe)


def _base(binary: str) -> str:
    """Нормализует имя бинаря по basename, чтобы полный путь не обходил классификатор.
    /usr/bin/docker и docker дают одно имя, /snap/bin/kubectl тоже kubectl."""
    return os.path.basename(str(binary or "").strip())


# Read-only бинари без мутирующих подкоманд в нашем контуре. Запускатели процессов (env, find,
# mount, ip, xargs) сюда СОЗНАТЕЛЬНО не входят: они разбираются отдельными обработчиками, потому
# что умеют исполнять или менять состояние и не являются чистым чтением.
_READ_ONLY_BINARIES = {
    "df", "du", "free", "uptime", "ps", "ls", "top", "htop", "nproc", "lscpu",
    "lsblk", "lsmem", "vmstat", "iostat", "mpstat", "who", "w", "id", "date",
    "hostname", "uname", "dmesg", "netstat", "ss", "cat", "head", "tail",
    "less", "grep", "egrep", "fgrep", "wc", "stat", "readlink", "realpath", "printenv",
    "getconf", "ulimit", "sensors", "nvidia-smi", "true", "echo", "which", "whoami",
    "pgrep", "pidof", "lsof", "file", "basename", "dirname", "cut", "sort", "uniq",
    "tr", "awk", "sed", "jq", "yq", "column", "tac", "nl", "od", "xxd", "strings",
}

# Обёртки-запускатели: исполняют другую команду, переданную дальше по argv. Класс определяется
# ВЛОЖЕННОЙ командой, поэтому такие обёртки разворачиваются до неё. Опасность в том, что без
# разворачивания env rm -rf /data выглядело бы как безобидный env.
_PREFIX_RUNNERS = {"sudo", "nohup", "setsid", "doas", "eatmydata", "catchsegv"}

# Оболочки: команда передаётся строкой (-c), классификатору её содержимое не видно, поэтому
# любой их вызов трактуется как destructive (fail-safe). Панель исполняет argv списком без
# оболочки, поэтому легитимная работа не требует sh -c.
_SHELL_BINARIES = {"sh", "bash", "zsh", "ash", "dash", "ksh", "fish", "csh", "tcsh"}

# Мутирующие подкоманды kubectl (меняют состояние кластера).
_KUBECTL_MUTATING_VERBS = {
    "delete", "patch", "apply", "create", "replace", "scale", "rollout", "edit",
    "annotate", "label", "cordon", "uncordon", "drain", "taint", "set", "expose",
    "run", "autoscale", "exec", "cp", "rollback", "attach", "port-forward", "proxy",
}
# Read-only подкоманды kubectl.
_KUBECTL_READ_VERBS = {
    "get", "describe", "logs", "top", "api-resources", "api-versions", "explain",
    "version", "cluster-info", "config", "auth", "wait", "events", "diff", "kustomize",
}

# Нормализация сокращённых имён ресурсов Kubernetes к каноническим множественным формам.
_K8S_RESOURCE_ALIASES = {
    "po": "pods", "pod": "pods", "pods": "pods",
    "deploy": "deployments", "deployment": "deployments", "deployments": "deployments",
    "deploy.apps": "deployments",
    "ns": "namespaces", "namespace": "namespaces", "namespaces": "namespaces",
    "pvc": "persistentvolumeclaims", "persistentvolumeclaim": "persistentvolumeclaims",
    "persistentvolumeclaims": "persistentvolumeclaims",
    "pv": "persistentvolumes", "persistentvolume": "persistentvolumes",
    "persistentvolumes": "persistentvolumes",
    "sts": "statefulsets", "statefulset": "statefulsets", "statefulsets": "statefulsets",
    "ds": "daemonsets", "daemonset": "daemonsets", "daemonsets": "daemonsets",
    "rs": "replicasets", "replicaset": "replicasets", "replicasets": "replicasets",
    "svc": "services", "service": "services", "services": "services",
    "cm": "configmaps", "configmap": "configmaps", "configmaps": "configmaps",
    "secret": "secrets", "secrets": "secrets",
    "job": "jobs", "jobs": "jobs",
    "cronjob": "cronjobs", "cronjobs": "cronjobs",
    "node": "nodes", "nodes": "nodes", "no": "nodes",
    "rc": "replicationcontrollers", "replicationcontroller": "replicationcontrollers",
    "sc": "storageclasses", "storageclass": "storageclasses", "storageclasses": "storageclasses",
}

# Ресурсы Kubernetes, удаление которых необратимо и разрушительно. Единственный ресурс, удаление
# которого считается ремонтом (контроллер пересоздаёт под) это pod, и то лишь поимённо.
_K8S_DESTRUCTIVE_RESOURCES = {
    "namespaces", "persistentvolumeclaims", "persistentvolumes", "deployments",
    "statefulsets", "daemonsets", "replicasets", "services", "storageclasses",
    "replicationcontrollers", "nodes", "secrets", "configmaps",
}

# Пути с ценными данными: любое разрушительное действие на них это destructive. Сопоставление по
# нормализованному пути (после снятия траверсала ``..``).
_DATA_PATH_MARKERS = (
    "/var/lib/postgresql", "/var/lib/postgres", "/pgdata", "/postgres-data",
    "/var/lib/rancher/k3s/storage", "/var/lib/kubelet/pods", "/mnt", "/s3",
    "/data", "/srv", "/home", "/var/lib/redis", "/var/lib/mysql", "/backup",
    "/var/lib/etcd", "/var/lib/rancher/k3s/server",
)

# Критичные системные пути: удаление даже одиночного файла на них ломает узел, это destructive.
_SYSTEM_PATH_MARKERS = (
    "/etc", "/root", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64",
    "/var/lib/kubelet", "/var/lib/containerd", "/opt/cni", "/etc/kubernetes",
)

# Пути кешей и временных данных: их очистка это ремонт (safe_write).
_CACHE_PATH_MARKERS = (
    "/tmp", "/var/tmp", "/var/cache", "/var/log", "/var/lib/docker/tmp",
    "/var/lib/docker/overlay2", "/var/lib/containerd/tmp", "/root/.cache",
    "/var/lib/docker/image", "/var/lib/docker/buildkit",
)

# Разрушительные бинари: сама попытка их применить к устройству или файловой системе необратима.
_DESTRUCTIVE_BINARIES = {
    "mkfs", "wipefs", "fdisk", "sgdisk", "parted", "shred", "blkdiscard",
    "lvremove", "vgremove", "pvremove", "cryptsetup", "mkswap",
}

_SQL_DROP_RE = re.compile(r"\b(drop|truncate)\b", re.IGNORECASE)
_SQL_DELETE_RE = re.compile(r"\bdelete\s+from\b", re.IGNORECASE)
_SQL_WHERE_RE = re.compile(r"\bwhere\b", re.IGNORECASE)
_SQL_MUTATING_RE = re.compile(
    r"\b(insert|update|delete|alter|create|grant|revoke|drop|truncate|copy|call|do|merge)\b",
    re.IGNORECASE)

_DOCKER_READ_SUB = {"ps", "images", "stats", "inspect", "logs", "top", "port",
                    "version", "info", "events", "history", "diff", "search"}
_DOCKER_SAFE_WRITE_SUB = {"prune", "rm", "rmi", "kill", "stop", "restart", "start", "unpause",
                          "pause", "update"}
_DOCKER_GROUP_SUB = {"image", "container", "volume", "network", "builder", "buildx", "system"}
_DOCKER_GROUP_READ_VERBS = {"ls", "inspect", "df", "info", "history", "list"}
_DOCKER_GROUP_WRITE_VERBS = {"prune", "rm", "rmi", "kill", "stop", "remove", "disconnect"}

_CRICTL_READ_SUB = {"ps", "images", "imagefsinfo", "stats", "inspect", "inspecti",
                    "info", "version", "pods", "logs", "inspectp", "stats"}
_CRICTL_SAFE_WRITE_SUB = {"rmi", "rm", "rmp", "stop", "stopp"}


# ---------------------------------------------------------------------------
# Пути.
# ---------------------------------------------------------------------------

def _norm(path: str) -> str:
    """Нормализует путь, снимая траверсал ``..`` лексически. /tmp/../var/lib/postgresql приводится
    к /var/lib/postgresql, поэтому маркер данных не обходится через /tmp/.. ."""
    p = str(path)
    # Отбрасываем возможное завершающее выражение, но нормализуем как POSIX-путь.
    return posixpath.normpath(p)


def _match_marker(path: str, markers) -> bool:
    p = _norm(path)
    for m in markers:
        if p == m or p.startswith(m.rstrip("/") + "/"):
            return True
    return False


def _is_data_path(path: str) -> bool:
    return _match_marker(path, _DATA_PATH_MARKERS)


def _is_system_path(path: str) -> bool:
    return _match_marker(path, _SYSTEM_PATH_MARKERS)


def _is_cache_path(path: str) -> bool:
    return _match_marker(path, _CACHE_PATH_MARKERS)


def _is_root_path(path: str) -> bool:
    """Корень или почти корень: / или /* или пустой путь после нормализации."""
    p = _norm(path)
    return p in ("/", ".", "") or p == "/*"


def _paths_in(argv) -> list[str]:
    """Позиционные аргументы, похожие на абсолютные пути (начинаются с /). Опции пропускаются.
    Относительные пути не распознаются намеренно: команда без явного абсолютного пути трактуется
    ниже как неопределённая, то есть fail-safe."""
    return [str(a) for a in argv[1:] if str(a).startswith("/")]


def _has_recursive_force(argv) -> bool:
    """Признак рекурсивного и принудительного удаления в любом виде записи флагов."""
    joined = " ".join(str(a) for a in argv)
    recursive = bool(re.search(r"(^|\s)-{1,2}[a-zA-Z]*[rR][a-zA-Z]*\b", joined)) or "--recursive" in joined
    force = bool(re.search(r"(^|\s)-{1,2}[a-zA-Z]*f[a-zA-Z]*\b", joined)) or "--force" in joined
    return recursive and force


# ---------------------------------------------------------------------------
# Снятие обёрток-запускателей.
# ---------------------------------------------------------------------------

def _unwrap(argv) -> tuple[list | None, bool]:
    """Разворачивает обёртки-запускатели до вложенной команды.

    Возвращает пару (вложенный argv, opaque). opaque=True означает непрозрачную оболочку
    (sh -c ...), содержимое которой классификатору не видно, поэтому вызывающий обязан вернуть
    destructive. Если вложенную команду достоверно выделить не удалось, возвращает (None, True),
    что тоже ведёт к fail-safe. Без обёрток возвращает (argv, False)."""
    binary = _base(argv[0])

    # Оболочка с -c или без аргументов: содержимое строкой, не разбираем.
    if binary in _SHELL_BINARIES:
        return None, True

    # Простые префиксные запускатели: следующий токен это уже вложенная команда.
    if binary in _PREFIX_RUNNERS:
        rest = list(argv[1:])
        # Пропускаем опции самого запускателя (sudo -u user, sudo -E и т. п.).
        while rest and str(rest[0]).startswith("-"):
            opt = str(rest[0])
            rest = rest[1:]
            # Опции с отдельным аргументом-значением у sudo: -u, -g, -h, -p, -C, -r, -t, -U.
            if opt in ("-u", "-g", "-h", "-p", "-C", "-r", "-t", "-U", "--user", "--group"):
                if rest:
                    rest = rest[1:]
        return (rest, False) if rest else (None, True)

    # env: снимаем env, его опции и присваивания NAME=VALUE, остаток это команда.
    if binary == "env":
        rest = list(argv[1:])
        while rest:
            tok = str(rest[0])
            if tok == "--":
                rest = rest[1:]
                break
            if tok in ("-i", "--ignore-environment", "-0", "-v", "--debug"):
                rest = rest[1:]
                continue
            if tok in ("-u", "-C", "-S", "--unset", "--chdir", "--split-string"):
                rest = rest[2:] if len(rest) > 1 else rest[1:]
                continue
            if tok.startswith("-"):
                rest = rest[1:]
                continue
            if "=" in tok and not tok.startswith("/"):
                # Присваивание переменной окружения.
                rest = rest[1:]
                continue
            break
        return (rest, False) if rest else (None, True)

    # nsenter: команда после разделителя --, либо после опций входа в пространства.
    if binary == "nsenter":
        rest = list(argv[1:])
        if "--" in [str(x) for x in rest]:
            idx = [str(x) for x in rest].index("--")
            inner = rest[idx + 1:]
            return (inner, False) if inner else (None, True)
        # Без --: достоверно отделить команду от опций nsenter нельзя, fail-safe.
        return None, True

    # xargs: исполняет команду, взятую из первого не-опционного токена.
    if binary == "xargs":
        rest = list(argv[1:])
        while rest and str(rest[0]).startswith("-"):
            opt = str(rest[0])
            rest = rest[1:]
            if opt in ("-a", "-E", "-I", "-L", "-n", "-P", "-s", "-d", "--arg-file",
                       "--delimiter", "--max-args", "--max-lines", "--max-procs"):
                if rest:
                    rest = rest[1:]
        return (rest, False) if rest else (None, True)

    # timeout N CMD, nice -n N CMD, ionice -c2 CMD, chrt PRIO CMD, stdbuf -oL CMD, watch CMD.
    if binary in ("timeout", "nice", "ionice", "chrt", "stdbuf", "watch", "time", "taskset"):
        rest = list(argv[1:])
        # Пропускаем опции и их числовые аргументы до первого токена, похожего на команду.
        while rest:
            tok = str(rest[0])
            if tok == "--":
                rest = rest[1:]
                break
            if tok.startswith("-"):
                rest = rest[1:]
                continue
            # Числовой токен это длительность, приоритет или значение опции запускателя, но никогда
            # не имя команды: пропускаем его у любого запускателя этой группы.
            if re.fullmatch(r"[0-9smhd.]+", tok):
                rest = rest[1:]
                continue
            break
        return (rest, False) if rest else (None, True)

    return argv, False


# ---------------------------------------------------------------------------
# Классификаторы по бинарю.
# ---------------------------------------------------------------------------

def _classify_kubectl(argv) -> str:
    if len(argv) < 2:
        return READ
    verb = str(argv[1]).lower()
    if verb in _KUBECTL_READ_VERBS:
        return READ
    if verb not in _KUBECTL_MUTATING_VERBS:
        return DESTRUCTIVE
    if verb == "rollout":
        return SAFE_WRITE
    if verb == "scale":
        return SAFE_WRITE
    if verb == "delete":
        return _classify_kubectl_delete(argv)
    if verb in ("cordon", "uncordon", "drain", "taint", "annotate", "label"):
        return SAFE_WRITE
    return DESTRUCTIVE


def _classify_kubectl_delete(argv) -> str:
    tokens = [str(t).lower() for t in argv[2:]]
    # Массовое удаление: --all или удаление по селектору это широкий необратимый эффект.
    if "--all" in tokens or any(t.startswith("--all") for t in tokens):
        return DESTRUCTIVE
    resources = []
    for t in tokens:
        if t.startswith("-"):
            continue
        head = t.split("/", 1)[0]
        canon = _K8S_RESOURCE_ALIASES.get(head)
        if canon:
            resources.append(canon)
    if not resources:
        # delete -f манифеста или по метке без явного ресурса: неясный эффект, fail-safe.
        return DESTRUCTIVE
    if any(r in _K8S_DESTRUCTIVE_RESOURCES for r in resources):
        return DESTRUCTIVE
    if set(resources) == {"pods"}:
        # Поимённое удаление подов: контроллер пересоздаёт, это ремонт. Селектор уже отсеян выше
        # как destructive, потому что затрагивает неизвестно сколько подов.
        if any(t in ("-l", "--selector") or t.startswith("--selector") or t.startswith("-l")
               for t in tokens):
            return DESTRUCTIVE
        return SAFE_WRITE
    return DESTRUCTIVE


def _classify_docker(argv) -> str:
    if len(argv) < 2:
        return READ
    sub = str(argv[1]).lower()
    if sub in _DOCKER_GROUP_SUB:
        verb = str(argv[2]).lower() if len(argv) > 2 else ""
        if verb in _DOCKER_GROUP_READ_VERBS:
            return READ
        if verb in _DOCKER_GROUP_WRITE_VERBS:
            return SAFE_WRITE
        return SAFE_WRITE
    if sub in _DOCKER_READ_SUB:
        return READ
    if sub in _DOCKER_SAFE_WRITE_SUB:
        return SAFE_WRITE
    return DESTRUCTIVE


def _classify_crictl(argv) -> str:
    if len(argv) < 2:
        return READ
    sub = str(argv[1]).lower()
    if sub in _CRICTL_READ_SUB:
        return READ
    if sub in _CRICTL_SAFE_WRITE_SUB:
        return SAFE_WRITE
    return DESTRUCTIVE


def _classify_journalctl(argv) -> str:
    joined = " ".join(str(a) for a in argv).lower()
    if any(k in joined for k in ("--rotate", "--vacuum", "--flush", "--sync")):
        return SAFE_WRITE
    return READ


def _classify_systemctl(argv) -> str:
    if len(argv) < 2:
        return READ
    sub = str(argv[1]).lower()
    if sub in ("status", "show", "list-units", "list-unit-files", "is-active",
               "is-enabled", "cat", "get-default", "list-dependencies", "list-timers"):
        return READ
    if sub in ("restart", "reload", "start", "stop", "enable", "disable", "mask",
               "unmask", "reload-or-restart", "try-restart", "daemon-reload", "kill"):
        return SAFE_WRITE
    return DESTRUCTIVE


def _classify_find(argv) -> str:
    """find это чтение, если нет действий-мутаторов. -delete и -exec/-execdir/-ok меняют или
    исполняют, поэтому классифицируются по цели и эффекту (fail-safe)."""
    tokens = [str(a) for a in argv[1:]]
    if any(t in ("-exec", "-execdir", "-ok", "-okdir", "-fprintf", "-fprint",
                 "-fprint0", "-fls") for t in tokens):
        # Исполнение произвольной команды или запись в файл по обходу дерева: неясный эффект.
        return DESTRUCTIVE
    if "-delete" in tokens:
        paths = [t for t in tokens if t.startswith("/")]
        if not paths or any(_is_root_path(p) or _is_data_path(p) or _is_system_path(p) for p in paths):
            return DESTRUCTIVE
        if all(_is_cache_path(p) for p in paths):
            return SAFE_WRITE
        return DESTRUCTIVE
    return READ


def _classify_mount(argv) -> str:
    """Голый mount перечисляет монтирования (чтение). С аргументами меняет состояние узла
    (ремонт, не разрушение данных)."""
    if len(argv) < 2:
        return READ
    if all(str(a).startswith("-") and str(a) not in ("--all",) for a in argv[1:]):
        # Только опции чтения (например mount -l): чтение.
        return READ
    return SAFE_WRITE


def _classify_ip(argv) -> str:
    """ip ... show/list или голый ip это чтение. Операции add/del/set/change/flush меняют
    состояние сети узла (ремонт)."""
    tokens = [str(a).lower() for a in argv[1:]]
    if any(t in ("add", "del", "delete", "set", "change", "replace", "flush", "append") for t in tokens):
        return SAFE_WRITE
    return READ


def _classify_sysctl(argv) -> str:
    """sysctl -a или чтение ключа это read. sysctl -w или ключ=значение меняет параметр ядра."""
    if any(str(a) == "-w" or ("=" in str(a) and not str(a).startswith("-")) for a in argv[1:]):
        return SAFE_WRITE
    return READ


def _classify_rm(argv) -> str:
    if "--no-preserve-root" in [str(a) for a in argv]:
        return DESTRUCTIVE
    paths = _paths_in(argv)
    if not paths:
        return DESTRUCTIVE
    if any(_is_root_path(p) or _is_data_path(p) or _is_system_path(p) for p in paths):
        return DESTRUCTIVE
    if all(_is_cache_path(p) for p in paths):
        return SAFE_WRITE
    # Прочие пути: рекурсивно-принудительное удаление рискованно, единичное удаление файла ремонт.
    if _has_recursive_force(argv):
        return DESTRUCTIVE
    return SAFE_WRITE


def _classify_dd(argv) -> str:
    for a in argv[1:]:
        s = str(a)
        if s.startswith("of="):
            target = s[3:]
            if target.startswith("/dev/") or _is_data_path(target) or _is_system_path(target):
                return DESTRUCTIVE
    return DESTRUCTIVE


def _classify_truncate(argv) -> str:
    paths = _paths_in(argv)
    if any(_is_data_path(p) or _is_system_path(p) for p in paths):
        return DESTRUCTIVE
    if paths and all(_is_cache_path(p) for p in paths):
        return SAFE_WRITE
    return DESTRUCTIVE


def _classify_sql(argv) -> str:
    """SQL-клиент. Если запрос читается из файла (-f), из stdin или мета-командой \\i, содержимое
    классификатору не видно, поэтому fail-safe в destructive. Иначе классифицируем видимый текст:
    DROP, TRUNCATE, DELETE без WHERE это destructive, чистый SELECT это read, прочая мутация
    fail-safe."""
    tokens = [str(a) for a in argv[1:]]
    # Чтение SQL из файла или stdin: не видим содержимого.
    if "-f" in tokens or "--file" in tokens or any(t.startswith("-f") and len(t) > 2 for t in tokens):
        return DESTRUCTIVE
    joined = " ".join(tokens)
    if "\\i" in joined or "\\ir" in joined:
        return DESTRUCTIVE
    # Извлекаем текст запроса после -c/--command, иначе рассматриваем всю склейку.
    if _SQL_DROP_RE.search(joined):
        return DESTRUCTIVE
    if _SQL_DELETE_RE.search(joined) and not _SQL_WHERE_RE.search(joined):
        return DESTRUCTIVE
    if not _SQL_MUTATING_RE.search(joined):
        # Ни одного мутирующего ключевого слова в видимом тексте: чтение (SELECT, \dt, psql -l).
        return READ
    return DESTRUCTIVE


# ---------------------------------------------------------------------------
# Главная функция классификации.
# ---------------------------------------------------------------------------

def classify(argv, _depth: int = 0) -> str:
    """Относит команду argv (список токенов) к классу: read, safe_write или destructive.
    Чистая функция без побочных эффектов. НЕИЗВЕСТНАЯ мутирующая команда падает в destructive."""
    if not argv or not isinstance(argv, (list, tuple)):
        return DESTRUCTIVE
    if _depth > 6:
        # Слишком глубокая вложенность обёрток: подозрительно, fail-safe.
        return DESTRUCTIVE
    if any(not isinstance(a, str) for a in argv):
        # Нестроковые элементы (вложенные списки, числа, None): не наш формат, fail-safe.
        return DESTRUCTIVE
    binary = _base(argv[0])
    if not binary:
        return DESTRUCTIVE

    # Снятие обёрток-запускателей до вложенной команды.
    inner, opaque = _unwrap(list(argv))
    if opaque:
        return DESTRUCTIVE
    if inner is not None and inner is not argv and _base(inner[0]) != binary:
        return classify(inner, _depth + 1)

    # k3s это обёртка над встроенными инструментами: классифицируем по вложенной команде.
    if binary == "k3s" and len(argv) >= 2 and _base(argv[1]) in ("crictl", "kubectl", "ctr", "k", "oc"):
        return classify(list(argv[1:]), _depth + 1)

    # Разрушительные бинари устройств и файловых систем.
    if binary in _DESTRUCTIVE_BINARIES:
        return DESTRUCTIVE
    if binary == "dd":
        return _classify_dd(argv)

    # Явно read-only бинари.
    if binary in _READ_ONLY_BINARIES:
        return READ

    if binary in ("kubectl", "k", "oc"):
        return _classify_kubectl(argv)
    if binary in ("docker", "podman", "nerdctl"):
        return _classify_docker(argv)
    if binary == "crictl":
        return _classify_crictl(argv)
    if binary == "ctr":
        return DESTRUCTIVE  # низкоуровневый клиент containerd: fail-safe
    if binary == "journalctl":
        return _classify_journalctl(argv)
    if binary == "systemctl":
        return _classify_systemctl(argv)
    if binary == "find":
        return _classify_find(argv)
    if binary in ("mount", "umount"):
        return _classify_mount(argv) if binary == "mount" else SAFE_WRITE
    if binary == "ip":
        return _classify_ip(argv)
    if binary == "sysctl":
        return _classify_sysctl(argv)
    if binary == "rm":
        return _classify_rm(argv)
    if binary in ("kill", "pkill", "killall"):
        return SAFE_WRITE
    if binary in ("psql", "mysql", "mariadb", "clickhouse-client"):
        return _classify_sql(argv)
    if binary in ("sync", "renice"):
        return SAFE_WRITE
    if binary == "truncate":
        return _classify_truncate(argv)

    # Любой прочий бинарь неизвестного эффекта: fail-safe в destructive.
    return DESTRUCTIVE


# ---------------------------------------------------------------------------
# Защищённые ресурсы и гейт автономии.
# ---------------------------------------------------------------------------

def is_protected(argv, patterns) -> bool:
    """Затрагивает ли команда защищаемый владельцем ресурс. Совпадение по вхождению любого
    шаблона (без учёта регистра) в любой аргумент. patterns это множество или список строк из
    SENTINEL_PROTECTED_PATTERNS; пустое означает, что защищённых ресурсов не задано."""
    if not patterns:
        return False
    joined = " ".join(str(a) for a in argv).lower()
    return any(str(p).strip().lower() in joined for p in patterns if str(p).strip())


def gate(argv, level: str, protected_patterns=None) -> str:
    """Детерминированное решение гейта автономии для команды argv на заданном уровне.

    Возвращает AUTO (исполнить автономно), CONFIRM (нужно подтверждение оператора) или PROPOSE
    (агент сам не действует, только предлагает оператору). Уровни (docs/CONVENTIONS.md):

      observe      любая мутация становится предложением; чтение исполняется.
      safe_repair  read и safe_write автономно; destructive и защищённое за подтверждением.
      full         автономно всё, кроме destructive и защищённого, которые всегда подтверждаются.
    """
    cls = classify(argv)
    if cls == READ:
        return AUTO
    protected = is_protected(argv, protected_patterns or ())
    if level == "observe":
        return PROPOSE
    if cls == DESTRUCTIVE or protected:
        return CONFIRM
    # cls == SAFE_WRITE и уровень safe_repair или full.
    return AUTO


def requires_confirmation(argv, level: str, protected_patterns=None) -> bool:
    """Требует ли команда подтверждения оператора на данном уровне."""
    return gate(argv, level, protected_patterns) == CONFIRM


def is_read(cls: str) -> bool:
    return cls == READ


def is_mutation(cls: str) -> bool:
    return cls in (SAFE_WRITE, DESTRUCTIVE)


_CLASS_RU = {
    READ: "чтение (безопасно, исполняется всегда)",
    SAFE_WRITE: "обратимый ремонт без разрушения данных",
    DESTRUCTIVE: "необратимое действие: требует подтверждения",
}


def describe(cls: str) -> str:
    return _CLASS_RU.get(cls, "неизвестный класс")
