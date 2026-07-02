"""Детерминированная классификация команд агентного девопса (ADR-0041, спецификация раздел 4).

Классификатор живёт ВНЕ языковой модели: модель формулирует команду, а решение о том, можно ли
исполнить её автономно или нужно подтверждение оператора, принимает эта чистая функция по спискам
паттернов. Тем самым модель физически не может обойти подтверждение для класса finance или
destructive, потому что классификация не зависит от её вывода.

Функция classify(argv) относит команду к одному из четырёх классов:

  read         только чтение. Автономно всегда, в бюджет гардов не считается.
  safe_write   ремонт без разрушения данных: rollout restart, delete pod, scale, prune кешей,
               rm временных путей, kill процесса, systemctl restart, освобождение места.
               Автономно в auto-режиме, предложение в manual.
  finance      тарифы, баланс, платежи, деньги тенанта. ВСЕГДА подтверждение, в любом режиме.
  destructive  необратимое: rm -rf на данных, DROP или TRUNCATE таблиц, удаление PVC, PV,
               namespace, тома, тенанта, mkfs, wipefs, dd на устройство. ВСЕГДА подтверждение.

Дисциплина классификатора: он всегда ошибается в сторону подтверждения. НЕИЗВЕСТНАЯ мутирующая
команда трактуется как destructive (fail-safe). Список destructive и finance это критичный код:
любое дополнение сопровождается тестом в test_policy.py.

Классификатор устойчив к обходу: argv[0] нормализуется по basename (полный путь /usr/bin/docker
даёт тот же результат, что docker), учитываются сокращённые имена ресурсов Kubernetes (po, deploy,
ns и так далее), опасные флаги распознаются в любом месте argv.
"""
from __future__ import annotations

import os
import re

# Классы политики. Порядок строгости по возрастанию (read, safe_write, finance, destructive):
# при неоднозначности выбирается более строгий.
READ = "read"
SAFE_WRITE = "safe_write"
FINANCE = "finance"
DESTRUCTIVE = "destructive"


def _base(binary: str) -> str:
    """Нормализует имя бинаря по basename, чтобы полный путь не обходил классификатор.
    /usr/bin/docker и docker дают одно и то же имя, /snap/bin/kubectl тоже kubectl."""
    return os.path.basename(str(binary or "").strip())


# Read-only бинари без подкоманд: любая их форма это чтение (нет мутирующего варианта в нашем
# контуре, а опасные варианты вроде dd сюда не входят и классифицируются отдельно).
_READ_ONLY_BINARIES = {
    "df", "du", "free", "uptime", "ps", "ls", "top", "htop", "nproc", "lscpu",
    "lsblk", "lsmem", "vmstat", "iostat", "mpstat", "who", "w", "id", "date",
    "hostname", "uname", "dmesg", "netstat", "ss", "ip", "cat", "head", "tail",
    "less", "grep", "wc", "find", "stat", "readlink", "realpath", "env", "printenv",
    "getconf", "ulimit", "mount", "sensors", "nvidia-smi", "true", "echo", "which",
}

# Мутирующие подкоманды kubectl (всё, что меняет состояние кластера).
_KUBECTL_MUTATING_VERBS = {
    "delete", "patch", "apply", "create", "replace", "scale", "rollout", "edit",
    "annotate", "label", "cordon", "uncordon", "drain", "taint", "set", "expose",
    "run", "autoscale", "exec", "cp", "rollback",
}
# Read-only подкоманды kubectl.
_KUBECTL_READ_VERBS = {
    "get", "describe", "logs", "top", "api-resources", "api-versions", "explain",
    "version", "cluster-info", "config", "auth", "wait", "events",
}

# Нормализация сокращённых имён ресурсов Kubernetes к каноническим множественным формам.
# Нужна, чтобы kubectl delete po (сокращение pod) не проскочил мимо распознавания ресурса.
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

# Ресурсы Kubernetes, удаление которых необратимо и разрушительно: тома, хранилища, целые
# пространства имён, деплойменты и наборы. Их удаление это destructive. Единственный ресурс,
# удаление которого считается ремонтом (safe_write) это pod: контроллер пересоздаёт его.
_K8S_DESTRUCTIVE_RESOURCES = {
    "namespaces", "persistentvolumeclaims", "persistentvolumes", "deployments",
    "statefulsets", "daemonsets", "replicasets", "services", "storageclasses",
    "replicationcontrollers", "nodes",
}

# Пути, содержащие клиентские или ценные данные: любое разрушительное действие на них
# (rm -rf, mkfs) это destructive. Совпадение по вхождению подстроки, поэтому вложенные пути
# тоже ловятся (/var/lib/postgresql/data/base попадает по /var/lib/postgresql).
_DATA_PATH_MARKERS = (
    "/var/lib/postgresql", "/var/lib/postgres", "/pgdata", "/postgres-data",
    "/var/lib/rancher/k3s/storage", "/var/lib/kubelet/pods", "/mnt/s3", "/s3",
    "/data", "/srv", "/home", "/var/lib/redis", "/var/lib/mysql", "/backup",
    "/etc", "/root", "/boot", "/var/lib/rancher/k3s/server",
)

# Пути кешей и временных данных: их очистка это ремонт (safe_write), а не разрушение данных.
# Это исключения из общего правила «rm с рекурсией на пути это опасно».
_CACHE_PATH_MARKERS = (
    "/tmp/", "/tmp", "/var/tmp", "/var/cache", "/var/log", "/var/lib/docker/tmp",
    "/var/lib/docker/overlay2", "/var/lib/containerd/tmp", "/root/.cache", "/home/.cache",
    "/var/lib/docker/image", "/var/lib/docker/buildkit",
)

# Финансовые маркеры: пути административного API и имена таблиц, где живут деньги тенанта.
# Совпадение по вхождению подстроки в любой аргумент (регистр не важен).
_FINANCE_MARKERS = (
    "/api/admin/tariff", "grant-minutes", "grant_minutes", "reapply", "renew-plan",
    "renew_plan", "extend-storage", "extend_storage", "minute_packs", "subscriptions",
    "payments", "/api/admin/grant", "/api/admin/renew", "/api/admin/extend",
    "tariff", "balance", "minute-packs", "billing", "invoice",
)
# Финансовые команды панели (слэш-команды из commands.py, меняющие деньги тенанта).
_FINANCE_COMMANDS = {
    "/tariff", "/grant", "/reapply", "/renewplan", "/renew-plan", "/extendstorage",
    "/extend-storage",
}

# Разрушительные бинари: сама попытка их применить к устройству или файловой системе необратима.
_DESTRUCTIVE_BINARIES = {
    "mkfs", "wipefs", "fdisk", "sgdisk", "parted", "shred", "blkdiscard",
    "lvremove", "vgremove", "pvremove", "cryptsetup",
}

# Опасные SQL-глаголы: DROP и TRUNCATE всегда разрушительны, DELETE без WHERE тоже.
_SQL_DROP_RE = re.compile(r"\b(drop|truncate)\b", re.IGNORECASE)
_SQL_DELETE_RE = re.compile(r"\bdelete\s+from\b", re.IGNORECASE)
_SQL_WHERE_RE = re.compile(r"\bwhere\b", re.IGNORECASE)

# Прямые read-only подкоманды docker (чтение состояния демона и образов).
_DOCKER_READ_SUB = {"ps", "images", "stats", "inspect", "logs", "top", "port",
                    "version", "info", "events", "history", "diff", "search"}
# Прямые ремонтные подкоманды docker (освобождение места, удаление остановленных объектов).
_DOCKER_SAFE_WRITE_SUB = {"prune", "rm", "rmi", "kill", "stop", "restart", "start"}
# Групповые подкоманды docker (image, container, volume, network, builder, system): класс
# определяется вложенным глаголом. Чтение это ls/inspect/df/info, ремонт это prune/rm/kill.
_DOCKER_GROUP_SUB = {"image", "container", "volume", "network", "builder", "buildx", "system"}
_DOCKER_GROUP_READ_VERBS = {"ls", "inspect", "df", "info", "history", "list"}
_DOCKER_GROUP_WRITE_VERBS = {"prune", "rm", "rmi", "kill", "stop", "remove"}

# crictl: инструмент containerd. Чтение против ремонта.
_CRICTL_READ_SUB = {"ps", "images", "imagefsinfo", "stats", "inspect", "inspecti",
                    "info", "version", "pods", "logs", "stopp"}
_CRICTL_SAFE_WRITE_SUB = {"rmi", "rm", "rmp", "stop", "stopp"}


def _has_recursive_force(argv) -> bool:
    """Есть ли в argv признак рекурсивного и принудительного удаления (rm -rf в любой записи
    флагов: -rf, -fr, -r -f, --recursive --force)."""
    joined = " ".join(str(a) for a in argv)
    recursive = bool(re.search(r"(^|\s)-{1,2}[a-zA-Z]*r[a-zA-Z]*\b", joined)) or "--recursive" in joined
    force = bool(re.search(r"(^|\s)-{1,2}[a-zA-Z]*f[a-zA-Z]*\b", joined)) or "--force" in joined
    return recursive and force


def _paths_in(argv) -> list:
    """Позиционные аргументы, похожие на пути (начинаются с /). Опции пропускаются."""
    return [str(a) for a in argv[1:] if str(a).startswith("/")]


def _is_data_path(path: str) -> bool:
    p = str(path)
    # Явный кеш или временный путь не считается данными, даже если по подстроке пересекается.
    for marker in _CACHE_PATH_MARKERS:
        if p == marker or p.startswith(marker.rstrip("/") + "/") or p == marker.rstrip("/"):
            return False
    for marker in _DATA_PATH_MARKERS:
        if p == marker or p.startswith(marker + "/") or p == marker:
            return True
    return False


def _is_cache_path(path: str) -> bool:
    p = str(path)
    for marker in _CACHE_PATH_MARKERS:
        if p == marker or p.startswith(marker.rstrip("/") + "/") or p == marker.rstrip("/"):
            return True
    return False


def _finance_hit(argv) -> bool:
    """Есть ли в команде финансовый маркер (путь API тарифов, имя денежной таблицы, слэш-команда
    смены тарифа). Совпадение без учёта регистра по вхождению подстроки."""
    joined = " ".join(str(a) for a in argv).lower()
    if any(str(a).lower() in _FINANCE_COMMANDS for a in argv[:1]):
        return True
    for marker in _FINANCE_MARKERS:
        if marker.lower() in joined:
            return True
    return False


def _classify_kubectl(argv) -> str:
    """Классификация kubectl-подобной команды по подкоманде и целевому ресурсу."""
    if len(argv) < 2:
        return READ  # голый kubectl это по сути справка
    verb = str(argv[1]).lower()
    if verb in _KUBECTL_READ_VERBS:
        return READ
    if verb not in _KUBECTL_MUTATING_VERBS:
        # Неизвестная подкоманда kubectl это мутация с неясным эффектом: fail-safe в destructive.
        return DESTRUCTIVE
    # exec, cp, run, edit, apply, create, replace, patch, rollback: эффект произвольный,
    # безопасно классифицируем как destructive (fail-safe), кроме явно ремонтных ниже.
    if verb == "rollout":
        # rollout restart и rollout undo это ремонт без разрушения данных.
        return SAFE_WRITE
    if verb == "scale":
        return SAFE_WRITE
    if verb == "delete":
        return _classify_kubectl_delete(argv)
    if verb in ("cordon", "uncordon", "drain", "taint", "annotate", "label"):
        # drain выселяет поды, но не разрушает данные: ремонт узла. cordon/uncordon тоже.
        return SAFE_WRITE
    # patch, apply, create, replace, edit, set, expose, run, autoscale, exec, cp, rollback.
    return DESTRUCTIVE


def _classify_kubectl_delete(argv) -> str:
    """kubectl delete: удаление пода это ремонт (контроллер пересоздаст), удаление namespace,
    pvc, pv, deployment и прочих ресурсов из denylist это destructive (необратимо)."""
    resources = []
    for tok in argv[2:]:
        t = str(tok).lower()
        if t.startswith("-"):
            continue
        # Форма ресурс/имя (pods/foo) и форма ресурс имя (pods foo).
        head = t.split("/", 1)[0]
        canon = _K8S_RESOURCE_ALIASES.get(head)
        if canon:
            resources.append(canon)
    if not resources:
        # Возможно delete -f манифеста или по метке без явного ресурса: неясный эффект, fail-safe.
        return DESTRUCTIVE
    if any(r in _K8S_DESTRUCTIVE_RESOURCES for r in resources):
        return DESTRUCTIVE
    if resources == ["pods"] or set(resources) == {"pods"}:
        return SAFE_WRITE
    # Смешанное или иное: fail-safe.
    return DESTRUCTIVE


def _classify_docker(argv) -> str:
    if len(argv) < 2:
        return READ
    sub = str(argv[1]).lower()
    # Групповые подкоманды: класс по вложенному глаголу (docker image prune это ремонт,
    # docker image ls это чтение, docker system df это чтение, docker system prune это ремонт).
    if sub in _DOCKER_GROUP_SUB:
        verb = str(argv[2]).lower() if len(argv) > 2 else ""
        if verb in _DOCKER_GROUP_READ_VERBS:
            return READ
        if verb in _DOCKER_GROUP_WRITE_VERBS:
            return SAFE_WRITE
        # Неизвестный вложенный глагол группы: fail-safe в ремонт (docker network create тоже
        # не разрушает данные), но чтобы не проскочило разрушительное, ограничим ремонтом.
        return SAFE_WRITE
    if sub in _DOCKER_READ_SUB:
        return READ
    if sub in _DOCKER_SAFE_WRITE_SUB:
        return SAFE_WRITE
    # Неизвестная подкоманда docker: fail-safe.
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
    """journalctl это чтение, кроме модифицирующих флагов (--rotate, --vacuum-*, --flush)."""
    joined = " ".join(str(a) for a in argv).lower()
    if any(k in joined for k in ("--rotate", "--vacuum", "--flush", "--sync")):
        return SAFE_WRITE
    return READ


def _classify_systemctl(argv) -> str:
    """systemctl restart и reload это ремонт. stop/disable/mask меняют состояние сервиса тоже
    как ремонт (не разрушают данные). start/status тоже безопасны."""
    if len(argv) < 2:
        return READ
    sub = str(argv[1]).lower()
    if sub in ("status", "show", "list-units", "list-unit-files", "is-active",
               "is-enabled", "cat", "get-default"):
        return READ
    if sub in ("restart", "reload", "start", "stop", "enable", "disable", "mask",
               "unmask", "reload-or-restart", "try-restart", "daemon-reload"):
        return SAFE_WRITE
    return DESTRUCTIVE


def _classify_cat(argv) -> str:
    """cat разрешён к чтению всегда (это read-only бинарь). Перенаправление вывода в оболочке
    сюда не попадает: agent_exec исполняет argv списком без sh -c, поэтому cat не может писать."""
    return READ


def _classify_rm(argv) -> str:
    """rm: удаление кешей и временных путей это ремонт, удаление путей с данными это destructive.
    rm -rf на данных или без явных безопасных путей это destructive (fail-safe)."""
    paths = _paths_in(argv)
    recursive_force = _has_recursive_force(argv)
    if not paths:
        # rm без явного пути (относительные пути, ввод из переменной): неясно, fail-safe.
        return DESTRUCTIVE
    # Если хоть один путь это данные, вся команда destructive.
    if any(_is_data_path(p) for p in paths):
        return DESTRUCTIVE
    # Все пути это кеши или временные: ремонт.
    if all(_is_cache_path(p) for p in paths):
        return SAFE_WRITE
    # Прочие пути (например /opt/app/logs): рекурсивно-принудительное удаление на них рискованно,
    # трактуем как destructive, единичное удаление файла как ремонт.
    if recursive_force:
        return DESTRUCTIVE
    return SAFE_WRITE


def _classify_dd(argv) -> str:
    """dd: запись на устройство (of=/dev/...) необратима. Чтение (of отсутствует или of в файл
    временного пути) не наш кейс ремонта, но безопасно, поэтому строго проверяем цель of."""
    for a in argv[1:]:
        s = str(a)
        if s.startswith("of="):
            target = s[3:]
            if target.startswith("/dev/"):
                return DESTRUCTIVE
            if _is_data_path(target):
                return DESTRUCTIVE
    # dd без записи на устройство или данные: неясный, но потенциально опасный, fail-safe.
    return DESTRUCTIVE


def _classify_psql(argv) -> str:
    """psql или иной SQL-клиент: DROP, TRUNCATE, DELETE без WHERE это destructive. Прочий SQL
    (SELECT, а также UPDATE или INSERT) сам по себе неизвестен по риску: SELECT это чтение,
    мутации без разрушения таблиц трактуем как destructive fail-safe, если это не явно
    финансовая операция (её ловит finance выше по порядку)."""
    joined = " ".join(str(a) for a in argv)
    if _SQL_DROP_RE.search(joined):
        return DESTRUCTIVE
    if _SQL_DELETE_RE.search(joined) and not _SQL_WHERE_RE.search(joined):
        return DESTRUCTIVE
    # Только SELECT и никаких мутирующих ключевых слов: чтение.
    mutating = re.search(r"\b(insert|update|delete|alter|create|grant|revoke|drop|truncate)\b",
                         joined, re.IGNORECASE)
    if not mutating:
        return READ
    # Есть мутация, но не разрушение таблиц: fail-safe в destructive (например ALTER, UPDATE).
    return DESTRUCTIVE


def _classify_kill(argv) -> str:
    """kill и pkill процесса это ремонт (перезапуск зависшего процесса не разрушает данные)."""
    return SAFE_WRITE


def classify(argv) -> str:
    """Относит команду argv (список токенов) к классу политики: read, safe_write, finance
    или destructive. Чистая функция без побочных эффектов.

    Порядок разбора: сперва финансовый маркер (высший приоритет подтверждения после
    destructive-бинарей устройств), затем разрушительные бинари устройств, затем разбор по
    конкретному бинарю. НЕИЗВЕСТНАЯ мутирующая команда падает в destructive (fail-safe)."""
    if not argv or not isinstance(argv, (list, tuple)):
        return DESTRUCTIVE
    binary = _base(argv[0])
    if not binary:
        return DESTRUCTIVE

    # k3s это обёртка над встроенными инструментами: `k3s crictl ...`, `k3s kubectl ...`,
    # `k3s ctr ...`. Классифицируем по ВЛОЖЕННОЙ команде, иначе валидная чистка хранилища образов
    # `k3s crictl rmi --prune` посчиталась бы неизвестной командой и ушла бы в destructive с
    # подтверждением вместо автономного безопасного ремонта. Так на k3s-узлах агент чистит сам.
    if binary == "k3s" and len(argv) >= 2 and _base(argv[1]) in ("crictl", "kubectl", "ctr", "k", "oc"):
        return classify(list(argv[1:]))

    # Разрушительные бинари устройств и файловых систем: решают сразу, обходить их через
    # финансовые маркеры бессмысленно, но mkfs с деньгами не бывает, поэтому порядок неважен.
    if binary in _DESTRUCTIVE_BINARIES:
        return DESTRUCTIVE
    if binary == "dd":
        return _classify_dd(argv)

    # Финансовый маркер имеет приоритет над обычной классификацией (curl к /api/admin/tariff,
    # psql к payments): любая такая команда это finance и требует подтверждения. Проверяется до
    # разбора по бинарю, чтобы http-клиент к финансовому пути не проскочил как безобидный.
    if _finance_hit(argv):
        return FINANCE

    # Явно read-only бинари.
    if binary in _READ_ONLY_BINARIES:
        if binary == "cat":
            return _classify_cat(argv)
        return READ

    if binary == "kubectl" or binary == "k" or binary == "oc":
        return _classify_kubectl(argv)
    if binary == "docker" or binary == "podman" or binary == "nerdctl":
        return _classify_docker(argv)
    if binary == "crictl":
        return _classify_crictl(argv)
    if binary == "journalctl":
        return _classify_journalctl(argv)
    if binary == "systemctl":
        return _classify_systemctl(argv)
    if binary == "rm":
        return _classify_rm(argv)
    if binary in ("kill", "pkill", "killall"):
        return _classify_kill(argv)
    if binary in ("psql", "mysql", "clickhouse-client"):
        return _classify_psql(argv)
    if binary in ("sync", "sysctl", "renice", "ionice", "nice", "chrt"):
        # Освобождение места и настройка планировщика без разрушения данных.
        return SAFE_WRITE
    if binary in ("truncate",):
        # truncate урезает файл: рискованно на данных.
        paths = _paths_in(argv)
        if any(_is_data_path(p) for p in paths):
            return DESTRUCTIVE
        return SAFE_WRITE

    # Любой прочий бинарь неизвестного эффекта: fail-safe в destructive.
    return DESTRUCTIVE


def requires_confirmation(cls: str) -> bool:
    """Требует ли класс подтверждения оператора В ЛЮБОМ режиме (finance и destructive)."""
    return cls in (FINANCE, DESTRUCTIVE)


def is_read(cls: str) -> bool:
    return cls == READ


def is_mutation(cls: str) -> bool:
    """Является ли класс мутацией (всё, кроме чистого чтения)."""
    return cls in (SAFE_WRITE, FINANCE, DESTRUCTIVE)


# Человеко-читаемое пояснение класса для карточки оператора (по-русски).
_CLASS_RU = {
    READ: "чтение (безопасно, исполняется всегда)",
    SAFE_WRITE: "ремонт без разрушения данных (автономно в auto-режиме)",
    FINANCE: "деньги тенанта (тариф, баланс, платёж): требует подтверждения всегда",
    DESTRUCTIVE: "необратимое действие: требует подтверждения всегда",
}


def describe(cls: str) -> str:
    return _CLASS_RU.get(cls, "неизвестный класс")
