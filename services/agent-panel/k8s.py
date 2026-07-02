"""Узкий доступ к Kubernetes для управления инфраструктурой из панели (ADR-0033, фаза 4).
Только пространство имён krokki и только через сервисный аккаунт пода с минимальным RBAC
(чтение деплойментов и их перезапуск). Перезапуск разрешён строго безсостоятельным сервисам
из allowlist; хранилища и особые поды (postgres, redis, vllm, stalwart) в denylist и не
перезапускаются из панели, потому что их рестарт вызывает простой или несовместим с одной
репликой. Вне кластера (нет токена сервисного аккаунта) функции мягко деградируют.
"""
from __future__ import annotations

import json
import os
import re

import httpx

# Имя ресурса Kubernetes (DNS-1123): единственная допустимая форма имени пода и узла.
# Проверка до подстановки имени в путь API исключает выход за пределы намеченного пути.
_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")

import config as _config

NAMESPACE = _config.NAMESPACE
_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Списки допустимых и запрещённых к перезапуску сервисов берутся из конфига продукта
# (переменные RESTART_ALLOWLIST и RESTART_DENYLIST), а не зашиты под приложение. Пустой
# allowlist означает, что автономный перезапуск выключен, пока адоптер не перечислит свои
# безсостоятельные сервисы, что безопасно для незнакомого кластера. Denylist защищает
# хранилища и особые поды всегда.
ALLOWED = _config.RESTART_ALLOWLIST
DENY = _config.RESTART_DENYLIST


def _incluster():
    """Возвращает (base_url, token, ca) при запуске в кластере, иначе None."""
    host = os.getenv("KUBERNETES_SERVICE_HOST")
    port = os.getenv("KUBERNETES_SERVICE_PORT", "443")
    if not host or not os.path.exists(_TOKEN_PATH):
        return None
    try:
        token = open(_TOKEN_PATH, encoding="utf-8").read().strip()
    except OSError:
        return None
    ca = _CA_PATH if os.path.exists(_CA_PATH) else False
    return f"https://{host}:{port}", token, ca


def _get_json(path: str, timeout: float = 10.0):
    """Чтение произвольного пути API Kubernetes сервисным аккаунтом пода. Возвращает
    разобранный JSON либо None вне кластера или при ошибке (мягкая деградация: панель
    остаётся работоспособной, просто показывает, что данные недоступны)."""
    c = _incluster()
    if c is None:
        return None
    base, token, ca = c
    try:
        with httpx.Client(verify=ca, timeout=timeout) as cl:
            r = cl.get(f"{base}{path}", headers={"Authorization": f"Bearer {token}"})
            r.raise_for_status()
            return r.json()
    except Exception:
        return None


def list_pods():
    """Список подов пространства krokki для наблюдения (ADR-0038, этап 2): фаза, узел,
    рестарты, причины ожидания (CrashLoopBackOff, ImagePullBackOff), признак OOMKilled
    последнего завершения и время последнего рестарта. None вне кластера."""
    data = _get_json(f"/api/v1/namespaces/{NAMESPACE}/pods")
    if data is None:
        return None
    out = []
    for p in data.get("items", []):
        meta = p.get("metadata", {}) or {}
        status = p.get("status", {}) or {}
        restarts = 0
        waiting_reason = None
        oom_killed = False
        last_restart_at = None
        for cs in status.get("containerStatuses") or []:
            restarts += cs.get("restartCount", 0) or 0
            waiting = (cs.get("state") or {}).get("waiting") or {}
            if waiting.get("reason"):
                waiting_reason = waiting["reason"]
            term = (cs.get("lastState") or {}).get("terminated") or {}
            if term.get("reason") == "OOMKilled":
                oom_killed = True
            fin = term.get("finishedAt")
            if fin and (last_restart_at is None or fin > last_restart_at):
                last_restart_at = fin
        out.append({
            "name": meta.get("name", ""),
            "phase": status.get("phase", ""),
            "node": (p.get("spec", {}) or {}).get("nodeName", ""),
            "restarts": restarts,
            "waiting_reason": waiting_reason,
            "oom_killed": oom_killed,
            "last_restart_at": last_restart_at,
        })
    out.sort(key=lambda x: x["name"])
    return out


def list_nodes():
    """Список узлов кластера: условия Ready, MemoryPressure, DiskPressure и ёмкости
    (capacity и allocatable по процессору и памяти). None вне кластера. Требует
    ClusterRole: узлы это кластерный ресурс, а не ресурс пространства имён."""
    data = _get_json("/api/v1/nodes")
    if data is None:
        return None
    out = []
    for n in data.get("items", []):
        meta = n.get("metadata", {}) or {}
        status = n.get("status", {}) or {}
        conds = {c.get("type"): c.get("status") == "True"
                 for c in status.get("conditions") or []}
        out.append({
            "name": meta.get("name", ""),
            "ready": conds.get("Ready", False),
            "memory_pressure": conds.get("MemoryPressure", False),
            "disk_pressure": conds.get("DiskPressure", False),
            "capacity": status.get("capacity", {}) or {},
            "allocatable": status.get("allocatable", {}) or {},
        })
    out.sort(key=lambda x: x["name"])
    return out


def list_events(limit: int = 50):
    """Свежие события пространства krokki (падения, выселения, нехватка ресурсов) для
    приложения к диагнозу. None вне кластера."""
    data = _get_json(f"/api/v1/namespaces/{NAMESPACE}/events?limit={int(limit)}")
    if data is None:
        return None
    out = []
    for e in data.get("items", []):
        out.append({
            "type": e.get("type", ""),
            "reason": e.get("reason", ""),
            "message": e.get("message", ""),
            "object": (e.get("involvedObject", {}) or {}).get("name", ""),
            "count": e.get("count", 1) or 1,
            "last_seen": e.get("lastTimestamp") or e.get("eventTime") or "",
        })
    out.sort(key=lambda x: x["last_seen"], reverse=True)
    return out


def pod_log_tail(pod: str, lines: int = 100):
    """Хвост лога пода (последние строки) для цитат в карточке инцидента. Возвращает
    текст либо None вне кластера, при неверном имени пода или при ошибке."""
    if not _NAME_RE.match(str(pod or "")):
        return None
    c = _incluster()
    if c is None:
        return None
    base, token, ca = c
    try:
        with httpx.Client(verify=ca, timeout=15.0) as cl:
            r = cl.get(f"{base}/api/v1/namespaces/{NAMESPACE}/pods/{pod}/log",
                       params={"tailLines": int(lines)},
                       headers={"Authorization": f"Bearer {token}"})
            r.raise_for_status()
            return r.text
    except Exception:
        return None


def node_stats_summary(node: str):
    """Сводка kubelet узла через прокси API-сервера (/api/v1/nodes/{node}/proxy/stats/summary):
    фактическое использование процессора, памяти и файловых систем по узлу и подам. Это
    закрывает вопросы «где кончилось место» и «кто съел память» без Prometheus (ADR-0038).
    None вне кластера, при неверном имени узла или если kubelet узла недоступен (сам по
    себе диагностический признак)."""
    if not _NAME_RE.match(str(node or "")):
        return None
    return _get_json(f"/api/v1/nodes/{node}/proxy/stats/summary", timeout=15.0)


def pod_service(pod_name: str) -> str:
    """Имя сервиса по имени пода деплоймента: worker-6b9f7-x2x1c принадлежит worker
    (отрезаются два хвостовых сегмента хэшей ReplicaSet и пода)."""
    parts = str(pod_name or "").split("-")
    if len(parts) >= 3:
        return "-".join(parts[:-2])
    return parts[0] if parts else ""


def delete_pod(pod: str):
    """Удаляет конкретный под (плейбук A4, действие a3 уровня A): контроллер пересоздаст
    его сам. Возвращает (ok, detail) как rollout_restart. Та же дисциплина, что и у
    перезапуска: имя проверяется по DNS-1123, а сервис-владелец пода обязан быть в
    allowlist и не в denylist, причём проверка идёт ДО обращения к API."""
    if not _NAME_RE.match(str(pod or "")):
        return False, "недопустимое имя пода"
    svc = pod_service(pod)
    if svc in DENY:
        return False, f"под сервиса «{svc}» в denylist: удаление из панели запрещено"
    if svc not in ALLOWED:
        return False, f"сервис «{svc}» не в allowlist безсостоятельных сервисов"
    c = _incluster()
    if c is None:
        return None, "вне кластера: нет доступа к API Kubernetes"
    base, token, ca = c
    try:
        with httpx.Client(verify=ca, timeout=15.0) as cl:
            r = cl.delete(f"{base}/api/v1/namespaces/{NAMESPACE}/pods/{pod}",
                          headers={"Authorization": f"Bearer {token}"})
    except Exception as e:
        return False, f"ошибка вызова API Kubernetes: {e}"
    if r.status_code in (200, 202):
        return True, "под удалён, контроллер пересоздаст его"
    return False, f"API Kubernetes вернул {r.status_code}"


def list_deployments():
    """Список деплойментов пространства krokki со статусом реплик. None вне кластера."""
    c = _incluster()
    if c is None:
        return None
    base, token, ca = c
    with httpx.Client(verify=ca, timeout=10.0) as cl:
        r = cl.get(f"{base}/apis/apps/v1/namespaces/{NAMESPACE}/deployments",
                   headers={"Authorization": f"Bearer {token}"})
        r.raise_for_status()
        data = r.json()
    out = []
    for d in data.get("items", []):
        name = d.get("metadata", {}).get("name", "")
        st = d.get("status", {}) or {}
        sp = d.get("spec", {}) or {}
        out.append({
            "name": name,
            "desired": sp.get("replicas", 0),
            "ready": st.get("readyReplicas", 0) or 0,
            "available": st.get("availableReplicas", 0) or 0,
        })
    out.sort(key=lambda x: x["name"])
    return out


# Дружеские синонимы узлов, чтобы оператор говорил по-человечески («на управляющем», «на gpu»,
# «на gooseek»), а не точным именем узла Kubernetes. Синоним сопоставляется с ролью узла
# (метка krokki.io/role), а роль с реальным именем узла. Так путь одинаково работает и с
# управляющим узлом, где живёт основное приложение, и с домашним GPU-узлом.
_NODE_ROLE_ALIASES = {
    "control": {"control", "controlplane", "control-plane", "управляющий", "управляющем",
                "мастер", "master", "cloud", "облако", "облачный", "api", "control-node"},
    "gpu": {"gpu", "гпу", "видеокарта", "домашний", "home", "ml", "инференс", "gooseek",
            "gooseek-serv", "гусик"},
}


def resolve_node(name: str) -> str | None:
    """Приводит дружеское имя узла к реальному имени узла Kubernetes. Точное имя возвращается как
    есть; синоним роли (control, gpu и т. п.) резолвится по метке krokki.io/role; иначе пробуется
    совпадение по подстроке имени (например «gooseek» совпадает с «gooseek-serv»). Возвращает None,
    если узел не найден или нет доступа к кластеру. Так агент понимает и «на управляющем», и точное
    «msk-1-vm-94q6», и «на gooseek»."""
    raw = str(name or "").strip()
    if not raw:
        return None
    data = _get_json("/api/v1/nodes")
    if data is None:
        # Вне кластера резолвить не по чему: возвращаем как есть, если это валидное имя.
        return raw if _NAME_RE.match(raw) else None
    nodes = data.get("items", []) or []
    names = [n.get("metadata", {}).get("name", "") for n in nodes]
    # 1. Точное имя узла.
    if raw in names:
        return raw
    low = raw.lower()
    # 2. Синоним роли.
    for role, aliases in _NODE_ROLE_ALIASES.items():
        if low in aliases:
            for n in nodes:
                if (n.get("metadata", {}).get("labels", {}) or {}).get("krokki.io/role") == role:
                    return n.get("metadata", {}).get("name")
    # 3. Совпадение по подстроке имени узла.
    for nm in names:
        if nm and (low in nm.lower() or nm.lower() in low):
            return nm
    return None


def get_node_agent_endpoint(node: str):
    """Возвращает базовый адрес пода node-agent, работающего на указанном узле, вида
    «http://<podIP>:9110», либо None вне кластера или если под node-agent на узле не найден.

    node-agent это привилегированный DaemonSet (ADR-0041, раздел 2): по одному поду на узел,
    слушает порт 9110 только внутрикластерно. Панель адресует под нужного узла по его podIP из
    Kubernetes API, поэтому команда исполняется именно на том хосте, который выбрал агент.
    Дискавери идёт по меткам DaemonSet (app=node-agent) в пространстве krokki с фильтром по
    имени узла (spec.nodeName). Дружеское имя узла сначала приводится к реальному через
    resolve_node. Имя узла валидируется по DNS-1123 до подстановки в путь API."""
    node = resolve_node(node) or node
    if not _NAME_RE.match(str(node or "")):
        return None
    ns = os.getenv("NODE_AGENT_NAMESPACE", NAMESPACE)
    selector = os.getenv("NODE_AGENT_SELECTOR", "app=node-agent")
    port = int(os.getenv("NODE_AGENT_PORT", "9110"))
    data = _get_json(f"/api/v1/namespaces/{ns}/pods?labelSelector={selector}")
    if data is None:
        return None
    for p in data.get("items", []):
        spec = p.get("spec", {}) or {}
        status = p.get("status", {}) or {}
        if spec.get("nodeName") != node:
            continue
        pod_ip = status.get("podIP")
        if pod_ip:
            return f"http://{pod_ip}:{port}"
    return None


def rollout_restart(name: str, now_iso: str):
    """Перезапускает деплоймент (аннотация restartedAt). Возвращает (ok, detail): ok=True успех,
    ok=False отказ по правилам или ошибке, ok=None вне кластера. Проверка allowlist/denylist идёт
    ДО обращения к API, поэтому запрещённый сервис не трогается ни при каких условиях."""
    if name in DENY:
        return False, f"сервис «{name}» в denylist: перезапуск из панели запрещён (хранилище или особый под)"
    if name not in ALLOWED:
        return False, f"сервис «{name}» не в allowlist безсостоятельных сервисов"
    c = _incluster()
    if c is None:
        return None, "вне кластера: нет доступа к API Kubernetes"
    base, token, ca = c
    patch = {"spec": {"template": {"metadata": {"annotations": {
        "kubectl.kubernetes.io/restartedAt": now_iso}}}}}
    with httpx.Client(verify=ca, timeout=15.0) as cl:
        r = cl.patch(f"{base}/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{name}",
                     headers={"Authorization": f"Bearer {token}",
                              "Content-Type": "application/strategic-merge-patch+json"},
                     content=json.dumps(patch))
    if r.status_code in (200, 201):
        return True, "перезапуск инициирован"
    return False, f"API Kubernetes вернул {r.status_code}"
