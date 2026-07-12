"""Узкий доступ к API Kubernetes для наблюдения и управления инфраструктурой из панели агента.

Слой домен-агностичен и не содержит зашитых имён узлов, сервисов или синонимов: наблюдаемое и
управляемое пространство имён, списки допустимых и запрещённых к перезапуску сервисов, а также
метка роли узла для дружеских имён берутся из конфигурации продукта (модуль ``config`` с единым
префиксом переменных окружения ``SENTINEL_``), топология же выясняется через сам API Kubernetes.
Доступ идёт через сервисный аккаунт пода с минимальным разграничением прав (чтение подов, узлов,
событий и деплойментов, перезапуск деплойментов и удаление подов). Перезапуск и удаление
разрешены строго безсостоятельным сервисам из allowlist и запрещены сервисам из denylist,
причём эта проверка выполняется до обращения к API. Вне кластера (при отсутствии токена
сервисного аккаунта) функции мягко деградируют, возвращая признак недоступности вместо падения.
Соглашения продукта описаны в ``docs/CONVENTIONS.md``.
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

# Метка роли узла для дружеских имён. Берётся из конфига продукта (SENTINEL_NODE_ROLE_LABEL),
# а не зашивается под конкретный кластер. Если метка на узлах не проставлена, агент оперирует
# именами узлов как есть.
NODE_ROLE_LABEL = _config.NODE_ROLE_LABEL

# Явные таймауты на все обращения к API Kubernetes (в секундах). Без таймаута зависший или
# недоступный API-сервер заморозил бы обработчик панели; с таймаутом отказ становится честной
# ошибкой. Значение единое, чтобы поведение было предсказуемым, чтение более тяжёлых ответов
# (логи, сводка kubelet) использует _READ_TIMEOUT.
_API_TIMEOUT = 10.0
_READ_TIMEOUT = 15.0


def _senv(name: str, default: str = "") -> str:
    """Значение переменной окружения продукта (префикс SENTINEL_) с обрезкой пробелов.

    Используется только для параметров дискавери node-agent, не представленных в модуле config
    (пространство имён, селектор меток и порт node-agent). Прочая конфигурация приходит из config,
    а не читается из окружения напрямую. Единый префикс SENTINEL_ соблюдается для всей настройки."""
    return os.getenv(name, default).strip()


def _senv_int(name: str, default: int) -> int:
    """Целочисленная переменная окружения продукта с устойчивостью к пустому и мусорному значению."""
    try:
        return int(_senv(name))
    except ValueError:
        return default


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


def _get_json(path: str, timeout: float = _API_TIMEOUT):
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
    """Список подов наблюдаемого пространства имён (config.NAMESPACE) для наблюдения: фаза, узел,
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
    """Свежие события наблюдаемого пространства имён (config.NAMESPACE): падения, выселения,
    нехватка ресурсов, для приложения к диагнозу. None вне кластера."""
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
        with httpx.Client(verify=ca, timeout=_READ_TIMEOUT) as cl:
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
    закрывает вопросы «где кончилось место» и «кто съел память» без Prometheus.
    None вне кластера, при неверном имени узла или если kubelet узла недоступен (сам по
    себе диагностический признак)."""
    if not _NAME_RE.match(str(node or "")):
        return None
    return _get_json(f"/api/v1/nodes/{node}/proxy/stats/summary", timeout=_READ_TIMEOUT)


def pod_service(pod_name: str) -> str:
    """Имя сервиса по имени пода деплоймента по стандартной схеме именования Kubernetes: у пода
    вида «<сервис>-<хэш ReplicaSet>-<хэш пода>» отрезаются два хвостовых сегмента, поэтому,
    например, «svc-6b9f7-x2x1c» приводится к «svc». Схема универсальна и не привязана ни к
    какому конкретному сервису."""
    parts = str(pod_name or "").split("-")
    if len(parts) >= 3:
        return "-".join(parts[:-2])
    return parts[0] if parts else ""


def delete_pod(pod: str):
    """Удаляет конкретный под: контроллер (ReplicaSet, Deployment, DaemonSet или StatefulSet)
    пересоздаёт его сам, поэтому удаление пода это обратимая ремонтная операция. Возвращает
    (ok, detail) с той же семантикой, что и rollout_restart. Дисциплина та же, что при перезапуске:
    имя проверяется по DNS-1123, а сервис-владелец пода обязан быть в allowlist и не в denylist,
    причём проверка выполняется до обращения к API."""
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
        with httpx.Client(verify=ca, timeout=_READ_TIMEOUT) as cl:
            r = cl.delete(f"{base}/api/v1/namespaces/{NAMESPACE}/pods/{pod}",
                          headers={"Authorization": f"Bearer {token}"})
    except Exception as e:
        return False, f"ошибка вызова API Kubernetes: {e}"
    if r.status_code in (200, 202):
        return True, "под удалён, контроллер пересоздаст его"
    return False, f"API Kubernetes вернул {r.status_code}"


def list_deployments():
    """Список деплойментов наблюдаемого пространства имён (config.NAMESPACE) со статусом реплик.
    None вне кластера, а также при недоступности или таймауте API Kubernetes (мягкая деградация,
    единообразно с прочими читающими функциями: панель показывает отсутствие данных, а не падает)."""
    c = _incluster()
    if c is None:
        return None
    base, token, ca = c
    try:
        with httpx.Client(verify=ca, timeout=_API_TIMEOUT) as cl:
            r = cl.get(f"{base}/apis/apps/v1/namespaces/{NAMESPACE}/deployments",
                       headers={"Authorization": f"Bearer {token}"})
            r.raise_for_status()
            data = r.json()
    except Exception:
        return None
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


def resolve_node(name: str) -> str | None:
    """Приводит дружеское имя узла к реальному имени узла Kubernetes, оставаясь домен-агностичным:
    зашитых имён узлов и зашитых синонимов в продукте нет, топология выясняется через API
    Kubernetes, а дружеские имена берутся из метки роли (config.NODE_ROLE_LABEL), если она
    проставлена на узлах.

    Разрешение идёт в три шага. Сначала проверяется точное имя узла: если переданная строка
    совпадает с именем существующего узла, она возвращается как есть. Затем, если на каком-либо
    узле проставлена метка роли config.NODE_ROLE_LABEL и её значение без учёта регистра совпадает с
    переданной строкой, возвращается имя этого узла (так работает «дружеское» имя, заданное
    владельцем кластера через метку роли). Наконец, пробуется совпадение по подстроке между
    переданной строкой и именем узла в обе стороны, что помогает распознать сокращённую форму
    имени. Возвращает None, если узел не найден. Вне кластера, когда список узлов недоступен,
    строка возвращается как есть при условии, что она является допустимым именем ресурса по
    DNS-1123, иначе None."""
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
    # 2. Дружеское имя из метки роли, заданной владельцем кластера (config.NODE_ROLE_LABEL).
    #    Никаких зашитых синонимов: сопоставляется только фактическое значение метки на узле.
    for n in nodes:
        labels = (n.get("metadata", {}) or {}).get("labels", {}) or {}
        role = labels.get(NODE_ROLE_LABEL)
        if role and str(role).lower() == low:
            nm = (n.get("metadata", {}) or {}).get("name")
            if nm:
                return nm
    # 3. Совпадение по подстроке имени узла (сокращённая форма реального имени).
    for nm in names:
        if nm and (low in nm.lower() or nm.lower() in low):
            return nm
    return None


def get_node_agent_endpoint(node: str):
    """Возвращает базовый адрес пода node-agent, работающего на указанном узле, вида
    «http://<podIP>:9110», либо None вне кластера или если под node-agent на узле не найден.

    node-agent это привилегированный DaemonSet: по одному поду на узел, слушает свой порт только
    внутрикластерно. Панель адресует под нужного узла по его podIP из API Kubernetes, поэтому
    команда исполняется именно на том хосте, который выбрал агент. Дискавери идёт по метке
    DaemonSet в наблюдаемом пространстве имён (config.NAMESPACE) с фильтром по имени узла
    (spec.nodeName). Параметры дискавери (пространство имён, селектор меток, порт) настраиваются
    переменными окружения продукта с префиксом SENTINEL_ и имеют нейтральные значения по умолчанию.
    Дружеское имя узла сначала приводится к реальному через resolve_node. Имя узла валидируется по
    DNS-1123 до подстановки в путь API."""
    node = resolve_node(node) or node
    if not _NAME_RE.match(str(node or "")):
        return None
    ns = _senv("SENTINEL_NODEAGENT_NAMESPACE") or NAMESPACE
    selector = _senv("SENTINEL_NODEAGENT_SELECTOR") or "app=node-agent"
    port = _senv_int("SENTINEL_NODEAGENT_PORT", 9110)
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
    try:
        with httpx.Client(verify=ca, timeout=_READ_TIMEOUT) as cl:
            r = cl.patch(f"{base}/apis/apps/v1/namespaces/{NAMESPACE}/deployments/{name}",
                         headers={"Authorization": f"Bearer {token}",
                                  "Content-Type": "application/strategic-merge-patch+json"},
                         content=json.dumps(patch))
    except Exception as e:
        return False, f"ошибка вызова API Kubernetes: {e}"
    if r.status_code in (200, 201):
        return True, "перезапуск инициирован"
    return False, f"API Kubernetes вернул {r.status_code}"
