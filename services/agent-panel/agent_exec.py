"""Агентный исполнитель команд эксплуатации: цикл использования инструментов языковой моделью.

Оператор пишет запрос на естественном языке, модель ведёт многошаговый диалог через клиента с
вызовом инструментов (llm.py): на каждом шаге она наблюдает состояние, рассуждает, действует и
проверяет результат. Инструменты, доступные модели:

  observe {argv, target, node}       чтение состояния кластера или узла. Классификатор обязан
                                     подтвердить, что команда действительно только читает; иначе
                                     шаг трактуется как мутация и проходит гейт автономии.
  act {argv, target, node, why}      мутация в кластере или на узле.
  explain {text}                     промежуточное объяснение оператору.
  done {summary}                     завершить задачу с итогом.

Ключевое свойство продукта: класс опасности каждой команды и решение о том, исполнять ли её
автономно, определяет ДЕТЕРМИНИРОВАННЫЙ гейт вне модели (policy.gate по уровню автономии из
config.autonomy()), поэтому модель физически не может обойти подтверждение необратимого. Уровни:

  observe      сухой прогон: любая мутация становится предложением оператору, ничего не исполняется.
  safe_repair  read и safe_write исполняются автономно; destructive и защищённое за подтверждением.
  full         автономно всё, кроме destructive и защищённого, которые подтверждаются всегда.

Дополнительный слой безопасности продукта: перезапуск сервиса из denylist (хранилища) и, при
непустом allowlist, перезапуск сервиса вне его требуют подтверждения независимо от уровня.

Гарды (guards.py) вызываются ПЕРЕД каждым автономным исполнением мутации: попытка резервируется
атомарно (record_attempt) до исполнения, что закрывает гонку проверки и фиксации. Каждое чтение и
каждая мутация пишутся в аудит (audit.py). Отложенные destructive и защищённые команды хранятся
персистентно (переживают перезапуск), привязаны к инициировавшему оператору и имеют срок жизни.

Топология НЕ зашита: перед диалогом агент снимает актуальный список узлов через API кластера и
передаёт его модели как факт на входе. Без ключа модели (llm.is_configured() ложно) исполнитель
работает как обработчик ОДНОЙ команды оператора: инструкция классифицируется и исполняется либо
предлагается, без планирования.
"""
from __future__ import annotations

import json
import os
import secrets
import shlex
import threading
import time
from pathlib import Path

import httpx

import audit
import config
import guards
import k8s
import llm
import mcp_tools
import policy
import slo

# Предел шагов агентного цикла: защита от бесконечного планирования модели.
AGENT_MAX_STEPS = int(os.getenv("SENTINEL_AGENT_MAX_STEPS", "12"))
# Ограничение вывода команды в трейсе и в результате инструмента, чтобы длинные логи не раздували
# ни ответ панели, ни контекст модели.
_OUTPUT_LIMIT = int(os.getenv("SENTINEL_AGENT_OUTPUT_LIMIT", "6000"))
# Таймаут узловой команды через node-agent.
_NODE_TIMEOUT = config.NODEAGENT_TIMEOUT
# Срок жизни отложенного подтверждения.
PENDING_TTL_SECONDS = int(os.getenv("SENTINEL_AGENT_PENDING_TTL_SECONDS", "300"))

# Каталог состояния вне рабочего дерева (тот же, что у гардов и аудита), чтобы агент не мог стереть
# собственные отложенные подтверждения как safe_write.
_STATE_DIR = os.getenv("SENTINEL_STATE_DIR", "/data")
_PENDING_PATH = Path(os.getenv("SENTINEL_AGENT_PENDING", str(Path(_STATE_DIR) / "agent-pending.json")))
_AUTONOMY_PATH = Path(os.getenv("SENTINEL_AGENT_AUTONOMY", str(Path(_STATE_DIR) / "agent-autonomy")))

_LOCK = threading.RLock()

# Потоколокальный контекст надёжности: доля ошибок текущего разбираемого инцидента. Ставится
# на время investigate из вердикта RCA и используется гейтом автономии, чтобы автономный ремонт
# запускался при прожигании бюджета ошибок, а не от одной уверенности модели. Вне разбора
# инцидента (например, одиночная команда оператора) контекст пуст и SLO-гейт не применяется.
_slo_ctx = threading.local()

_VALID_LEVELS = (config.AUTONOMY_OBSERVE, config.AUTONOMY_SAFE_REPAIR, config.AUTONOMY_FULL)
# Совместимость со старыми названиями режима панели.
_LEGACY_MODE = {"auto": config.AUTONOMY_SAFE_REPAIR, "manual": config.AUTONOMY_OBSERVE}

# Реестр инструментов открытых серверов MCP (наблюдаемость и прочее). Строится лениво из
# конфигурации; при отсутствии серверов пуст, и агент работает только со встроенными инструментами.
_REGISTRY: mcp_tools.MCPRegistry | None = None


def _mcp_registry() -> mcp_tools.MCPRegistry:
    global _REGISTRY
    if _REGISTRY is None:
        try:
            _REGISTRY = mcp_tools.build_registry()
        except Exception as e:  # noqa: BLE001 недоступность MCP не должна ронять панель
            print(f"agent_exec: реестр MCP не построен: {e}", flush=True)
            _REGISTRY = mcp_tools.MCPRegistry()
    return _REGISTRY


def _build_tools() -> list[dict]:
    """Встроенные инструменты плюс инструменты подключённых серверов MCP."""
    return _TOOLS + _mcp_registry().schemas()


# ---------------------------------------------------------------------------
# Уровень автономии (с горячим переопределением из интерфейса).
# ---------------------------------------------------------------------------

def effective_autonomy() -> str:
    """Действующий уровень автономии: переопределение из интерфейса (файл состояния) имеет приоритет
    над значением окружения config.autonomy(). При отсутствии или порче файла берётся окружение."""
    try:
        val = _AUTONOMY_PATH.read_text(encoding="utf-8").strip()
        if val in _VALID_LEVELS:
            return val
    except OSError:
        pass
    return config.autonomy()


def set_mode(level: str) -> str:
    """Переключает уровень автономии из интерфейса и персистентно его сохраняет. Принимает канонные
    уровни (observe, safe_repair, full) и старые названия (auto, manual). Недопустимое значение
    отклоняется мягко: остаётся прежний уровень."""
    val = str(level or "").strip().lower()
    val = _LEGACY_MODE.get(val, val)
    if val not in _VALID_LEVELS:
        return effective_autonomy()
    try:
        _AUTONOMY_PATH.parent.mkdir(parents=True, exist_ok=True)
        _AUTONOMY_PATH.write_text(val, encoding="utf-8")
    except OSError:
        pass
    return val


def get_mode() -> str:
    return effective_autonomy()


# ---------------------------------------------------------------------------
# Отложенные подтверждения (персистентные, привязаны к оператору, с TTL).
# ---------------------------------------------------------------------------

def _pending_load() -> dict:
    try:
        return json.loads(_PENDING_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _pending_save(data: dict) -> None:
    try:
        _PENDING_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = _PENDING_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data), encoding="utf-8")
        os.replace(tmp, _PENDING_PATH)
    except OSError as e:
        print(f"agent_exec: не удалось сохранить отложенное подтверждение: {e}", flush=True)


def _pending_prune(data: dict, now: float) -> dict:
    return {tok: p for tok, p in data.items() if p.get("expires", 0) > now}


def _stage_pending(argv, target, node, why, cls, operator) -> tuple[str, str]:
    """Ставит мутирующую команду в отложенное подтверждение и возвращает (token, message)."""
    now = time.time()
    token = secrets.token_urlsafe(16)
    with _LOCK:
        data = _pending_prune(_pending_load(), now)
        data[token] = {"argv": list(argv), "target": target, "node": node, "why": why,
                       "class": cls, "operator": operator, "created": now,
                       "expires": now + PENDING_TTL_SECONDS}
        _pending_save(data)
    audit.audit_pending(operator, "agent.stage", {"target": target, "node": node, "why": why},
                        node or target, cls, argv=list(argv))
    human = policy.describe(cls)
    msg = (f"Требуется подтверждение оператора: {human}. Команда: {' '.join(argv)}"
           + (f" на узле {node}" if node else "") + ".")
    return token, msg


def confirm(token: str, operator: str) -> dict:
    """Подтверждает и исполняет ранее отложенную команду по одноразовому токену. Токен привязан к
    инициировавшему оператору: подтвердить может только он. Исполнение идёт через гарды и аудит с
    отметкой confirmed=True."""
    now = time.time()
    with _LOCK:
        data = _pending_prune(_pending_load(), now)
        p = data.get(token)
        if not p:
            _pending_save(data)  # сохраняем результат чистки просроченных
            return {"ok": False, "message": "Токен не найден или истёк. Повторите запрос."}
        if p.get("operator") and p["operator"] != operator:
            # Токен НЕ расходуется: инициатор ещё сможет подтвердить.
            return {"ok": False, "message": "Подтвердить может только инициировавший оператор."}
        data.pop(token, None)
        _pending_save(data)
    if p.get("kind") == "mcp":
        return _confirm_mcp(p, operator)
    argv, target, node = p["argv"], p.get("target", "cluster"), p.get("node")
    res = _execute_mutation(argv, target, node, operator, confirmed=True)
    ok = _result_ok(res)
    out = _result_text(res)
    return {"ok": ok, "message": ("Исполнено." if ok else "Не удалось исполнить.") + (f" {out}" if out else ""),
            "result": res}


# ---------------------------------------------------------------------------
# Исполнение команд: узловой агент и кластер.
# ---------------------------------------------------------------------------

def _clip(s: str) -> str:
    s = str(s or "")
    return s if len(s) <= _OUTPUT_LIMIT else s[:_OUTPUT_LIMIT] + "\n...[обрезано]"


def _valid_argv(argv) -> bool:
    return isinstance(argv, list) and bool(argv) and all(isinstance(a, str) for a in argv)


def _run_node(node: str, argv, timeout: int = _NODE_TIMEOUT) -> dict:
    """Исполняет argv на узле через node-agent. Мягкая деградация: нет токена или узла даёт честную
    ошибку шага, а не падение."""
    if not config.NODEAGENT_TOKEN:
        return {"error": "узловые команды недоступны: не задан SENTINEL_NODEAGENT_TOKEN"}
    real = k8s.resolve_node(node) if node else None
    endpoint = k8s.get_node_agent_endpoint(real or node) if (real or node) else None
    if not endpoint:
        return {"error": f"node-agent на узле «{node}» не найден (панель вне кластера или узел неизвестен)"}
    try:
        with httpx.Client(timeout=timeout + 5) as c:
            r = c.post(f"{endpoint}/run", headers={"X-NodeAgent-Token": config.NODEAGENT_TOKEN},
                       json={"argv": list(argv), "timeout": timeout})
            r.raise_for_status()
            return r.json()
    except httpx.HTTPError as e:
        return {"error": f"ошибка обращения к node-agent: {e}"}


def _control_node() -> str | None:
    """Выбирает узел управляющего слоя для кластерных команд без зашитых имён: узел, чья метка роли
    (SENTINEL_NODE_ROLE_LABEL) указывает на control-plane, определяется живьём через resolve_node;
    если такого нет, берётся первый узел кластера. Роль в списке узлов не публикуется, поэтому
    control-plane выясняется именно по метке, а не по полю списка."""
    nodes = k8s.list_nodes() or []
    names = [n.get("name") for n in nodes if n.get("name")]
    for hint in ("control-plane", "controlplane", "master", "control"):
        resolved = k8s.resolve_node(hint)
        if resolved in names:
            return resolved
    return names[0] if names else None


def _cluster_read(argv) -> dict:
    """Кластерное чтение через API Kubernetes для распознанных намерений kubectl (не требует kubectl
    и kubeconfig на хосте). Нераспознанное чтение уходит на узловой агент управляющего узла."""
    base = os.path.basename(argv[0])
    if base in ("kubectl", "k", "oc") and len(argv) >= 2:
        verb = argv[1].lower()
        rest = [a.lower() for a in argv[2:] if not a.startswith("-")]
        if verb == "events":
            return {"data": k8s.list_events(), "source": "k8s-api"}
        if verb == "get":
            if any(r.startswith(("po", "pod")) for r in rest):
                return {"data": k8s.list_pods(), "source": "k8s-api"}
            if any(r.startswith(("no", "node")) for r in rest):
                return {"data": k8s.list_nodes(), "source": "k8s-api"}
            if any(r.startswith("event") for r in rest):
                return {"data": k8s.list_events(), "source": "k8s-api"}
            if any(r.startswith("deploy") for r in rest):
                return {"data": k8s.list_deployments(), "source": "k8s-api"}
        if verb == "logs":
            pod = next((a for a in argv[2:] if not a.startswith("-")), "")
            pod = pod.split("/")[-1]
            return {"data": k8s.pod_log_tail(pod), "source": "k8s-api"}
    node = _control_node()
    if not node:
        return {"error": "не удалось определить управляющий узел для кластерной команды; "
                         "используйте observe с target=node и явным узлом"}
    return _run_node(node, argv)


def _cluster_mutation(argv, now_iso: str) -> dict:
    """Кластерная мутация через типизированные операции API (rollout restart, delete pod). Прочее
    исполняется на управляющем узле через node-agent (честный отказ, если недоступно)."""
    base = os.path.basename(argv[0])
    if base in ("kubectl", "k", "oc") and len(argv) >= 2:
        verb = argv[1].lower()
        if verb == "rollout" and len(argv) >= 3 and argv[2].lower() == "restart":
            target = next((a for a in argv[3:] if not a.startswith("-")), "")
            ok, detail = k8s.rollout_restart(target, now_iso)
            return {"ok": ok, "detail": detail}
        if verb == "delete" and any(a.lower().startswith(("pod", "po")) for a in argv[2:]):
            pod = ""
            for a in argv[2:]:
                if a.startswith("-") or a.lower() in ("pod", "pods", "po"):
                    continue
                pod = a.split("/")[-1]
                break
            if pod:
                ok, detail = k8s.delete_pod(pod)
                return {"ok": ok, "detail": detail}
    node = _control_node()
    if not node:
        return {"error": "не удалось определить управляющий узел для кластерной мутации"}
    return _run_node(node, argv)


def _result_ok(res: dict) -> bool:
    if not isinstance(res, dict):
        return False
    if res.get("error"):
        return False
    if "ok" in res:
        return res["ok"] is True
    # Ответ node-agent: успех только при явном exit_code == 0 (частичный ответ без кода это неуспех).
    return res.get("exit_code") == 0


def _result_text(res: dict) -> str:
    if not isinstance(res, dict):
        return str(res)
    for key in ("stdout", "detail", "error"):
        v = res.get(key)
        if v:
            return _clip(v)
    if res.get("stderr"):
        return _clip(res["stderr"])
    if res.get("data") is not None:
        return _clip(json.dumps(res["data"], ensure_ascii=False))
    return ""


def _read(argv, target, node, operator) -> dict:
    """Исполняет чтение и пишет его в аудит (обращение к состоянию протоколируется)."""
    res = _run_node(node, argv) if target == "node" else _cluster_read(argv)
    audit.audit_read(operator, "agent.observe", node or target, _result_text(res)[:200],
                     params={"target": target, "node": node}, argv=list(argv))
    return res


def _fingerprint(argv, target, node) -> str:
    return f"{target}:{node or '-'}:{' '.join(argv)}"


def _restart_target(argv) -> str | None:
    """Имя сервиса, который перезапускает команда (для denylist/allowlist и кулдауна сервиса)."""
    base = os.path.basename(argv[0])
    if base in ("kubectl", "k", "oc"):
        if len(argv) >= 3 and argv[1].lower() == "rollout" and argv[2].lower() == "restart":
            tail = next((a for a in argv[3:] if not a.startswith("-")), "")
            return tail.split("/")[-1] or None
        if len(argv) >= 2 and argv[1].lower() == "delete":
            for a in argv[2:]:
                if a.startswith("-") or a.lower() in ("pod", "pods", "po"):
                    continue
                return k8s.pod_service(a.split("/")[-1]) or a.split("/")[-1]
    if base == "systemctl" and len(argv) >= 3 and argv[1].lower() in ("restart", "reload", "stop", "start"):
        return argv[2]
    return None


def _execute_mutation(argv, target, node, operator, confirmed: bool) -> dict:
    """Исполняет мутацию под гардами и аудитом. Резервирует попытку ДО исполнения (закрытие гонки),
    затем фиксирует исход. confirmed=True для подтверждённых оператором отложенных команд."""
    now = time.time()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    cls = policy.classify(argv)
    service = _restart_target(argv) or (node or target)
    fp = _fingerprint(argv, target, node)

    if not confirmed:
        allowed, why = guards.check(fp, "act", service, now)
        if not allowed:
            audit.audit_write(operator, "agent.act",
                              {"target": target, "node": node, "class": cls, "blocked": why},
                              node or target, False, f"заблокировано гардом: {why}",
                              op_type=audit.OP_EXECUTE, danger_class=cls, argv=list(argv))
            return {"error": f"заблокировано гардом: {why}", "blocked": True}
        guards.record_attempt(fp, "act", service, now)

    res = _run_node(node, argv) if target == "node" else _cluster_mutation(argv, now_iso)
    ok = _result_ok(res)
    if not confirmed:
        guards.record_result(fp, ok, now)
    actor = operator if confirmed else audit.ACTOR_AGENT
    audit.audit_write(actor, "agent.act", {"target": target, "node": node, "class": cls},
                      node or target, confirmed,
                      ("успех: " if ok else "неудача: ") + _result_text(res)[:400],
                      op_type=audit.OP_EXECUTE, danger_class=cls, argv=list(argv))
    return res


# ---------------------------------------------------------------------------
# Гейт автономии с учётом allowlist и denylist перезапуска.
# ---------------------------------------------------------------------------

def _decision(argv, level: str) -> str:
    """Действующее решение гейта: базовое из policy.gate плюс продуктовый слой allowlist/denylist
    перезапуска сервисов. Перезапуск (и равносильное ему удаление пода) сервиса из denylist или
    вне allowlist требует подтверждения независимо от уровня. Пустой allowlist по умолчанию означает
    «автономный перезапуск выключен»: на незнакомом кластере агент никого не перезапускает сам, а
    предлагает оператору, пока тот не перечислит доверенные безсостоятельные сервисы."""
    base = policy.gate(argv, level, config.PROTECTED_PATTERNS)
    if base != policy.AUTO:
        return base
    svc = _restart_target(argv)
    if svc:
        if svc in config.RESTART_DENYLIST or svc not in config.RESTART_ALLOWLIST:
            return policy.CONFIRM
    # Гейт по целям уровня обслуживания: автономная мутация без прожигания бюджета ошибок
    # понижается до предложения. Так ремонт запускается сам только когда страдает пользователь,
    # а не от абстрактной уверенности. Слой опционален: при незаданных SLO гейт всегда разрешает.
    er = getattr(_slo_ctx, "error_rate", None)
    if er is not None and not slo.gate(slo.evaluate(er)):
        return policy.PROPOSE
    return base


# ---------------------------------------------------------------------------
# Обработка одного вызова инструмента.
# ---------------------------------------------------------------------------

def _handle_tool(name: str, args: dict, operator: str, level: str) -> tuple[dict, str, bool]:
    """Обрабатывает один вызов инструмента модели. Возвращает (шаг трейса, содержимое tool_result
    для модели, stop). stop=True завершает ход (отложенное подтверждение), иначе цикл продолжается."""
    if name == "explain":
        text = str(args.get("text", "")).strip()
        return {"step": "explain", "text": text}, "ок", False
    if name == "done":
        summary = str(args.get("summary", "")).strip()
        return {"step": "done", "summary": summary}, "ок", False
    if mcp_tools.is_mcp_tool(name):
        return _handle_mcp(name, args, operator, level)

    argv = args.get("argv")
    target = (args.get("target") or "cluster").lower()
    node = args.get("node") or ""
    why = str(args.get("why", "")).strip()
    if not _valid_argv(argv):
        step = {"step": name, "argv": argv, "node": node, "outcome": "error",
                "result": {"error": "argv должен быть непустым списком строк"}}
        return step, "ошибка: argv должен быть непустым списком строк", False
    if target == "node" and not node:
        step = {"step": "node_cmd", "argv": argv, "node": node, "outcome": "error",
                "result": {"error": "для target=node нужно имя узла"}}
        return step, "ошибка: для target=node укажите node", False

    cls = policy.classify(argv)
    step_kind = "node_cmd" if target == "node" else "act"

    # Класс команды решает классификатор вне модели, а не её ярлык инструмента. Любая команда
    # класса read исполняется как чтение (безопасно всегда), даже если модель назвала её act; и
    # наоборот, названная observe мутация проходит гейт автономии, а не проскакивает как чтение.
    if cls == policy.READ:
        res = _read(argv, target, node, operator)
        step = {"step": "observe", "argv": argv, "node": node, "outcome": "executed", "result": res}
        return step, _result_text(res) or "нет вывода", False

    decision = _decision(argv, level)
    if decision == policy.PROPOSE:
        step = {"step": step_kind, "argv": argv, "node": node, "class": cls, "outcome": "proposed",
                "result": {"detail": "уровень наблюдения: действие только предложено, не исполнено"},
                "why": why}
        return step, ("Уровень автономии observe: это действие только предложение оператору, оно "
                      "не исполнено. Продолжай наблюдать и заверши done со сводкой предложений."), False
    if decision == policy.CONFIRM:
        token, msg = _stage_pending(argv, target, node, why, cls, operator)
        step = {"step": step_kind, "argv": argv, "node": node, "class": cls,
                "outcome": "pending_confirm", "confirm_token": token, "message": msg, "why": why}
        return step, msg + " Ход остановлен до подтверждения оператора.", True

    # AUTO: исполняем автономно под гардами и аудитом.
    res = _execute_mutation(argv, target, node, operator, confirmed=False)
    outcome = "blocked" if isinstance(res, dict) and res.get("blocked") else "executed"
    step = {"step": step_kind, "argv": argv, "node": node, "class": cls, "outcome": outcome,
            "result": res, "why": why}
    return step, _result_text(res) or ("исполнено" if _result_ok(res) else "нет вывода"), False


def _handle_mcp(name: str, args: dict, operator: str, level: str) -> tuple[dict, str, bool]:
    """Обрабатывает вызов инструмента открытого сервера MCP. Читающий инструмент (сервер помечен
    read_only) исполняется свободно с аудитом чтения. Инструмент потенциально мутирующего сервера
    не исполняется автономно: на уровне observe это предложение, иначе постановка в отложенное
    подтверждение оператора. Так структурированный вызов MCP не обходит защитную модель продукта."""
    reg = _mcp_registry()
    tool = reg.get(name)
    if tool is None:
        step = {"step": "act", "argv": [name], "outcome": "error",
                "result": {"error": "инструмент MCP не найден или сервер не подключён"}}
        return step, "ошибка: инструмент MCP не найден", False
    if tool.read_only:
        res = reg.call(name, args or {})
        ok = not res.get("error")
        text = res.get("text") or res.get("error") or ""
        audit.audit_read(operator, f"mcp.{name}", tool.server, text[:200], params={"args": args})
        step = {"step": "observe", "argv": [name], "node": tool.server, "mcp": True,
                "outcome": "executed" if ok else "error", "result": res}
        return step, _clip(text) or "нет вывода", False
    if level == config.AUTONOMY_OBSERVE:
        step = {"step": "act", "argv": [name], "node": tool.server, "mcp": True, "outcome": "proposed",
                "result": {"detail": "уровень наблюдения: инструмент MCP только предложен"}}
        return step, "Уровень observe: инструмент MCP не исполнен, только предложен оператору.", False
    token, msg = _stage_pending_mcp(name, args or {}, operator, tool.server)
    step = {"step": "act", "argv": [name], "node": tool.server, "mcp": True,
            "outcome": "pending_confirm", "confirm_token": token, "message": msg}
    return step, msg + " Ход остановлен до подтверждения оператора.", True


def _stage_pending_mcp(name: str, args: dict, operator: str, server: str) -> tuple[str, str]:
    """Ставит мутирующий вызов инструмента MCP в отложенное подтверждение."""
    now = time.time()
    token = secrets.token_urlsafe(16)
    with _LOCK:
        data = _pending_prune(_pending_load(), now)
        data[token] = {"kind": "mcp", "tool": name, "args": args, "server": server,
                       "operator": operator, "created": now, "expires": now + PENDING_TTL_SECONDS}
        _pending_save(data)
    audit.audit_pending(operator, "mcp.stage", {"tool": name, "args": args}, server, "mcp_mutation")
    msg = f"Требуется подтверждение оператора: вызов инструмента MCP {name} на сервере {server}."
    return token, msg


def _confirm_mcp(p: dict, operator: str) -> dict:
    """Исполняет подтверждённый вызов инструмента MCP под аудитом."""
    reg = _mcp_registry()
    res = reg.call(p["tool"], p.get("args") or {})
    ok = not res.get("error")
    text = res.get("text") or res.get("error") or ""
    audit.audit_write(operator, "mcp.call", {"tool": p["tool"]}, p.get("server") or "mcp", True,
                      ("успех: " if ok else "ошибка: ") + text[:400],
                      op_type=audit.OP_EXECUTE, danger_class="mcp")
    return {"ok": ok, "message": ("Исполнено." if ok else "Не удалось исполнить.")
            + (f" {_clip(text)}" if text else ""), "result": res}


# ---------------------------------------------------------------------------
# Системная инструкция и схема инструментов.
# ---------------------------------------------------------------------------

_SYSTEM = (
    "Ты автономный инженер по надёжности и эксплуатации (SRE) за терминалом кластера Kubernetes. "
    "Тебе дана инструкция оператора и актуальный снимок кластера. Ты домен-агностичен: не знаешь "
    "заранее имён сервисов и узлов, а выясняешь их наблюдением и из снимка. На каждом шаге вызывай "
    "инструменты. Порядок работы: сначала наблюдай (observe), рассуждай (explain), затем действуй "
    "(act), после проверяй результат наблюдением и заверши done со сводкой по-русски.\n"
    "target у observe и act это 'cluster' (поды, узлы, события, деплойменты, логи через API "
    "кластера) или 'node' (диск, процессор, память, процессы, containerd, systemctl на конкретном "
    "узле; тогда укажи node из снимка). argv это список отдельных аргументов, без склейки команд и "
    "без пробелов внутри одного аргумента.\n"
    "Опасное (удаление данных, томов, пространств имён, деплойментов, DROP таблиц, перезапуск "
    "хранилищ) не пытайся обойти: предлагай командой, детерминированная система сама решит, нужно "
    "ли подтверждение оператора, и остановит ход. Не выдумывай вывод команд: тебе возвращается "
    "фактический результат каждого шага."
)

_TOOLS = [
    {"name": "observe", "description": "Прочитать состояние кластера или узла.",
     "input_schema": {"type": "object", "properties": {
         "argv": {"type": "array", "items": {"type": "string"},
                  "description": "команда чтения списком аргументов"},
         "target": {"type": "string", "enum": ["cluster", "node"]},
         "node": {"type": "string", "description": "имя узла для target=node"}},
         "required": ["argv", "target"]}},
    {"name": "act", "description": "Мутирующая команда в кластере или на узле.",
     "input_schema": {"type": "object", "properties": {
         "argv": {"type": "array", "items": {"type": "string"}},
         "target": {"type": "string", "enum": ["cluster", "node"]},
         "node": {"type": "string"},
         "why": {"type": "string", "description": "зачем это действие, по-русски"}},
         "required": ["argv", "target", "why"]}},
    {"name": "explain", "description": "Промежуточное объяснение оператору по-русски.",
     "input_schema": {"type": "object", "properties": {"text": {"type": "string"}},
                      "required": ["text"]}},
    {"name": "done", "description": "Завершить задачу с итогом по-русски.",
     "input_schema": {"type": "object", "properties": {"summary": {"type": "string"}},
                      "required": ["summary"]}},
]


def _cluster_snapshot() -> str:
    """Актуальный снимок топологии как факт для модели: пространство имён и узлы с ролями. Без
    зашитых имён; при недоступности API честно сообщает об этом."""
    nodes = k8s.list_nodes()
    lines = [f"Пространство имён: {config.NAMESPACE}."]
    if nodes is None:
        lines.append("Снимок узлов недоступен (панель вне кластера): опирайся на наблюдение.")
    elif not nodes:
        lines.append("Узлы не обнаружены.")
    else:
        lines.append("Узлы кластера:")
        for n in nodes:
            flags = []
            if n.get("ready") is False:
                flags.append("не готов")
            if n.get("disk_pressure"):
                flags.append("давление диска")
            if n.get("memory_pressure"):
                flags.append("давление памяти")
            state = ", ".join(flags) if flags else "в норме"
            lines.append(f"  {n.get('name')} ({state})")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Публичный вход: агентный цикл и одиночная команда.
# ---------------------------------------------------------------------------

def run(instruction: str, operator: str = "operator", *, client: llm.LLMClient | None = None,
        seed_context: str = "") -> dict:
    """Исполняет запрос оператора. При наличии клиента модели ведёт полноценный агентный цикл; без
    клиента исполняет инструкцию как одиночную команду (классификация плюс гейт). Возвращает трейс
    шагов, действующий уровень автономии и итоговую сводку."""
    level = effective_autonomy()
    instruction = str(instruction or "").strip()
    if client is None and llm.is_configured():
        try:
            client = llm.build_client()
        except Exception:  # noqa: BLE001 недоступный SDK не должен ронять панель
            client = None

    if client is None:
        return _run_single(instruction, operator, level)

    conv = client.start(_SYSTEM, _build_tools())
    prompt = _cluster_snapshot() + "\n\nИнструкция оператора: " + instruction
    if seed_context:
        prompt += "\n\nКонтекст: " + seed_context
    client.send_user(conv, prompt)

    steps: list[dict] = []
    for _ in range(AGENT_MAX_STEPS):
        try:
            turn = client.run(conv)
        except Exception as e:  # noqa: BLE001 честная ошибка шага, не падение панели
            steps.append({"step": "error", "text": f"ошибка обращения к модели: {e}"})
            break
        if turn.text and not turn.tool_calls:
            steps.append({"step": "explain", "text": turn.text})
        results = []
        stop = False
        for call in turn.tool_calls:
            step, content, do_stop = _handle_tool(call.name, call.input or {}, operator, level)
            steps.append(step)
            results.append((call.id, _clip(content), step.get("outcome") == "error"))
            if step.get("step") == "done" or do_stop:
                stop = True
                break
        if stop:
            break
        if not turn.tool_calls:
            break  # модель завершила ответ текстом
        client.send_tool_results(conv, results)

    return {"steps": steps, "autonomy": level, "mode": level, "summary": _summary(steps)}


def _run_single(instruction: str, operator: str, level: str) -> dict:
    """Фолбэк без модели: инструкция оператора трактуется как одна команда. Для узла оператор пишет
    префикс 'node:<узел> ', иначе команда идёт в кластер."""
    target, node = "cluster", ""
    if instruction.lower().startswith("node:"):
        head, _, rest = instruction[5:].partition(" ")
        node, target, instruction = head.strip(), "node", rest.strip()
    try:
        argv = shlex.split(instruction)
    except ValueError:
        argv = instruction.split()
    if not _valid_argv(argv):
        return {"steps": [{"step": "error", "text": "пустая команда"}], "autonomy": level,
                "mode": level, "summary": "пустая команда"}
    step, _content, _stop = _handle_tool("act", {"argv": argv, "target": target, "node": node,
                                                 "why": "команда оператора"}, operator, level)
    return {"steps": [step], "autonomy": level, "mode": level, "summary": _summary([step])}


def investigate(verdict: dict, *, operator: str = "operator",
                client: llm.LLMClient | None = None) -> dict:
    """Агентный разбор инцидента: цикл над готовым вердиктом RCA (расследование плюс безопасный
    ремонт). Вердикт передаётся модели как контекст."""
    v = verdict or {}
    parts = []
    if v.get("root_cause"):
        parts.append(f"Предполагаемая первопричина: {v['root_cause']}.")
    if v.get("status"):
        parts.append(f"Статус: {v['status']}.")
    for e in (v.get("evidence") or [])[:5]:
        snip = e.get("snippet") if isinstance(e, dict) else str(e)
        if snip:
            parts.append(f"Свидетельство: {snip}")
    context = " ".join(parts) or "Вердикт без деталей."
    # Ставим контекст надёжности на время разбора: доля ошибок из вердикта питает SLO-гейт
    # автономии. Снимаем в finally, чтобы поток не унёс контекст в последующие вызовы.
    _slo_ctx.error_rate = v.get("error_rate")
    try:
        return run("Разберись в инциденте и, если безопасно, устрани первопричину.",
                   operator, client=client, seed_context=context)
    finally:
        _slo_ctx.error_rate = None


def _summary(steps: list[dict]) -> str:
    for s in reversed(steps):
        if s.get("step") == "done" and s.get("summary"):
            return s["summary"]
    for s in reversed(steps):
        if s.get("step") == "explain" and s.get("text"):
            return s["text"]
    for s in reversed(steps):
        if s.get("step") == "error" and s.get("text"):
            return s["text"]
    return "Готово."


def state_summary() -> dict:
    """Сводка состояния агента для карточки интерфейса: уровень автономии, готовность модели,
    состояние гардов, число отложенных подтверждений."""
    with _LOCK:
        pending = len(_pending_prune(_pending_load(), time.time()))
    return {"autonomy": effective_autonomy(), "mode": effective_autonomy(),
            "llm_configured": llm.is_configured(), "observe_only": guards.observe_only(),
            "pending": pending, "guards": guards.state_summary()}
