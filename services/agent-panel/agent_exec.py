"""Агентный исполнитель команд девопса: цикл использования инструментов языковой моделью
(ADR-0041, спецификация разделы 3, 4, 5, 6, 8).

Модель (Gemma через _llm_complete из commands.py) на каждом шаге возвращает СТРОГО один JSON
вызова инструмента. Схема проверяется кодом (как в solve.py), при мусоре фолбэк. Инструменты:

  observe {argv, target}       чтение состояния. Классификатор ОБЯЗАН подтвердить read, иначе
                               шаг трактуется как act. В бюджет гардов не считается.
  act {argv, target, why}      мутация в кластере или локально. Классифицируется policy.py.
  node_cmd {node, argv, why}   мутация или чтение на конкретном узле через node-agent.
  explain {text}               промежуточное объяснение оператору по-русски.
  done {summary}               завершить задачу с итогом.

Политика исполнения (раздел 4):
  auto-режим:    read и safe_write исполняются сразу; finance и destructive уходят в отложенное
                 подтверждение (PENDING-токен), НЕ исполняются автономно.
  manual-режим:  любая мутация (safe_write, finance, destructive) возвращается оператору как
                 предложение; observe агент делает сам, чтобы собрать данные.

Гарды (guards.py) вызываются ПЕРЕД каждым исполнением мутации: бюджет часа, кулдаун, предохранитель,
осцилляция. Каждое исполнение пишется в audit.py (actor=agent или actor=<оператор>).

Мягкая деградация: нет node-agent или токена даёт честную ошибку шага, не падение. Без модели
(_llm_complete недоступен) agent_exec работает как исполнитель ОДНОЙ команды оператора без
планирования: одна инструкция классифицируется и исполняется либо предлагается.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shlex
import time
from pathlib import Path

import httpx

import guards
import k8s
import policy
from audit import audit_write

# Предел шагов агентного цикла (наблюдение не считается в бюджет гардов, но общий предел шагов
# защищает от бесконечного планирования модели).
AGENT_MAX_STEPS = int(os.getenv("AGENT_MAX_STEPS", "12"))

# Токен доступа к node-agent (общий секрет, заголовок X-NodeAgent-Token). Пусто означает, что
# узловые команды недоступны и дают честную ошибку шага, а не падение.
NODEAGENT_TOKEN = os.getenv("NODEAGENT_TOKEN", "")
NODEAGENT_TIMEOUT = int(os.getenv("NODEAGENT_TIMEOUT", "30"))

# Ограничение вывода команды в трейсе шага, чтобы длинные логи не раздували ответ панели.
_OUTPUT_LIMIT = int(os.getenv("AGENT_OUTPUT_LIMIT", "8000"))

# Время жизни и хранилище отложенных finance и destructive команд (PENDING-механизм с
# одноразовым токеном и TTL, по образцу commands.PENDING).
PENDING_TTL_SECONDS = int(os.getenv("AGENT_PENDING_TTL_SECONDS", "300"))
PENDING: dict = {}

# Персистентный флаг режима работы агента: auto (по умолчанию) или manual. Хранится простым
# файлом рядом с журналом инцидентов, чтобы режим переживал перезапуск панели.
_MODE_PATH = Path(os.getenv("ADMINCHAT_AGENT_MODE",
                            str(Path(__file__).parent / "agent-mode.txt")))
_VALID_MODES = ("auto", "manual")


def get_mode() -> str:
    """Текущий режим агента (auto или manual). При отсутствии или порче файла возвращает auto."""
    try:
        val = _MODE_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return "auto"
    return val if val in _VALID_MODES else "auto"


def set_mode(mode: str) -> str:
    """Переключает режим агента. Возвращает установленный режим. Недопустимое значение
    отклоняется мягко (остаётся прежний режим)."""
    mode = str(mode or "").strip().lower()
    if mode not in _VALID_MODES:
        return get_mode()
    try:
        _MODE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _MODE_PATH.write_text(mode, encoding="utf-8")
    except OSError:
        pass
    return mode


# ---------------------------------------------------------------------------
# Системная инструкция и схема инструментов для модели.
# ---------------------------------------------------------------------------

SYSTEM = (
    "Ты автономный девопс-агент платформы KROKKI за терминалом кластера. Тебе дана инструкция "
    "оператора и, при наличии, результаты прошлых шагов. На КАЖДОМ шаге верни СТРОГО один "
    "JSON-объект вызова ОДНОГО инструмента, без текста вокруг. Инструменты:\n"
    '{"tool":"observe","argv":["kubectl","get","pods"],"target":"cluster"}: чтение состояния '
    "(kubectl get/describe/logs/top, df, du, docker ps, crictl images, ps, free, uptime, cat "
    "/proc). target это cluster|control|gpu.\n"
    '{"tool":"act","argv":["kubectl","rollout","restart","deployment/asr"],"target":"cluster",'
    '"why":"по-русски зачем"}: мутирующая команда (rollout restart, delete pod, prune, rm кеша, '
    "kill, systemctl restart).\n"
    '{"tool":"node_cmd","node":"gpu","argv":["df","-h","/"],"why":"по-русски зачем"}: команда на '
    "конкретном узле через node-agent.\n"
    '{"tool":"explain","text":"по-русски промежуточное объяснение"}: рассуждение оператору.\n'
    '{"tool":"done","summary":"по-русски итог"}: завершить задачу.\n'
    "Сначала наблюдай (observe), рассуждай (explain), потом действуй (act или node_cmd), затем "
    "проверяй результат наблюдением и заверши done. Опасное (удаление данных, деньги тенанта) "
    "предлагай командой, система сама спросит подтверждение.\n"
    "ТОПОЛОГИЯ. В кластере два узла: управляющий (node=control, на нём api, web, базы, панель) и "
    "домашний GPU-узел gooseek (node=gpu, на нём ML: asr, llm, diarize). Слова «gooseek», «гусик», "
    "«gpu», «видеокарта» это ОДИН И ТОТ ЖЕ узел node=gpu, а не под и не сервис: не ищи его среди "
    "подов. Вопросы про диск, процессор, память, файлы, docker и containerd УЗЛА решай через "
    "node_cmd с node=control или node=gpu. Вопросы про поды, деплойменты, очередь заданий, тенантов "
    "решай через observe и act в кластере.\n"
    "Правила: argv это список отдельных аргументов, НЕ склеивай несколько команд в один argv и НЕ "
    "клади пробелы внутрь одного аргумента (пиши [\"du\",\"-sh\",\"--max-depth=1\",\"/\"], а не "
    "[\"du\",\"-sh\",\"/ --max-depth=1\"]). Каждый предыдущий шаг возвращает тебе фактический вывод "
    "(stdout, код возврата): опирайся на него, не выдумывай. Не повторяй одну и ту же команду, если "
    "она уже дала результат. Узлы работают на k3s (containerd), докера для рантайма нет. Для "
    "чистки диска узла корректные команды: осмотр [\"df\",\"-h\",\"/\"] и вглубь "
    "[\"du\",\"-xh\",\"--max-depth=1\",\"/var/lib\"]; РЕАЛЬНОЕ хранилище образов k3s чистится "
    "через [\"k3s\",\"crictl\",\"rmi\",\"--prune\"] (обычный crictl бьёт в другой, почти пустой "
    "containerd, толку мало); эфемерные данные подов ищи в "
    "[\"du\",\"-xh\",\"--max-depth=2\",\"/var/lib/kubelet/pods\"] с сортировкой, а крупные каталоги "
    "в [\"du\",\"-xh\",\"--max-depth=2\",\"/var/lib/rancher/k3s\"]. Сначала измерь, потом чисти, "
    "потом перепроверь df. Отвечай только JSON одного вызова."
)

_VALID_TOOLS = {"observe", "act", "node_cmd", "explain", "done"}


def _parse_tool_call(text: str) -> dict | None:
    """Извлекает и валидирует один вызов инструмента из ответа модели (как в solve.py: ищем
    первый JSON-объект, проверяем схему). При мусоре возвращает None, тогда цикл делает фолбэк."""
    m = re.search(r"\{.*\}", str(text or ""), re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except (ValueError, TypeError):
        return None
    if not isinstance(d, dict):
        return None
    tool = d.get("tool")
    if tool not in _VALID_TOOLS:
        return None
    # Проверка обязательных полей по инструменту.
    if tool in ("observe", "act"):
        if not isinstance(d.get("argv"), list) or not d["argv"]:
            return None
        d["argv"] = [str(x) for x in d["argv"]]
    if tool == "node_cmd":
        if not isinstance(d.get("argv"), list) or not d["argv"] or not d.get("node"):
            return None
        d["argv"] = [str(x) for x in d["argv"]]
        d["node"] = str(d["node"])
    if tool == "explain" and not isinstance(d.get("text"), str):
        return None
    if tool == "done" and not isinstance(d.get("summary"), str):
        return None
    return d


def _truncate(text: str) -> str:
    s = str(text or "")
    if len(s) <= _OUTPUT_LIMIT:
        return s
    return s[:_OUTPUT_LIMIT] + "\n… вывод обрезан …"


# ---------------------------------------------------------------------------
# Исполнение отдельных команд (наблюдение и мутация).
# ---------------------------------------------------------------------------


def _run_node_agent(node: str, argv: list, http_post=None) -> dict:
    """Исполняет argv на узле node через node-agent (HTTP POST на podIP:9110, заголовок
    X-NodeAgent-Token). Возвращает результат контракта node-agent либо словарь с ключом error
    при мягкой деградации (нет токена, нет пода, сетевая ошибка). Не бросает исключений наружу,
    чтобы отказ node-agent не ронял весь агентный цикл (ADR-0041, мягкая деградация)."""
    if not NODEAGENT_TOKEN:
        return {"error": "node-agent недоступен: не задан NODEAGENT_TOKEN"}
    endpoint = k8s.get_node_agent_endpoint(node)
    if not endpoint:
        return {"error": f"node-agent на узле «{node}» не найден (панель вне кластера или под отсутствует)"}
    body = {"argv": list(argv), "timeout": NODEAGENT_TIMEOUT}
    headers = {"X-NodeAgent-Token": NODEAGENT_TOKEN}
    try:
        if http_post is not None:
            # Внедрённый транспорт для тестов (без сети).
            resp = http_post(f"{endpoint}/run", body, headers)
        else:
            with httpx.Client(timeout=NODEAGENT_TIMEOUT + 5) as c:
                r = c.post(f"{endpoint}/run", json=body, headers=headers)
                r.raise_for_status()
                resp = r.json()
    except Exception as e:
        return {"error": f"ошибка вызова node-agent узла «{node}»: {e}"}
    if not isinstance(resp, dict):
        return {"error": "node-agent вернул неожиданный ответ"}
    return {
        "exit_code": resp.get("exit_code"),
        "stdout": _truncate(resp.get("stdout", "")),
        "stderr": _truncate(resp.get("stderr", "")),
        "duration_ms": resp.get("duration_ms"),
        "node": resp.get("node", node),
    }


def _run_cluster_read(argv: list) -> dict:
    """Исполняет read-only kubectl-подобную команду через существующий k8s.py, покрывая частые
    формы (get pods, get nodes, get events, logs, describe). Прочее чтение кластера, для которого
    нет прямого метода, честно сообщает об ограничении, а не выдумывает вывод."""
    if _base(argv[0]) not in ("kubectl", "k", "oc") or len(argv) < 2:
        return {"error": "локальное чтение вне узла не поддерживается напрямую, используйте node_cmd"}
    verb = argv[1].lower()
    resource = argv[2].lower() if len(argv) > 2 else ""
    if verb == "get" and resource.startswith("pod"):
        pods = k8s.list_pods()
        return {"data": pods} if pods is not None else {"error": "вне кластера"}
    if verb == "get" and resource.startswith("node"):
        nodes = k8s.list_nodes()
        return {"data": nodes} if nodes is not None else {"error": "вне кластера"}
    if verb == "get" and (resource.startswith("deploy")):
        deps = k8s.list_deployments()
        return {"data": deps} if deps is not None else {"error": "вне кластера"}
    if verb == "get" and resource.startswith("event"):
        evs = k8s.list_events()
        return {"data": evs} if evs is not None else {"error": "вне кластера"}
    if verb == "logs" and len(argv) > 2:
        tail = k8s.pod_log_tail(argv[2], lines=100)
        return {"data": _truncate(tail)} if tail is not None else {"error": "логи недоступны"}
    return {"error": f"команда чтения «{' '.join(argv)}» не имеет прямого метода в панели"}


def _base(binary: str) -> str:
    return os.path.basename(str(binary or "").strip())


def _fingerprint(argv: list, node: str | None = None) -> str:
    """Отпечаток мутации для гардов: узел плюс канонизированная команда. Одинаковые команды дают
    одинаковый отпечаток, поэтому кулдаун и лимит попыток работают по существу действия."""
    return (node or "local") + "|" + " ".join(str(a) for a in argv)


def _guard_service(argv: list) -> str | None:
    """Имя сервиса для кулдауна перезапусков, если команда это rollout restart или delete pod
    конкретного деплоймента или пода. Иначе None."""
    if _base(argv[0]) not in ("kubectl", "k", "oc"):
        return None
    joined = " ".join(argv)
    m = re.search(r"(?:deployment|deploy)[/ ]([a-z0-9-]+)", joined)
    if m:
        return m.group(1)
    return None


def _guard_action(cls: str, argv: list) -> str:
    """Имя действия для гардов. Совпадение с именами из autopilot (restart, delete_pod) даёт
    учёт кулдауна сервиса; прочие мутации проходят как generic-действие класса."""
    joined = " ".join(argv)
    if "rollout" in joined and "restart" in joined:
        return "restart"
    if "delete" in joined and re.search(r"\bpo(d|ds)?\b", joined):
        return "delete_pod"
    return cls


# ---------------------------------------------------------------------------
# Обработка одного вызова инструмента.
# ---------------------------------------------------------------------------


def _handle_observe(call: dict, http_post=None) -> dict:
    """observe: классификатор обязан подтвердить read, иначе шаг трактуется как act. Read не
    считается в бюджет гардов и исполняется сразу."""
    argv = call["argv"]
    cls = policy.classify(argv)
    if cls != policy.READ:
        # Модель назвала observe, но команда мутирующая: перенаправляем в act (fail-safe).
        return _handle_act({"argv": argv, "target": call.get("target", "cluster"),
                            "why": "команда, названная наблюдением, оказалась мутирующей"},
                           http_post=http_post)
    target = call.get("target", "cluster")
    if target in ("control", "gpu") or _base(argv[0]) not in ("kubectl", "k", "oc"):
        # Узловое или локальное чтение идёт через node-agent (если задан узел через target).
        node = target if target in ("control", "gpu") else "control"
        res = _run_node_agent(node, argv, http_post=http_post)
    else:
        res = _run_cluster_read(argv)
    return {"step": "observe", "argv": argv, "class": cls, "counts_budget": False,
            "target": target, "result": res}


def _handle_act(call: dict, operator: str = "agent", http_post=None,
                node: str | None = None) -> dict:
    """act и node_cmd: классификация и политика по режиму. Возвращает структуру шага. Мутация
    проходит через guards ПЕРЕД исполнением; finance и destructive в auto уходят в отложенное
    подтверждение; в manual любая мутация возвращается предложением."""
    argv = call["argv"]
    why = call.get("why", "")
    cls = policy.classify(argv)
    mode = get_mode()

    step = {"step": "node_cmd" if node else "act", "argv": argv, "class": cls,
            "class_ru": policy.describe(cls), "why": why, "counts_budget": True,
            "node": node, "target": call.get("target")}

    # Read, ошибочно пришедшее в act: исполняем как наблюдение, в бюджет не считаем.
    if cls == policy.READ:
        step["counts_budget"] = False
        if node:
            step["result"] = _run_node_agent(node, argv, http_post=http_post)
        else:
            step["result"] = _run_cluster_read(argv)
        return step

    # finance и destructive: подтверждение обязательно В ЛЮБОМ режиме. Не исполняем автономно.
    if policy.requires_confirmation(cls):
        token = _stage_pending(argv, cls, node, why, operator)
        step["outcome"] = "pending_confirm"
        step["confirm_token"] = token
        step["message"] = (f"Требуется подтверждение оператора: {policy.describe(cls)}. "
                           f"Команда: {' '.join(argv)}. Подтвердите через /agent/confirm.")
        return step

    # safe_write. В manual-режиме не исполняем сами, а предлагаем оператору.
    if mode == "manual":
        token = _stage_pending(argv, cls, node, why, operator)
        step["outcome"] = "proposed"
        step["confirm_token"] = token
        step["message"] = (f"Ручной режим: предлагаю мутацию (ремонт). Команда: {' '.join(argv)}. "
                           f"Подтвердите через /agent/confirm или введите свою команду.")
        return step

    # auto-режим, safe_write: исполняем через гарды.
    return _execute_mutation(argv, cls, node, why, operator, http_post=http_post, step=step)


def _stage_pending(argv, cls, node, why, operator) -> str:
    """Кладёт мутацию в PENDING с одноразовым токеном и TTL. Возвращает токен."""
    token = secrets.token_hex(8)
    PENDING[token] = {"argv": list(argv), "class": cls, "node": node, "why": why,
                      "operator": operator, "ts": time.time()}
    return token


def _execute_mutation(argv, cls, node, why, operator, http_post=None, step=None) -> dict:
    """Исполняет мутацию через гарды и аудит. Гарды вызываются ПЕРЕД исполнением: при отказе
    команда не исполняется, шаг помечается blocked. Каждое исполнение пишется в audit.py."""
    if step is None:
        step = {"step": "node_cmd" if node else "act", "argv": argv, "class": cls,
                "class_ru": policy.describe(cls), "why": why, "node": node, "counts_budget": True}
    fp = _fingerprint(argv, node)
    action = _guard_action(cls, argv)
    service = _guard_service(argv)
    allowed, reason = guards.check(fp, action, service=service)
    if not allowed:
        step["outcome"] = "blocked"
        step["message"] = f"Гард запретил действие: {reason}"
        audit_write(operator, "agent.act", {"argv": argv, "class": cls, "node": node},
                    node or "cluster", confirmed=False, result=f"заблокировано гардом: {reason}")
        return step

    # Регистрируем попытку (бюджет часа, кулдаун сервиса) ДО исполнения.
    guards.record_attempt(fp, action, service=service)
    if node:
        res = _run_node_agent(node, argv, http_post=http_post)
        ok = isinstance(res, dict) and res.get("error") is None and (res.get("exit_code") in (0, None))
    else:
        res = _run_cluster_mutation(argv)
        ok = isinstance(res, dict) and res.get("ok") is True
    guards.record_result(fp, bool(ok))
    step["outcome"] = "executed" if ok else "failed"
    step["result"] = res
    audit_write(operator, "agent.act", {"argv": argv, "class": cls, "node": node},
                node or "cluster", confirmed=(operator != "agent"),
                result=("успех" if ok else "неудача") + f": {_truncate(json.dumps(res, ensure_ascii=False))[:400]}")
    return step


def _run_cluster_mutation(argv: list) -> dict:
    """Исполняет ремонтную мутацию в кластере через существующий k8s.py (rollout restart и
    delete pod покрыты прямыми методами с их allowlist и denylist). Прочее честно сообщает об
    ограничении, а не выдумывает исполнение."""
    if _base(argv[0]) not in ("kubectl", "k", "oc"):
        return {"ok": False, "error": "локальная мутация вне узла не поддерживается, используйте node_cmd"}
    joined = " ".join(argv)
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if "rollout" in joined and "restart" in joined:
        m = re.search(r"(?:deployment|deploy)[/ ]([a-z0-9-]+)", joined)
        if m:
            ok, detail = k8s.rollout_restart(m.group(1), now_iso)
            return {"ok": bool(ok), "detail": detail}
        return {"ok": False, "error": "не распознан деплоймент для rollout restart"}
    if "delete" in joined:
        m = re.search(r"(?:pod|po)[/ ]([a-z0-9-]+)", joined)
        if m:
            ok, detail = k8s.delete_pod(m.group(1))
            return {"ok": bool(ok), "detail": detail}
        return {"ok": False, "error": "не распознан под для delete pod"}
    return {"ok": False, "error": f"мутация «{joined}» не имеет прямого метода в панели"}


# ---------------------------------------------------------------------------
# Подтверждение отложенных команд.
# ---------------------------------------------------------------------------


def confirm(token: str, operator: str, http_post=None) -> dict:
    """Подтверждает и исполняет ранее отложенную finance, destructive или (в manual) safe_write
    команду. Токен одноразовый, с TTL. Исполнение идёт через те же гарды и аудит."""
    p = PENDING.pop(token, None)
    if not p:
        return {"ok": False, "message": "Подтверждение недействительно или уже использовано."}
    if time.time() - p["ts"] > PENDING_TTL_SECONDS:
        return {"ok": False, "message": "Подтверждение истекло, повторите команду."}
    step = _execute_mutation(p["argv"], p["class"], p.get("node"), p.get("why", ""),
                             operator, http_post=http_post)
    step["confirmed_by"] = operator
    ok = step.get("outcome") == "executed"
    return {"ok": ok, "step": step,
            "message": (f"Подтверждено оператором «{operator}». "
                       f"Результат: {step.get('outcome')}." )}


# ---------------------------------------------------------------------------
# Агентный цикл и фолбэк без модели.
# ---------------------------------------------------------------------------


def _fallback_single_command(message: str, operator: str, http_post=None) -> dict:
    """Фолбэк без языковой модели: трактует инструкцию оператора как ОДНУ команду (строку
    оболочки), безопасно разбирает её в argv (shlex, без исполнения оболочки), классифицирует и
    исполняет либо предлагает по политике. Планирования нет."""
    try:
        argv = shlex.split(message.strip())
    except ValueError:
        argv = message.strip().split()
    if not argv:
        return {"steps": [], "mode": get_mode(), "model": False,
                "message": "Пустая команда."}
    # Если первый токен это read-only или явная команда, классифицируем и исполняем как act/observe.
    cls = policy.classify(argv)
    if cls == policy.READ:
        step = _handle_observe({"argv": argv, "target": "cluster"}, http_post=http_post)
    else:
        step = _handle_act({"argv": argv, "target": "cluster", "why": "прямая команда оператора"},
                           operator=operator, http_post=http_post)
    return {"steps": [step], "mode": get_mode(), "model": False,
            "message": "Модель недоступна: исполнена одна команда оператора без планирования."}


def _step_feedback(step) -> str:
    """Строка обратной связи модели по шагу. Предпочитаем ФАКТИЧЕСКИЙ результат команды (вывод
    node-agent или кластера с stdout и кодом возврата), иначе сообщение, иначе исход. Без подачи
    результата модель не видит вывод df, du, docker и решает, что команда вернула None, и мечется
    с повторами. Read-команды исхода (outcome) не имеют, поэтому опора именно на result."""
    if step.get("result") is not None:
        return _truncate(json.dumps(step["result"], ensure_ascii=False))[:800]
    if step.get("message"):
        return f"{step.get('outcome') or 'нет исхода'}: {step['message']}"
    return str(step.get("outcome") or "нет данных")


def run(message: str, operator: str, llm_complete=None, http_post=None,
        max_steps: int | None = None) -> dict:
    """Запускает агентный цикл над инструкцией оператора. Возвращает полный трейс шагов, чтобы
    панель могла отобразить или сэмулировать стрим. Без модели уходит в фолбэк одной команды.

    llm_complete это функция prompt даёт text (переиспользуй commands._llm_complete). http_post
    это внедряемый транспорт node-agent для тестов; в проде None (реальный httpx)."""
    if llm_complete is None:
        return _fallback_single_command(message, operator, http_post=http_post)

    max_steps = AGENT_MAX_STEPS if max_steps is None else max_steps
    steps: list = []
    transcript = f"Инструкция оператора: {message}\n"
    mutations_used = 0
    seen_cmds: dict = {}  # сигнатура команды в этом запуске -> сколько раз вызвана (анти-цикл)

    for _ in range(max_steps * 3):  # запас итераций: observe не тратит бюджет шагов
        if mutations_used >= max_steps:
            steps.append({"step": "explain", "text": "Достигнут предел шагов агента, останавливаюсь."})
            break
        prompt = SYSTEM + "\n\n" + transcript + "\nJSON:"
        try:
            text = llm_complete(prompt)
        except Exception as e:
            steps.append({"step": "error", "text": f"Модель недоступна на шаге: {e}"})
            break
        call = _parse_tool_call(text)
        if call is None:
            # Мусор от модели: фолбэк, завершаем честной ошибкой шага, не зацикливаемся.
            steps.append({"step": "error", "text": "Модель вернула не разобранный JSON, останавливаюсь.",
                          "raw": _truncate(text)})
            break
        tool = call["tool"]

        # Анти-цикл в пределах запуска: одну и ту же команду не гоняем более двух раз, даже если
        # модель настаивает. Защищает от залипания, когда модель повторяет действие вместо разбора
        # уже полученного результата.
        if tool in ("observe", "act", "node_cmd"):
            sig = (tool, json.dumps(call.get("argv"), ensure_ascii=False, sort_keys=True), call.get("node"))
            seen_cmds[sig] = seen_cmds.get(sig, 0) + 1
            if seen_cmds[sig] >= 3:
                steps.append({"step": "explain",
                              "text": "Останавливаюсь: команда повторяется без нового результата, "
                                      "нужен другой подход или внимание оператора."})
                break

        if tool == "done":
            steps.append({"step": "done", "summary": call.get("summary", "")})
            break
        if tool == "explain":
            step = {"step": "explain", "text": call.get("text", "")}
            steps.append(step)
            transcript += f"[explain] {step['text']}\n"
            continue
        if tool == "observe":
            step = _handle_observe(call, http_post=http_post)
            steps.append(step)
            transcript += f"[observe] {' '.join(call['argv'])} -> {_truncate(json.dumps(step['result'], ensure_ascii=False))[:600]}\n"
            continue
        if tool == "act":
            step = _handle_act(call, operator="agent", http_post=http_post)
            steps.append(step)
            if step.get("counts_budget"):
                mutations_used += 1
            transcript += f"[act] {' '.join(call['argv'])} -> {_step_feedback(step)}\n"
            continue
        if tool == "node_cmd":
            step = _handle_act({"argv": call["argv"], "why": call.get("why", ""),
                                "target": call["node"]},
                               operator="agent", http_post=http_post, node=call["node"])
            steps.append(step)
            if step.get("counts_budget"):
                mutations_used += 1
            transcript += f"[node_cmd {call['node']}] {' '.join(call['argv'])} -> {_step_feedback(step)}\n"
            continue

    return {"steps": steps, "mode": get_mode(), "model": True, "message": "Агентный цикл завершён."}


# ---------------------------------------------------------------------------
# Расследование инцидента агентом (ADR-0041, разделы 3, 7). Инцидент больше не
# сваливается на оператора текстом-отпиской «проверьте вручную»: его факты
# передаются агентному циклу, чтобы агент сам пошёл за логами (kubectl logs, du,
# df, docker system df через observe и node_cmd), поставил диагноз и в auto-режиме
# выполнил безопасный ремонт (safe_write). Гарды (бюджет, кулдаун, предохранитель,
# осцилляция) остаются на месте: они вызываются внутри _handle_act перед каждой
# мутацией, поэтому расследование не может обойти ограничители.
# ---------------------------------------------------------------------------

# Узел для узловых команд диагноза по умолчанию. Диск, du и docker system df имеют
# смысл на конкретном хосте, поэтому агенту подсказывается имя GPU-узла из окружения.
GPU_NODE = os.getenv("ADMINCHAT_GPU_NODE", "gooseek")


def _incident_brief(verdict: dict) -> str:
    """Короткая сводка фактов инцидента для инструкции агенту: статус, первопричина,
    сработавшие детекторы, узел, сервис или под, ключевые параметры. Числа сохраняются,
    чтобы агент видел процент заполнения диска и имена ресурсов."""
    v = verdict or {}
    params = v.get("params") or {}
    parts = []
    if v.get("root_cause"):
        parts.append(f"Первопричина: {v['root_cause']}.")
    if v.get("status"):
        parts.append(f"Статус: {v['status']}.")
    dets = v.get("detectors") or []
    if dets:
        parts.append("Детекторы: " + ", ".join(str(d) for d in dets) + ".")
    for key, ru in (("service", "сервис"), ("pod", "под"), ("node", "узел"),
                    ("fs", "том"), ("store", "хранилище"), ("percent", "заполнение, %"),
                    ("used_percent", "заполнение, %"), ("culprit", "виновник")):
        if params.get(key) not in (None, ""):
            parts.append(f"{ru}: {params[key]}.")
    if v.get("action"):
        parts.append(f"Рекомендация RCA: {v['action']}.")
    return " ".join(parts) or "Факты инцидента не классифицированы."


def _incident_instruction(verdict: dict) -> str:
    """Строит инструкцию оператора для агентного цикла из фактов инцидента. Инструкция
    на русском задаёт агенту порядок: собрать факты наблюдением (df, du, docker system df,
    kubectl logs), объяснить диагноз, выполнить безопасный ремонт в auto-режиме, проверить
    результат. Опасное (destructive, finance) агент лишь предложит на подтверждение."""
    brief = _incident_brief(verdict)
    return (
        f"Расследуй инцидент и по возможности устрани его. {brief} "
        f"Сначала собери факты наблюдением: на затронутом узле (например «{GPU_NODE}» или "
        "«control») выполни df и du по подозрительным путям и docker system df, а в кластере "
        "посмотри логи виновного пода (kubectl logs). Объясни оператору по-русски, что именно "
        "не так. Затем, если это безопасный ремонт (освобождение места очисткой docker system "
        "prune и crictl rmi --prune, перезапуск сервиса, возврат заданий в очередь), выполни "
        "его. Если требуется необратимое действие или деньги тенанта, не выполняй сам: собери "
        "факты и предложи конкретную команду на подтверждение. После ремонта проверь результат "
        "наблюдением и заверши."
    )


def investigate(verdict: dict, operator: str = "agent", llm_complete=None,
                http_post=None, max_steps: int | None = None) -> dict:
    """Запускает агентный цикл над фактами инцидента (расследование плюс ремонт). Возвращает
    тот же трейс шагов, что и run, плюс поле instruction (что именно поручено агенту). Без
    модели уходит в тот же фолбэк run: агент честно сообщает, что планирование недоступно, но
    хотя бы исполняет собранную рекомендацию как одну команду, если она распознаётся. Гарды
    остаются активными: расследование не может их обойти."""
    instruction = _incident_instruction(verdict)
    result = run(instruction, operator, llm_complete=llm_complete, http_post=http_post,
                 max_steps=max_steps)
    result["instruction"] = instruction
    return result


def state_summary() -> dict:
    """Состояние агента для GET /agent/state: режим, гарды (бюджет, кулдауны, предохранитель),
    число отложенных подтверждений."""
    g = guards.state_summary()
    return {
        "mode": get_mode(),
        "guards": g,
        "pending_confirmations": len(PENDING),
    }
