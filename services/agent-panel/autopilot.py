"""Автономный агент-девопс панели (ADR-0038, этап 3): цикл «наблюдение, диагноз,
действие, проверка» с тактом AGENT_TICK_SECONDS. Модуль называется autopilot, потому что
имя agent занято интерпретатором естественного языка (agent.py).

Разделение ответственности по ADR-0032: факты и пороги считает детерминированный каталог
алертов (alerts.py), ограничители исполняет детерминированный код (guards.py), а языковая
модель лишь выбирает вариант плейбука строго из разрешённого множества (по образцу
solve.py); её ответ проверяется схемой, а гарды проверяются ПОСЛЕ выбора, поэтому модель
физически не может их обойти.

Режимы:
  AGENT_AUTONOMOUS=0 (по умолчанию): сухой прогон, агент пишет в ленту инцидентов и в
  аудит «что бы сделал», но не действует. AGENT_AUTONOMOUS=1: действия уровня A исполняются.
  Команды /agent pause и /agent resume приостанавливают ТОЛЬКО действия: наблюдение,
  диагноз и эскалации работают всегда.

Проверка результата: через VERIFY_DELAY секунд после действия агент повторяет диагностику
того же алерта. Исчезновение алерта помечает группу resolved_auto (actor=agent, действие
указано); сохранение считается неудачей в guards, а исчерпание попыток переводит группу
в escalated с историей.
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone

import alerts
import guards
import incidents
import k8s
import llm
import rca_client
import app_adapter
from audit import audit_write

TICK_SECONDS = int(os.getenv("AGENT_TICK_SECONDS", "30"))
VERIFY_DELAY = int(os.getenv("AGENT_VERIFY_DELAY", os.getenv("VERIFY_DELAY", "180")))
AUTONOMOUS = os.getenv("AGENT_AUTONOMOUS", "0") == "1"

# Пауза действий командой /agent pause (наблюдение работает всегда).
_paused = False
# Отложенные проверки результата: списки словарей {fp, code, gid, action, service, due}.
_pending_verify: list = []
# Группы, по которым сухой прогон уже записан (чтобы не спамить каждую итерацию).
_dry_noted: set = set()
# Группы, по которым эскалация уже записана в этой жизни группы.
_escalated_noted: set = set()

ACTOR = "agent"


# ---------------------------------------------------------------------------
# Плейбуки уровней A и B. Значение: детерминированный список вариантов действий по
# порядку попыток; пустой список означает «только эскалация». Каждый вариант:
# {"action": ..., "service"/"pod": ...}. Действия уровня B (этап 4) исполняются
# автономно, но СРАЗУ порождают уведомление оператора (не молча), и проходят через
# те же гарды, что и уровень A.
# ---------------------------------------------------------------------------

# Действия уровня B (ADR-0038, раздел 2.3): автономно, но с немедленным уведомлением
# оператора. Проверяются теми же гардами (бюджет, кулдауны), пишутся в аудит actor=agent.
LEVEL_B_ACTIONS = {"cleanup_temp", "intake_pause", "lower_concurrency"}


def is_level_b(action: str) -> bool:
    return action in LEVEL_B_ACTIONS


# ---------------------------------------------------------------------------
# Порог регистрации инцидентов (ADR-0041, раздел 7). Поднят, чтобы лента не тонула
# в шуме от общего анализа логов. Детекторы, подтверждающие недоступность или сетевой
# сбой (постгрес и прочая сеть): их появление регистрирует инцидент даже при средней
# уверенности, потому что это не «шумовой» вывод, а подтверждённый факт.
# ---------------------------------------------------------------------------

# Детекторы подтверждённого сетевого сбоя (connection_refused, dns_error) в RCA. D5 это
# network_failure: он покрывает недоступность postgres и прочих зависимостей по сети.
_CONFIRMED_DETECTORS = {"D5"}


def _register_verdict(verdict: dict) -> bool:
    """Заносить ли вердикт RCA инцидентом (ADR-0041, раздел 7). Поднятый порог: инцидент
    регистрируется ТОЛЬКО при band=high ИЛИ при подтверждённом детекторе застревания, сети
    или postgres (D5). При band=uncertain на общем анализе логов инцидент НЕ заносится,
    чтобы нормальные состояния и слабые сигналы не захлёбывали ленту. Застрявшие приходят
    отдельным вердиктом (stuck_verdict) и проходят по своему пути."""
    if not verdict:
        return False
    if verdict.get("band") == "high":
        return True
    dets = set(verdict.get("detectors") or [])
    return bool(dets & _CONFIRMED_DETECTORS)


def playbook_options(alert: dict) -> list:
    """Разрешённое множество действий для алерта. Всё, что вне списка, недоступно
    ни модели, ни коду."""
    code = alert.get("code")
    params = alert.get("params") or {}
    if code == "A2":
        # Сначала возврат застрявших в очередь, затем перезапуск воркера. Воркер в
        # allowlist (безсостоятельный, очередь в Postgres переживает рестарт); если его
        # когда-нибудь уберут из allowlist, второй шаг сам выпадет из вариантов.
        opts = [{"action": "requeue"}]
        if "worker" in k8s.ALLOWED:
            opts.append({"action": "restart", "service": "worker"})
        return opts
    if code == "A3":
        # Уровень B: при заполнении диска чистим временные файлы воркера (b2); при
        # критическом заполнении дополнительно ставим паузу приёма (b1), чтобы очередь
        # не разбухала. Для томов Loki, медиа и Postgres автономных действий нет: их
        # разбирает эскалация (escalation_hint). Очистка имеет смысл на узле управления.
        opts = [{"action": "cleanup_temp"}]
        if params.get("crit"):
            opts.append({"action": "intake_pause"})
        return opts
    if code == "A4":
        svc = params.get("service") or ""
        if svc in k8s.ALLOWED and svc not in k8s.DENY and params.get("pod"):
            return [{"action": "delete_pod", "pod": params["pod"], "service": svc}]
        return []  # denylist (vllm, postgres): карточка уровня C у оператора
    if code == "A5":
        culprit = params.get("culprit")
        if culprit and culprit in k8s.ALLOWED and culprit not in k8s.DENY:
            return [{"action": "restart", "service": culprit}]
        return []  # первопричина в хранилище или неясна: немедленная эскалация
    if code == "A6":
        # Латентность распознавания: если растёт с ростом параллелизма, снижаем
        # параллелизм воркера (уровень B); если без роста нагрузки, разовый перезапуск
        # asr (уровень A); иначе эскалация.
        if params.get("load_high"):
            return [{"action": "lower_concurrency"}]
        if "asr" in k8s.ALLOWED and "asr" not in k8s.DENY:
            return [{"action": "restart", "service": "asr"}]
        return []
    # A1, A7, A8 (разбирается отдельно ниже как уровень A), A9, A10, A11, A12 и прочее:
    # автономного плейбука нет либо он специфичен, см. detect и escalation_hint.
    if code == "A8":
        svc = params.get("service") or ""
        if svc in k8s.ALLOWED and svc not in k8s.DENY:
            return [{"action": "restart", "service": svc}]
        return []  # вне allowlist: эскалация
    return []


def escalation_hint(alert: dict) -> str:
    """Направление расследования для агента при эскалации (ADR-0041). Раньше это была
    подсказка оператору «сделайте руками»; теперь автономного плейбука уровня A нет, но
    инцидент передаётся агентному циклу (см. _escalate), поэтому текст описывает, КУДА
    агенту смотреть и ЧТО он попробует, а не сваливает работу на человека. Опасное
    (деньги тенанта, необратимое) агент лишь предложит на подтверждение."""
    code = alert.get("code")
    params = alert.get("params") or {}
    if code == "A1":
        return ("Домашний сервер за туннелем панель не поднимет удалённо. Диагноз: "
                + str(params.get("diagnosis") or "см. карточку") + ". Агент проверит "
                "состояние узла и туннеля WireGuard наблюдением и приложит факты; питание "
                "и физический доступ вне контура панели.")
    if code == "A3":
        fs = str(params.get("fs") or "том")
        return (f"Диск ({fs}) заполнен. Агент сам смотрит, чем именно забито (df, du, docker "
                "system df на узле), и освобождает место безопасным ремонтом (docker system "
                "prune, crictl rmi --prune, очистка кешей и временных путей). Тома медиа и "
                "Postgres содержат клиентские данные: их агент не трогает автономно, а "
                "предложит расширение тома на подтверждение с оценкой запаса места.")
    if code == "A6":
        return ("Латентность распознавания выше порога. Агент смотрит память GPU-узла и число "
                "параллельных заданий наблюдением, снижает параллелизм или перезапускает asr.")
    if code == "A8":
        svc = params.get("service") or "сервис"
        return (f"Сервис {svc} молчит (под Running, логов нет). Агент снимет логи пода "
                "(kubectl logs) и опишет причину; перезапуск вне allowlist он предложит на "
                "подтверждение, а не выполнит молча.")
    if code == "A9":
        return ("Живой режим у потолка занятости. Потолок железный: агент приложит факты "
                "загрузки, но расширение мощности это закупка железа, решает человек.")
    if code == "A10":
        return ("Сертификат TLS истекает. Агент проверит, жив ли механизм продления "
                "(cert-manager), наблюдением; принудительное продление он предложит на "
                "подтверждение.")
    if code == "A11":
        p = params or {}
        return (f"Почта не уходит (stalwart в denylist). Сетевых ошибок {p.get('network_errors', 0)}, "
                f"отказов получателей {p.get('recipient_errors', 0)}. Агент снимет логи stalwart и "
                "разделит проблему релея и туннеля от проблемы адресатов; перезапуск stalwart "
                "предложит на подтверждение.")
    if code == "A12":
        return ("Ошибки в биллинговых путях. Агент соберёт логи api и события и опишет, что "
                "именно ломается; любое вмешательство в биллинг он лишь предложит на "
                "подтверждение (это класс finance), а не выполнит сам.")
    if code == "A7":
        store = params.get("store") or "хранилище"
        return (f"Хранилище {store} в denylist панели. Агент снимет его логи и фазу пода "
                f"наблюдением и опишет причину; перезапуск деплоймента {store} он предложит на "
                "подтверждение, потому что это особый под с данными.")
    if code == "A4":
        return ("Сервис вне allowlist либо повторный сбой. Агент снимет логи пода и опишет "
                "причину сбоя; перезапуск вне allowlist предложит на подтверждение.")
    if code == "A5":
        return ("Первопричина вне allowlist или неясна. Агент соберёт факты по вердикту RCA "
                "и логам виновного сервиса и опишет диагноз с предложением ремонта.")
    if code == "A2":
        return ("Очередь стоит после requeue и перезапуска воркера. Агент снимет логи воркера "
                "и застрявших заданий и опишет, что мешает продвижению очереди.")
    return "Агент расследует инцидент и приложит собранные факты с предложением ремонта."


# ---------------------------------------------------------------------------
# Выбор действия: языковая модель выбирает вариант из разрешённого множества,
# фолбэк без модели детерминированный (вариант по номеру попытки).
# ---------------------------------------------------------------------------

_SYSTEM = (
    "Ты дежурный инженер платформы KROKKI. Дан алерт (JSON) и НУМЕРОВАННЫЙ список "
    "разрешённых действий. Выбери ровно одно действие и верни СТРОГО один JSON вида "
    '{"choice": N} без текста вокруг, где N это номер действия из списка. '
    "Действий вне списка не существует."
)


def choose_action(alert: dict, attempt: int, llm_complete=None) -> dict | None:
    """Выбирает действие плейбука для попытки attempt (нумерация с нуля). None означает
    «действий не осталось, эскалация». Ответ модели проверяется по разрешённому множеству;
    без модели или при невалидном ответе действует детерминированный фолбэк: варианты
    плейбука идут по порядку попыток."""
    options = playbook_options(alert)
    if attempt >= len(options):
        return None
    fallback = options[attempt]
    if llm_complete is None or len(options) == 1:
        return fallback
    prompt = (_SYSTEM + "\n\nАлерт: " + json.dumps(
        {"code": alert.get("code"), "title": alert.get("title"),
         "params": alert.get("params")}, ensure_ascii=False)[:1200]
        + "\nДействия: " + json.dumps(list(enumerate(options)), ensure_ascii=False)
        + "\nJSON:")
    try:
        text = llm_complete(prompt)
    except Exception:
        return fallback
    m = re.search(r"\{.*\}", str(text or ""), re.S)
    if not m:
        return fallback
    try:
        d = json.loads(m.group(0))
        i = int(d.get("choice"))
    except (ValueError, TypeError):
        return fallback
    # Жёсткая схема: только номер из разрешённого множества, иначе фолбэк.
    if 0 <= i < len(options):
        return options[i]
    return fallback


# ---------------------------------------------------------------------------
# Исполнение действий уровня A. Ввод-вывод собран здесь, чтобы тесты подменяли
# одну функцию _execute_action.
# ---------------------------------------------------------------------------


def _execute_action(decision: dict, rca_url: str) -> tuple:
    """Исполняет выбранное действие. Возвращает (ok, detail)."""
    action = decision.get("action")
    if action == "requeue":
        try:
            sv = rca_client.stuck(rca_url)
        except Exception as e:
            return False, f"не удалось получить список застрявших: {e}"
        ids = [str(e["source"]).split("job:", 1)[1] for e in (sv.get("evidence") or [])
               if str(e.get("source", "")).startswith("job:")]
        if not ids:
            return False, "идентификаторы застрявших заданий не найдены"
        ok_n = 0
        for jid in ids:
            ok, _d = app_adapter.admin_post("/api/admin/requeue", {"job_id": jid}, ACTOR)
            if ok:
                ok_n += 1
        return ok_n > 0, f"вернул в очередь {ok_n} из {len(ids)} заданий"
    if action == "restart":
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ok, detail = k8s.rollout_restart(decision.get("service", ""), now_iso)
        return ok is True, detail
    if action == "delete_pod":
        ok, detail = k8s.delete_pod(decision.get("pod", ""))
        return ok is True, detail
    # Действия уровня B (этап 4): тонкие вызовы новых административных эндпоинтов api.
    if action == "cleanup_temp":
        ok, detail = app_adapter.admin_post("/api/admin/worker/cleanup-temp", {}, ACTOR)
        return ok is True, ("очистка временных файлов воркера выполнена"
                            if ok else f"очистка не выполнена: {detail}")
    if action == "intake_pause":
        ok, detail = app_adapter.admin_post("/api/admin/intake/pause", {}, ACTOR)
        return ok is True, ("приём новых тяжёлых заданий приостановлен"
                            if ok else f"пауза приёма не выполнена: {detail}")
    if action == "lower_concurrency":
        # Снижение до 1 (безопасная нижняя граница): восстановление штатного параллелизма
        # выполняет либо оператор через эндпоинт /api/admin/worker/concurrency с limit=0,
        # либо сам агент, когда латентность вернётся в норму.
        ok, detail = app_adapter.admin_post("/api/admin/worker/concurrency",
                                          {"limit": 1}, ACTOR)
        return ok is True, ("параллелизм воркера снижен до 1"
                            if ok else f"снижение параллелизма не выполнено: {detail}")
    return False, f"неизвестное действие {action}"


def _describe(decision: dict) -> str:
    a = decision.get("action")
    if a == "requeue":
        return "вернуть застрявшие задания в очередь (requeue)"
    if a == "restart":
        return f"перезапустить сервис {decision.get('service')}"
    if a == "delete_pod":
        return f"удалить больной под {decision.get('pod')} (контроллер пересоздаст)"
    if a == "cleanup_temp":
        return "очистить временные файлы воркера (уровень B)"
    if a == "intake_pause":
        return "приостановить приём новых тяжёлых заданий (уровень B)"
    if a == "lower_concurrency":
        return "снизить параллелизм воркера до 1 (уровень B)"
    return str(a)


def _trace_summary(trace: dict) -> str:
    """Сжимает трейс агентного расследования в человекочитаемую заметку для ленты
    инцидента: последнее объяснение или итог агента, число выполненных мутаций и число
    предложенных на подтверждение опасных команд. Полный трейс уходит в аудит."""
    steps = (trace or {}).get("steps") or []
    explains = [s.get("text", "") for s in steps if s.get("step") == "explain" and s.get("text")]
    done = [s.get("summary", "") for s in steps if s.get("step") == "done" and s.get("summary")]
    executed = sum(1 for s in steps if s.get("outcome") == "executed")
    pending = [s for s in steps if s.get("outcome") in ("pending_confirm", "proposed")]
    diagnosis = done[-1] if done else (explains[-1] if explains else "")
    tail = []
    if diagnosis:
        tail.append(f"Диагноз агента: {diagnosis}")
    if executed:
        tail.append(f"выполнено безопасных действий: {executed}")
    if pending:
        cmds = "; ".join(" ".join(s.get("argv") or []) for s in pending if s.get("argv"))
        tail.append(f"на подтверждение предложено ({len(pending)}): {cmds}")
    if not tail:
        tail.append("агент собрал факты, но не смог предложить действие")
    return ". ".join(tail) + "."


def _run_investigation(gid: str, alert: dict) -> dict | None:
    """Запускает агентное расследование инцидента над его вердиктом (ADR-0041). Собирает
    факты через observe и node_cmd, ставит диагноз и в auto-режиме выполняет безопасный
    ремонт; опасное предлагает на подтверждение. Гарды остаются активными внутри
    agent_exec. Возвращает трейс шагов либо None при любой ошибке (расследование не роняет
    такт агента). Инъекция agent_exec ленивая, чтобы избежать цикла импорта."""
    import agent_exec
    verdict = dict(alert.get("verdict") or {})
    # Если в такте есть готовый вердикт из фактов, используем его; иначе синтезируем из
    # полей алерта, чтобы у агента были и первопричина, и параметры (узел, том, процент).
    if not verdict:
        verdict = {"root_cause": alert.get("title") or alert.get("code"),
                   "detectors": [alert.get("code")], "status": "incident",
                   "params": alert.get("params") or {}}
    try:
        return agent_exec.investigate(verdict, operator=ACTOR,
                                      llm_complete=llm.complete)
    except Exception:
        return None


def _escalate(gid: str, alert: dict, reason: str) -> None:
    """Инцидент без автономного плейбука уровня A больше не сваливается на оператора текстом
    «проверьте вручную»: он передаётся агентному циклу (agent_exec.investigate), чтобы агент
    сам пошёл за логами (kubectl logs, du, df, docker system df), поставил диагноз и в
    auto-режиме выполнил безопасный ремонт. Если агент реально не может (нужен destructive
    или finance), он оставляет КОНКРЕТНЫЙ вывод с собранными фактами и предложенной командой
    на подтверждение. Гарды остаются активными внутри agent_exec. Пишется один раз на группу."""
    g = incidents.get_group(gid)
    if not g or g.get("lifecycle") == "escalated" or gid in _escalated_noted:
        return
    _escalated_noted.add(gid)
    incidents.set_lifecycle(gid, "escalated", by=ACTOR)
    # Направление расследования (куда смотреть и что агент попробует), затем сам запуск.
    hint = escalation_hint(alert)
    incidents.add_note(gid, ACTOR, f"Эскалация [{alert.get('code')}]: {reason} {hint}")
    trace = _run_investigation(gid, alert)
    if trace is not None:
        incidents.add_note(gid, ACTOR,
                           f"Расследование агента [{alert.get('code')}]: {_trace_summary(trace)}")
        audit_write(ACTOR, f"agent:investigate:{alert.get('code')}",
                    {"instruction": trace.get("instruction"),
                     "steps": len(trace.get("steps") or [])},
                    gid, confirmed=False, result="investigated")
    audit_write(ACTOR, f"agent:escalate:{alert.get('code')}", alert.get("params") or {},
                gid, confirmed=False, result=reason)


# ---------------------------------------------------------------------------
# Наблюдение и такт.
# ---------------------------------------------------------------------------


def observe(rca_url: str) -> dict:
    """Собирает факты для диагноза (раздел 2.1): кластер, kubelet, конвейер, RCA."""
    nodes = k8s.list_nodes()
    facts = {
        "nodes": nodes,
        "pods": k8s.list_pods(),
        "stats_by_node": app_adapter.stats_by_node(nodes),
        "overview": app_adapter.admin_get("/api/admin/overview"),
        "gpu_node": app_adapter.GPU_NODE,
        "now": datetime.now(timezone.utc),
        "rca_verdict": None,
        "rca_facts": None,
        "stuck_verdict": None,
        "tls_days": None,
    }
    try:
        out = rca_client.analyze(rca_url, {"minutes": 15, "use_baseline": False,
                                              "formulate": True})
        facts["rca_verdict"] = rca_client.verdict_payload(out)
        # Посчитанные факты окна логов нужны детекторам A6, A8, A11, A12 (латентность,
        # молчание сервиса, ошибки почты и биллинга): один запрос, оба применения.
        facts["rca_facts"] = out.get("facts") or {}
    except Exception:
        pass
    try:
        facts["stuck_verdict"] = rca_client.stuck(rca_url)
    except Exception:
        pass
    # Срок TLS-сертификата (проверка раз в сутки, значение из кэша status.py) для A10.
    try:
        facts["tls_days"] = app_adapter.tls_days_left()
    except Exception:
        pass
    return facts


def _verify_due(fps_now: set, now: float) -> None:
    """Отложенные проверки: алерт исчез, действие подтверждено (resolved_auto); алерт
    остался, попытка неудачна; исчерпание попыток переводит группу в escalated."""
    for p in list(_pending_verify):
        if p["due"] > now:
            continue
        _pending_verify.remove(p)
        gid = p["gid"]
        if p["fp"] not in fps_now:
            guards.record_result(p["fp"], True, now)
            incidents.set_lifecycle(gid, "resolved_auto", by=ACTOR, action=p["action"])
            incidents.add_note(gid, ACTOR,
                               f"Проверка через {VERIFY_DELAY} с: алерт {p['code']} исчез. "
                               f"Действие «{p['action']}» подтверждено, решено агентом.")
            audit_write(ACTOR, f"agent:verify:{p['code']}", {"action": p["action"]},
                        gid, confirmed=False, result="resolved_auto")
        else:
            guards.record_result(p["fp"], False, now)
            incidents.add_note(gid, ACTOR,
                               f"Проверка через {VERIFY_DELAY} с: алерт {p['code']} не исчез, "
                               f"попытка «{p['action']}» неудачна.")
            audit_write(ACTOR, f"agent:verify:{p['code']}", {"action": p["action"]},
                        gid, confirmed=False, result="verify_failed")
            if guards.attempts(p["fp"]) >= guards.MAX_ATTEMPTS:
                _escalate(gid, p["alert"],
                          f"исчерпаны {guards.MAX_ATTEMPTS} попытки, алерт держится.")
            else:
                # Попытки остались: группа возвращается в работу следующим тактом.
                incidents.set_lifecycle(gid, "new", by=ACTOR)


def tick(rca_url: str, now: float | None = None, facts: dict | None = None,
         llm_complete=None) -> list:
    """Один такт цикла. Возвращает список записей о принятых решениях (для тестов).
    now и facts подставляются тестами; в бою факты собирает observe()."""
    now = time.time() if now is None else now
    facts = observe(rca_url) if facts is None else facts

    # Наследие поллера: вердикты RCA и застрявшие тоже попадают в центр инцидентов, но с
    # поднятым порогом (ADR-0041, раздел 7). Общий анализ логов с band=uncertain больше НЕ
    # заносится инцидентом: он тонет в шуме. Заносим вердикт RCA только при band=high либо при
    # подтверждённом детекторе застревания, сети или postgres. Застрявшие (stuck_verdict) это
    # подтверждённое застревание конвейера, поэтому проходят всегда при статусе инцидента.
    v = facts.get("rca_verdict") or {}
    if v.get("status") in ("incident", "degraded") and _register_verdict(v):
        incidents.upsert(v)
    sv = facts.get("stuck_verdict") or {}
    if sv.get("status") in ("incident", "degraded"):
        incidents.upsert(sv)

    found = alerts.detect_all(facts)
    fps_now = {incidents.fingerprint(a["verdict"]) for a in found}

    # Сначала отложенные проверки результата.
    _verify_due(fps_now, now)

    decisions = []
    pending_fps = {p["fp"] for p in _pending_verify}
    last_ok_fp = guards.last_success_within(now=now)
    for alert in found:
        fp = incidents.fingerprint(alert["verdict"])
        gid, _new = incidents.upsert(alert["verdict"])
        g = incidents.get_group(gid) or {}
        if fp in pending_fps or g.get("lifecycle") in ("auto_fixing", "escalated",
                                                       "acknowledged"):
            continue
        # Детектор осцилляции: успешное действие по X, а следом появился Y.
        if last_ok_fp and last_ok_fp != fp:
            guards.note_followup(last_ok_fp, fp, now)

        decision = choose_action(alert, guards.attempts(fp), llm_complete)
        if decision is None:
            _escalate(gid, alert, "автономного плейбука уровня A нет либо он исчерпан.")
            decisions.append({"gid": gid, "code": alert["code"], "decision": "escalate"})
            continue

        # Гарды проверяются ПОСЛЕ выбора действия: модель их не обходит.
        allowed, reason = guards.check(fp, decision["action"],
                                       decision.get("service"), now)
        if not allowed:
            hard = any(w in reason for w in ("лимит", "предохранитель", "бюджет",
                                             "осцилляции"))
            if hard:
                _escalate(gid, alert, f"действие запрещено гардом: {reason}.")
            elif gid not in _dry_noted:
                _dry_noted.add(gid)
                incidents.add_note(gid, ACTOR, f"Действие отложено гардом: {reason}.")
            decisions.append({"gid": gid, "code": alert["code"], "decision": "blocked",
                              "reason": reason})
            continue

        desc = _describe(decision)
        if not AUTONOMOUS or _paused:
            # Сухой прогон: запись в аудит и в ленту, никаких действий.
            if gid not in _dry_noted:
                _dry_noted.add(gid)
                mode = "пауза" if _paused else "сухой прогон"
                incidents.add_note(gid, ACTOR, f"[{mode}] Выполнил бы: {desc}.")
                audit_write(ACTOR, f"agent:dryrun:{alert['code']}", dict(decision),
                            gid, confirmed=False, result=f"dry_run: {desc}")
            decisions.append({"gid": gid, "code": alert["code"], "decision": "dry_run",
                              "action": decision["action"]})
            continue

        # Автономное исполнение уровней A и B.
        incidents.set_lifecycle(gid, "auto_fixing", by=ACTOR, action=decision["action"])
        guards.record_attempt(fp, decision["action"], decision.get("service"), now)
        ok, detail = _execute_action(decision, rca_url)
        level_b = is_level_b(decision["action"])
        level = "уровень B" if level_b else "уровень A"
        incidents.add_note(gid, ACTOR, f"Действие ({level}): {desc}. Результат: {detail}. "
                                       f"Проверка через {VERIFY_DELAY} с.")
        audit_write(ACTOR, f"agent:{decision['action']}", dict(decision), gid,
                    confirmed=True, result=detail)
        # Уровень B исполняется автономно, но с НЕМЕДЛЕННЫМ уведомлением оператора: агент
        # не делает заметных изменений режима обработки молча (ADR-0038, раздел 2.3).
        # Уведомление ложится в ленту тем же путём, что и обычная системная запись агента
        # (incidents.add_note), и отдельной строкой аудита с actor=agent.
        if level_b:
            verb = "выполнено" if ok else "НЕ УДАЛОСЬ"
            incidents.add_note(gid, ACTOR,
                               f"Уведомление [{alert['code']}, уровень B]: агент "
                               f"самостоятельно {verb}: {desc}. {detail}. Вмешательство "
                               "оператора не требуется, если результат подтвердится проверкой.")
            audit_write(ACTOR, f"agent:notify:{alert['code']}", dict(decision), gid,
                        confirmed=False,
                        result=("level_b_done" if ok else "level_b_failed"))
        if ok:
            _pending_verify.append({"fp": fp, "code": alert["code"], "gid": gid,
                                    "action": decision["action"],
                                    "alert": alert, "due": now + VERIFY_DELAY})
        else:
            # Действие не исполнилось: это сразу неудачная попытка.
            guards.record_result(fp, False, now)
            if guards.attempts(fp) >= guards.MAX_ATTEMPTS:
                _escalate(gid, alert, f"действие не исполнилось: {detail}.")
        decisions.append({"gid": gid, "code": alert["code"], "decision": "executed",
                          "action": decision["action"], "ok": ok})
    return decisions


def run_loop(rca_url: str) -> None:
    """Фоновый цикл агента (заменяет прежний _poller приложения)."""
    while True:
        time.sleep(TICK_SECONDS)
        try:
            tick(rca_url, llm_complete=llm.complete)
        except Exception:
            # Любая ошибка такта не роняет цикл: следующий такт начнётся с чистого листа.
            pass


# ---------------------------------------------------------------------------
# Управление и состояние (/agent, /agent pause, /agent resume).
# ---------------------------------------------------------------------------


def pause() -> str:
    """Пауза только действий; аудит пишет вызывающая команда с именем оператора."""
    global _paused
    _paused = True
    return "Автономные действия приостановлены. Наблюдение и эскалации работают."


def resume() -> str:
    global _paused
    _paused = False
    return "Автономные действия возобновлены."


def agent_state(now: float | None = None) -> dict:
    """Состояние агента для карточки /agent."""
    now = time.time() if now is None else now
    s = guards.state_summary(now)
    s.update({
        "autonomous": AUTONOMOUS,
        "paused": _paused,
        "tick_seconds": TICK_SECONDS,
        "verify_delay": VERIFY_DELAY,
        "pending_verify": len(_pending_verify),
    })
    return s
