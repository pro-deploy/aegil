"""Автономный цикл SRE-агента aegil: наблюдение, диагноз, ремонт, проверка результата.

Модуль называется autopilot, потому что имя agent занято другим слоем. Разделение ответственности:
факты и пороги считает детерминированный универсальный каталог симптомов (alerts.py), ограничители
исполняет детерминированный код (guards.py), уровень автономии и детерминированный гейт опасности
команд обеспечивает agent_exec. Автопилот НЕ классифицирует команды сам: он доверяет гейту внутри
agent_exec, который по действующему уровню автономии сам решает, что исполнить автономно, а что
вынести оператору на подтверждение.

Уровни автономии (config.autonomy, с горячим переопределением agent_exec.effective_autonomy):
наблюдение observe это сухой прогон, при котором агент диагностирует, предлагает и эскалирует, но не
исполняет никаких мутаций; безопасный ремонт safe_repair и полная автономия full поручают ремонт
инцидента агентному расследованию agent_exec.investigate, чей детерминированный гейт исполняет
обратимое и выносит опасное на подтверждение.

Устойчивость к недоступности источников наблюдения. Слепота системы (RCA недоступен, kubelet молчит,
API Kubernetes не отвечает) отражается отдельным состоянием и НЕ трактуется как отсутствие проблем.
При слепоте пустой список симптомов не закрывает ожидающие проверки как успешно решённые: проверка
откладывается до восстановления видимости. Исключение при исполнении действия не замораживает инцидент
в состоянии ремонта: оно честно фиксируется неудачей, инцидент возвращается в работу или эскалируется.
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

import agent_exec
import alerts
import app_adapter
import config
import guards
import incidents
import remediate
import k8s
import outcomes
import rca_client
from audit import audit_write

# Такт наблюдения и задержка проверки результата (переменные окружения AEGIL_).
TICK_SECONDS = int(os.getenv("AEGIL_TICK_SECONDS", "30"))
VERIFY_DELAY = int(os.getenv("AEGIL_VERIFY_DELAY", "180"))

# Отложенные проверки результата: списки словарей {fp, code, gid, due}.
_pending_verify: list = []
# Группы, по которым запись сухого прогона уже сделана (чтобы не спамить каждую итерацию).
_dry_noted: set = set()
# Группы, по которым эскалация уже записана в этой жизни группы.
_escalated_noted: set = set()

ACTOR = "agent"


# ---------------------------------------------------------------------------
# Наблюдение и различение слепоты источников от здоровья.
# ---------------------------------------------------------------------------


def observe(rca_url: str) -> dict:
    """Собирает факты для диагноза из всех источников наблюдения. Каждый источник может оказаться
    недоступным (значение None): это НЕ признак здоровья, а признак слепоты, который различается
    отдельно (см. is_blind). Никаких имён приложения владельца здесь нет: топология выясняется через
    API Kubernetes."""
    nodes = k8s.list_nodes()
    facts = {
        "nodes": nodes,
        "pods": k8s.list_pods(),
        "deployments": k8s.list_deployments(),
        "events": k8s.list_events(),
        "stats_by_node": app_adapter.stats_by_node(nodes),
        "now": datetime.now(timezone.utc),
        "rca_verdict": None,
        "tls_days": None,
    }
    try:
        out = rca_client.analyze(rca_url, {"minutes": 15, "use_baseline": False,
                                           "formulate": True})
        facts["rca_verdict"] = rca_client.verdict_payload(out)
        facts["rca_available"] = True
    except Exception:  # noqa: BLE001 недоступность RCA это слепота, не здоровье
        facts["rca_available"] = False
    try:
        facts["tls_days"] = app_adapter.tls_days_left()
    except Exception:  # noqa: BLE001
        pass
    return facts


# Источники наблюдения кластера, чья одновременная недоступность означает полную слепоту.
_CLUSTER_SOURCES = ("pods", "nodes", "deployments", "events")


def is_blind(facts: dict) -> bool:
    """Слеп ли агент по кластеру: все источники наблюдения кластера недоступны (значение None), а RCA
    тоже недоступен. В этом состоянии пустой список симптомов не является свидетельством здоровья, и
    ожидающие проверки не закрываются как решённые."""
    f = facts or {}
    cluster_blind = all(f.get(src) is None for src in _CLUSTER_SOURCES)
    rca_blind = not f.get("rca_available", False)
    return cluster_blind and rca_blind


# ---------------------------------------------------------------------------
# Регистрация вердиктов RCA инцидентами (поднятый порог против шума).
# ---------------------------------------------------------------------------

# Детекторы подтверждённого сетевого сбоя (connection_refused, dns_error и подобное) в RCA. Их
# появление регистрирует инцидент даже при средней уверенности, потому что это подтверждённый факт, а
# не шумовой вывод общего анализа логов.
_CONFIRMED_DETECTORS = {"D5"}


def _register_verdict(verdict: dict) -> bool:
    """Заносить ли вердикт RCA инцидентом. Порог поднят: только при band=high либо при подтверждённом
    детекторе сетевого сбоя. Слабые сигналы (band=uncertain на общем анализе логов) не заносятся,
    чтобы лента не тонула в шуме."""
    if not verdict:
        return False
    if verdict.get("band") == "high":
        return True
    dets = set(verdict.get("detectors") or [])
    return bool(dets & _CONFIRMED_DETECTORS)


# ---------------------------------------------------------------------------
# Агентное расследование и ремонт инцидента.
# ---------------------------------------------------------------------------


def _trace_summary(trace: dict) -> str:
    """Сжимает трейс агентного расследования в человекочитаемую заметку для ленты инцидента:
    последний итог или объяснение агента, число выполненных мутаций и число вынесенных на
    подтверждение опасных команд. Полный трейс уходит в аудит."""
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
    """Запускает агентное расследование инцидента над его вердиктом. Детерминированный гейт внутри
    agent_exec сам решает по действующему уровню автономии, что исполнить обратимым ремонтом, а что
    вынести на подтверждение. Возвращает трейс шагов либо None при любой ошибке: расследование не
    роняет такт агента."""
    verdict = dict(alert.get("verdict") or {})
    if not verdict:
        verdict = {"root_cause": alert.get("title") or alert.get("code"),
                   "detectors": [alert.get("code")], "status": "incident",
                   "params": alert.get("params") or {}}
    try:
        return agent_exec.investigate(verdict, operator=ACTOR)
    except Exception:  # noqa: BLE001 честная ошибка расследования, не падение цикла
        return None


def _repair(gid: str, alert: dict, fp: str, now: float) -> dict:
    """Поручает ремонт инцидента агентному расследованию (уровни safe_repair и full). Устойчиво к
    исключению исполнения: любая ошибка внутри расследования уже поглощена в _run_investigation и
    возвращает None, но и сам переход состояний инцидента обёрнут так, чтобы группа не залипла в
    состоянии ремонта. Возвращает запись решения для тестов."""
    incidents.set_lifecycle(gid, "auto_fixing", by=ACTOR, action="investigate")

    # Детерминированный ремонт БЕЗ языковой модели: по хорошо понятному симптому выбирается
    # конкретное безопасное действие (перезапуск безсостоятельного сервиса) и исполняется через
    # гейт, гарды и аудит. Действуем только если действие исполнилось бы автономно (сервис в
    # allowlist): иначе не плодим отложенное подтверждение, а уступаем расследованию моделью.
    # Так автономный ремонт работает и с моделью без вызова инструментов (например gemma).
    det = remediate.propose(alert)
    if det and agent_exec.would_autoact(det["argv"]):
        res = agent_exec.act(det["argv"], det.get("target", "cluster"), "", det.get("why", ""), ACTOR)
        if res.get("outcome") == "executed":
            incidents.add_note(gid, ACTOR, f"Ремонт [{alert.get('code')}]: детерминированно выполнено "
                               f"«{' '.join(det['argv'])}». Проверка через {VERIFY_DELAY} с.")
            audit_write(ACTOR, f"agent:repair:{alert.get('code')}", det.get("params", {}),
                        gid, confirmed=True, result="remediated")
            _pending_verify.append({"fp": fp, "code": alert["code"], "gid": gid,
                                    "alert": alert, "due": now + VERIFY_DELAY})
            return {"gid": gid, "code": alert["code"], "decision": "repair", "mode": "deterministic"}

    guards.record_attempt(fp, "investigate", None, now)
    trace = _run_investigation(gid, alert)
    if trace is None:
        # Расследование не удалось (ошибка модели, недоступность инструментов): не оставляем группу
        # замороженной в ремонте. Честно фиксируем неудачу и эскалируем либо возвращаем в работу.
        guards.record_result(fp, False, now)
        incidents.add_note(gid, ACTOR,
                           f"Ремонт [{alert.get('code')}]: расследование не удалось (модель или "
                           "инструменты недоступны).")
        audit_write(ACTOR, f"agent:repair:{alert.get('code')}", alert.get("params") or {},
                    gid, confirmed=False, result="repair_failed")
        if guards.attempts(fp) >= guards.MAX_ATTEMPTS:
            _escalate(gid, alert, "ремонт не удался, попытки исчерпаны.")
        else:
            incidents.set_lifecycle(gid, "new", by=ACTOR)
        return {"gid": gid, "code": alert["code"], "decision": "repair_failed"}
    # Расследование прошло: фиксируем итог, ставим отложенную проверку результата.
    incidents.add_note(gid, ACTOR,
                       f"Ремонт [{alert.get('code')}]: {_trace_summary(trace)} "
                       f"Проверка через {VERIFY_DELAY} с.")
    audit_write(ACTOR, f"agent:repair:{alert.get('code')}",
                {"steps": len(trace.get("steps") or [])},
                gid, confirmed=True, result="investigated")
    _pending_verify.append({"fp": fp, "code": alert["code"], "gid": gid,
                            "alert": alert, "due": now + VERIFY_DELAY})
    return {"gid": gid, "code": alert["code"], "decision": "repair"}


def _escalate(gid: str, alert: dict, reason: str) -> None:
    """Эскалация инцидента: перевод в состояние escalated с запуском агентного расследования, чтобы
    агент сам собрал факты и приложил их с предложением ремонта, а не сваливал работу на оператора
    текстом «проверьте вручную». Пишется один раз на группу."""
    g = incidents.get_group(gid)
    if not g or g.get("lifecycle") == "escalated" or gid in _escalated_noted:
        return
    _escalated_noted.add(gid)
    incidents.set_lifecycle(gid, "escalated", by=ACTOR)
    incidents.add_note(gid, ACTOR, f"Эскалация [{alert.get('code')}]: {reason}")
    trace = _run_investigation(gid, alert)
    if trace is not None:
        incidents.add_note(gid, ACTOR,
                           f"Расследование агента [{alert.get('code')}]: {_trace_summary(trace)}")
        audit_write(ACTOR, f"agent:investigate:{alert.get('code')}",
                    {"steps": len(trace.get("steps") or [])},
                    gid, confirmed=False, result="investigated")
    audit_write(ACTOR, f"agent:escalate:{alert.get('code')}", alert.get("params") or {},
                gid, confirmed=False, result=reason)


# ---------------------------------------------------------------------------
# Проверка результата.
# ---------------------------------------------------------------------------


def _verify_due(fps_now: set, now: float, blind: bool) -> None:
    """Отложенные проверки результата. При слепоте (источники наблюдения недоступны) проверка НЕ
    выполняется: исчезновение симптома из пустых фактов не является свидетельством решения, поэтому
    ожидающая проверка откладывается на следующий такт с восстановленной видимостью, а не закрывается
    как resolved_auto. При видимости: симптом исчез, значит ремонт подтверждён (resolved_auto); симптом
    остался, значит попытка неудачна; исчерпание попыток переводит группу в escalated."""
    for p in list(_pending_verify):
        if p["due"] > now:
            continue
        gid = p["gid"]
        if blind:
            # Слепота это неизвестность, а не успех. Не закрываем и не проваливаем проверку: отражаем
            # неопределённость записью и переносим срок проверки вперёд. Запись делается один раз.
            if not p.get("blind_noted"):
                p["blind_noted"] = True
                incidents.add_note(gid, ACTOR,
                                   f"Проверка [{p['code']}] отложена: источники наблюдения "
                                   "недоступны, результат ремонта неизвестен (не здоровье и не "
                                   "неудача).")
            p["due"] = now + VERIFY_DELAY
            continue
        _pending_verify.remove(p)
        p.pop("blind_noted", None)
        if p["fp"] not in fps_now:
            guards.record_result(p["fp"], True, now)
            incidents.set_lifecycle(gid, "resolved_auto", by=ACTOR, action="investigate")
            incidents.add_note(gid, ACTOR,
                               f"Проверка через {VERIFY_DELAY} с: симптом {p['code']} исчез. "
                               "Ремонт подтверждён, решено агентом.")
            audit_write(ACTOR, f"agent:verify:{p['code']}", {}, gid,
                        confirmed=False, result="resolved_auto")
            # Замыкание активного обучения: подтверждённый автономный ремонт это размеченный пример.
            outcomes.record(dict(p["alert"].get("verdict") or {}), f"repair:{p['code']}", resolved=True)
        else:
            guards.record_result(p["fp"], False, now)
            incidents.add_note(gid, ACTOR,
                               f"Проверка через {VERIFY_DELAY} с: симптом {p['code']} не исчез, "
                               "попытка ремонта неудачна.")
            audit_write(ACTOR, f"agent:verify:{p['code']}", {}, gid,
                        confirmed=False, result="verify_failed")
            # Неудачный ремонт тоже размеченный пример: диагноз не привёл к устранению.
            outcomes.record(dict(p["alert"].get("verdict") or {}), f"repair:{p['code']}", resolved=False)
            if guards.attempts(p["fp"]) >= guards.MAX_ATTEMPTS:
                _escalate(gid, p["alert"],
                          f"исчерпаны {guards.MAX_ATTEMPTS} попытки, симптом держится.")
            else:
                incidents.set_lifecycle(gid, "new", by=ACTOR)


# ---------------------------------------------------------------------------
# Такт цикла.
# ---------------------------------------------------------------------------


def tick(rca_url: str, now: float | None = None, facts: dict | None = None,
         autonomy: str | None = None) -> list:
    """Один такт цикла. Возвращает список записей о принятых решениях (для тестов). now, facts и
    autonomy подставляются тестами; в бою факты собирает observe(), а уровень автономии берётся из
    agent_exec.effective_autonomy()."""
    now = time.time() if now is None else now
    facts = observe(rca_url) if facts is None else facts
    autonomy = agent_exec.effective_autonomy() if autonomy is None else autonomy
    blind = is_blind(facts)

    # Вердикт RCA с поднятым порогом тоже попадает в центр инцидентов.
    v = facts.get("rca_verdict") or {}
    if v.get("status") in ("incident", "degraded") and _register_verdict(v):
        incidents.upsert(v)

    found = alerts.detect_all(facts)
    fps_now = {incidents.fingerprint(a["verdict"]) for a in found}

    # Сначала отложенные проверки результата (с учётом слепоты).
    _verify_due(fps_now, now, blind)

    # При слепоте новые действия не начинаются: агент не действует вслепую, только наблюдает и ждёт
    # восстановления видимости.
    if blind:
        return [{"decision": "blind"}]

    decisions = []
    pending_fps = {p["fp"] for p in _pending_verify}
    last_ok_fp = guards.last_success_within(now=now)
    dry_run = autonomy == config.AUTONOMY_OBSERVE
    for alert in found:
        fp = incidents.fingerprint(alert["verdict"])
        gid, _new = incidents.upsert(alert["verdict"])
        g = incidents.get_group(gid) or {}
        if fp in pending_fps or g.get("lifecycle") in ("auto_fixing", "escalated",
                                                       "acknowledged"):
            continue
        # Детектор осцилляции: успешное действие по одному отпечатку, а следом появился другой.
        if last_ok_fp and last_ok_fp != fp:
            guards.note_followup(last_ok_fp, fp, now)

        # Гарды проверяются до начала ремонта (бюджет, кулдауны, предохранитель, осцилляция).
        allowed, reason = guards.check(fp, "investigate", None, now)
        if not allowed:
            hard = any(w in reason for w in ("лимит", "предохранитель", "бюджет", "осцилляции"))
            if hard:
                _escalate(gid, alert, f"ремонт запрещён гардом: {reason}.")
            elif gid not in _dry_noted:
                _dry_noted.add(gid)
                incidents.add_note(gid, ACTOR, f"Ремонт отложен гардом: {reason}.")
            decisions.append({"gid": gid, "code": alert["code"], "decision": "blocked",
                              "reason": reason})
            continue

        if dry_run:
            # Уровень наблюдения: сухой прогон. Запись в ленту и аудит, никаких мутаций.
            if gid not in _dry_noted:
                _dry_noted.add(gid)
                incidents.add_note(gid, ACTOR,
                                   f"[наблюдение] Симптом {alert['code']}: {alert['title']}. "
                                   "Ремонт предложен, но уровень автономии observe исполнять "
                                   "запрещает.")
                audit_write(ACTOR, f"agent:observe:{alert['code']}", alert.get("params") or {},
                            gid, confirmed=False, result="dry_run")
            decisions.append({"gid": gid, "code": alert["code"], "decision": "dry_run"})
            continue

        # Уровни safe_repair и full: поручаем ремонт агентному расследованию. Исключения исполнения
        # поглощены внутри _repair, группа не залипает в состоянии ремонта.
        decisions.append(_repair(gid, alert, fp, now))
    return decisions


def run_loop(rca_url: str) -> None:
    """Фоновый цикл агента. Публичная сигнатура сохранена: её вызывает app.py на старте."""
    while True:
        time.sleep(TICK_SECONDS)
        try:
            tick(rca_url)
        except Exception:  # noqa: BLE001 ошибка такта не роняет цикл
            pass


# ---------------------------------------------------------------------------
# Состояние для карточки интерфейса.
# ---------------------------------------------------------------------------


def agent_state(now: float | None = None) -> dict:
    """Состояние агента для карточки интерфейса: уровень автономии, признак слепоты, состояние гардов,
    число отложенных проверок."""
    now = time.time() if now is None else now
    s = guards.state_summary(now)
    s.update({
        "autonomy": agent_exec.effective_autonomy(),
        "tick_seconds": TICK_SECONDS,
        "verify_delay": VERIFY_DELAY,
        "pending_verify": len(_pending_verify),
        "blind": any(p.get("blind_noted") for p in _pending_verify),
    })
    return s
