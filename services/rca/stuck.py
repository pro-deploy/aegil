"""Детектор застрявших заданий (ADR-0032/0033). Долгий простой задания в очереди или на
стадии обработки это инцидент: конвейер не движется, даже если в логах нет ошибок (застревание
это ОТСУТСТВИЕ прогресса, глава про перерывы в потоке). Детектор читает таблицу jobs, находит
задания, превысившие порог по своей стадии, определяет ответственный за стадию сервис
(вероятный тормоз) и собирает вердикт для центра инцидентов. Само «в чём дело» уточняется по
логам сервиса-тормоза на стороне приложения (app.py): ошибки против тихого зависания.

Модуль без сети в чистой части (build_verdict), запрос к базе изолирован в find_stuck и
best-effort: без драйвера или без DSN возвращается пустой список (мягкая деградация).
"""
from __future__ import annotations

import os

# Стадия обработки -> сервис, ответственный за неё (где искать тормоз). Соответствует
# конвейеру воркера (ADR-0012): очередь держит воркер, распознавание asr, разметка дикторов
# diarize, план и саммари и описание кадров llm.
STAGE_SERVICE = {
    "queued": "worker",
    "transcribing": "asr",
    "diarizing": "diarize",
    "planning": "llm",
    "summarizing": "llm",
    "describing": "llm",
}

# Пороги застревания по стадиям в секундах (калибруются). Распознавание длинного аудио
# законно идёт дольше, поэтому у него порог выше.
def _thr(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


STAGE_THRESHOLD = {
    "queued": _thr("STUCK_QUEUED_S", 300),
    "transcribing": _thr("STUCK_TRANSCRIBING_S", 1800),
    "diarizing": _thr("STUCK_DIARIZING_S", 900),
    "planning": _thr("STUCK_PLANNING_S", 600),
    "summarizing": _thr("STUCK_SUMMARIZING_S", 900),
    "describing": _thr("STUCK_DESCRIBING_S", 900),
}
ACTIVE_STAGES = tuple(STAGE_SERVICE)


def find_stuck(dsn: str) -> list[dict]:
    """Возвращает застрявшие задания: список dict(job_id, tenant_id, status, age_s, service).
    Best-effort: при отсутствии драйвера/DSN или ошибке возвращает пустой список."""
    if not dsn:
        return []
    try:
        import psycopg2
    except Exception:
        return []
    try:
        conn = psycopg2.connect(dsn)
    except Exception:
        return []
    out: list[dict] = []
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "SELECT id, tenant_id, status, "
                "  EXTRACT(EPOCH FROM (now() - COALESCE(started_at, updated_at, created_at)))::int, "
                "  is_enqueued "
                "FROM jobs WHERE status = ANY(%s) "
                "ORDER BY 4 DESC LIMIT 200",
                (list(ACTIVE_STAGES),),
            )
            for jid, tid, status, age_s, enq in cur.fetchall():
                if age_s is None or age_s < STAGE_THRESHOLD.get(status, 900):
                    continue
                # queued без is_enqueued это ожидание слота тенанта (тарифный троттл),
                # а не тормоз сервиса: не считаем инцидентом.
                if status == "queued" and not enq:
                    continue
                out.append({
                    "job_id": str(jid),
                    "tenant_id": str(tid) if tid else "",
                    "status": status,
                    "age_s": int(age_s),
                    "service": STAGE_SERVICE.get(status, "unknown"),
                })
    except Exception:
        return []
    finally:
        conn.close()
    return out


def _mins(sec: int) -> int:
    return sec // 60


def build_verdict(stuck: list[dict], service_note: str = "") -> dict:
    """Собирает вердикт по застрявшим заданиям для центра инцидентов. service_note это
    уточнение по логам сервиса-тормоза (ошибки против тихого зависания), подставляется
    приложением. Возвращает ту же пятиполевую схему, что и обычный вердикт RCA."""
    n = len(stuck)
    if n == 0:
        return {
            "type": "verdict", "status": "healthy",
            "confidence": {"value": 0.0, "band": "low"}, "band": "low",
            "root_cause": None, "action": None, "evidence": [],
            "detectors": [], "stuck": 0,
            "speech": "Застрявших заданий нет.",
        }

    # Группировка по (стадия, сервис): доминирующая группа задаёт вероятный тормоз.
    groups: dict[tuple, list] = {}
    for s in stuck:
        groups.setdefault((s["status"], s["service"]), []).append(s)
    (status, service), items = max(groups.items(), key=lambda kv: len(kv[1]))
    oldest = max(s["age_s"] for s in stuck)

    root = (f"{n} заданий застряли в обработке; больше всего в стадии «{status}» "
            f"({len(items)}), самое старое уже {_mins(oldest)} мин. Вероятный тормоз: "
            f"сервис {service}.")
    if service_note:
        root += " " + service_note
    action = (f"Проверить сервис {service}: здоровье, латентность, очередь. Если завис, "
              f"перезапустить его и затронутые задания.")

    evidence = [{
        "source": f"job:{s['job_id']}",
        "snippet": (f"job {s['job_id']} tenant {s['tenant_id'] or '-'} стадия "
                    f"{s['status']} уже {_mins(s['age_s'])} мин"),
    } for s in sorted(stuck, key=lambda x: -x["age_s"])[:6]]

    # Полоса доверия: единичный чуть-застрявший это degraded, много или очень старое это incident.
    high = n >= 3 or oldest >= 2 * STAGE_THRESHOLD.get(status, 900)
    band = "high" if high else "uncertain"
    conf = 0.95 if high else 0.75

    speech = (f"Инцидент: {n} заданий застряли, стадия {status}, вероятный тормоз {service}, "
              f"самое старое {_mins(oldest)} минут.")

    return {
        "type": "verdict",
        "status": "incident" if high else "degraded",
        "confidence": {"value": conf, "band": band}, "band": band,
        "root_cause": root, "action": action, "evidence": evidence,
        "detectors": [f"stuck:{service}"], "stuck": n,
        "report": root + " " + action, "speech": speech,
    }
