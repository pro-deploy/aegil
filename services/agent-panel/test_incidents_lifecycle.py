"""Модульные тесты жизненного цикла инцидентов и помесячного хранилища kube-sentinel.

Собираемый pytest-вид (функции с префиксом test_), без сети. Запуск:
    cd services/agent-panel && python3 -m pytest -q test_incidents_lifecycle.py

Покрыты: жизненный цикл группы, переоткрытие после решения, помесячное хранилище и
совместимость со старым единым файлом, отпечаток с замаскированными числами, замена слабого
хеша на SHA-256, вынос пути хранилища в каталог данных вне рабочего дерева и потокобезопасность
конкурентного upsert из такта агента и обработчика.
"""
import json
import tempfile
import threading
from pathlib import Path

import incidents


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


V = {"status": "incident", "detectors": ["D5"], "root_cause": "отказ у цели app на порту 9101"}


def _fresh():
    tmp = Path(tempfile.mkdtemp())
    incidents.STORE_PATH = tmp / "incidents.log.jsonl"
    incidents.STORE_DIR = tmp
    incidents._groups.clear()
    incidents._active.clear()
    return tmp


def test_lifecycle():
    _fresh()
    gid, new = incidents.upsert(V)
    _eq("new group", new, True)
    g = incidents.get_group(gid)
    _eq("start lifecycle", g["lifecycle"], "new")
    _eq("no reopen link", g["reopened_from"], None)

    # Оператор берёт в работу: acknowledged с атрибуцией.
    incidents.acknowledge(gid, "max")
    _eq("acked", g["lifecycle"], "acknowledged")
    _eq("acked by", g["acked_by"], "max")

    # Оператор решает кнопкой: resolved_operator с оператором и действием.
    incidents.resolve_operator(gid, "max", "requeue")
    _eq("resolved", g["lifecycle"], "resolved_operator")
    _eq("resolved by", g["resolved_by"], "max")
    _eq("resolved action", g["resolved_action"], "requeue")
    assert g["resolved_at"], "resolved_at пуст"
    _eq("resolved unread", g["unread"], False)

    # Недопустимый статус отбивается без изменения группы.
    _eq("bad lifecycle", incidents.set_lifecycle(gid, "deleted"), None)
    _eq("lifecycle kept", g["lifecycle"], "resolved_operator")

    # Поиск группы работает и по ключу отпечатка, и по номеру INC.
    _eq("get by key", incidents.get_group(g["key"])["id"], gid)

    # Выдача наружу содержит поля цикла и день для группировки в ленте.
    out = incidents.list_groups()[0]
    _eq("day", out["day"], out["last_seen"][:10])
    assert out["lifecycle"] == "resolved_operator"
    print("lifecycle: ok")


def test_reopen():
    _fresh()
    gid1, _ = incidents.upsert(V)
    # Пока группа не решена, повтор отпечатка копится в ней же.
    gid2, new = incidents.upsert(dict(V))
    _eq("same group while open", gid2, gid1)
    _eq("not new", new, False)
    _eq("count", incidents.get_group(gid1)["count"], 2)

    # После решения повтор открывает НОВУЮ группу со ссылкой на прежнюю.
    incidents.resolve_operator(gid1, "max", "restart")
    gid3, new = incidents.upsert(dict(V))
    assert gid3 != gid1, "решённая группа воскрешена вместо переоткрытия"
    _eq("reopened is new", new, True)
    g3 = incidents.get_group(gid3)
    _eq("reopen link", g3["reopened_from"], gid1)
    _eq("reopen lifecycle", g3["lifecycle"], "new")
    # Старая группа не удалена и не изменена: инциденты вечные.
    old = incidents._groups[gid1]
    _eq("old kept resolved", old["lifecycle"], "resolved_operator")
    _eq("groups total", len(incidents.list_groups()), 2)

    # После рестарта вся история (включая переоткрытие) восстанавливается из журнала.
    incidents.load()
    _eq("reload groups", len(incidents.list_groups()), 2)
    g3r = incidents.get_group(g3["key"])
    _eq("reload reopen link", g3r["reopened_from"], gid1)
    _eq("reload old resolved", incidents._groups[gid1]["lifecycle"], "resolved_operator")
    print("reopen: ok")


def test_monthly_files():
    tmp = _fresh()
    gid, _ = incidents.upsert(V)
    # События пишутся в помесячный файл incidents-YYYY-MM.log.jsonl, не в старый единый.
    month_files = sorted(tmp.glob("incidents-????-??.log.jsonl"))
    _eq("one month file", len(month_files), 1)
    assert not incidents.STORE_PATH.exists(), "новые события попали в старый единый файл"
    # Событие жизненного цикла тоже append-only в тот же журнал.
    incidents.resolve_operator(gid, "max", "requeue")
    lines = month_files[0].read_text(encoding="utf-8").strip().splitlines()
    _eq("events appended", len(lines), 2)
    _eq("lifecycle event", json.loads(lines[1])["event"], "lifecycle")

    # Совместимость: старый единый файл читается при старте вместе с помесячными.
    legacy = {"ts": "2025-12-31T10:00:00.000Z",
              "verdict": {"status": "degraded", "detectors": ["D1"], "root_cause": "старый инцидент"}}
    incidents.STORE_PATH.write_text(json.dumps(legacy, ensure_ascii=False) + "\n", encoding="utf-8")
    # Плюс журнал другого месяца: при старте восстанавливаются ВСЕ файлы.
    other = {"ts": "2026-01-15T10:00:00.000Z",
             "verdict": {"status": "incident", "detectors": ["D2"], "root_cause": "январский инцидент"}}
    (tmp / "incidents-2026-01.log.jsonl").write_text(
        json.dumps(other, ensure_ascii=False) + "\n", encoding="utf-8")
    incidents.load()
    _eq("all files replayed", len(incidents.list_groups()), 3)
    titles = {g["title"] for g in incidents.list_groups()}
    assert "старый инцидент" in titles and "январский инцидент" in titles, titles


def test_sha256_identifier():
    """Идентификатор группы строится на SHA-256, а не на слабом MD5/SHA1 (блокер сканера ailc).
    Проверяем детерминизм и совпадение с эталонным SHA-256 от того же зерна."""
    import hashlib
    _fresh()
    gid, _ = incidents.upsert(V)
    g = incidents.get_group(gid)
    # Идентификатор это INC- плюс первые восемь знаков SHA-256 от зерна ключ|момент|порядок.
    seed = f"{g['key']}|{g['first_seen']}|0"
    expected = "INC-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:8].upper()
    _eq("идентификатор на SHA-256", gid, expected)
    # Тот же идентификатор не совпал бы с SHA-1 от того же зерна.
    sha1 = "INC-" + hashlib.sha1(seed.encode("utf-8")).hexdigest()[:8].upper()
    assert gid != sha1, "идентификатор всё ещё на SHA-1"


def test_store_path_outside_worktree(monkeypatch):
    """Пути хранилища по умолчанию лежат в каталоге данных вне рабочего дерева агента, а не
    внутри каталога модуля."""
    monkeypatch.delenv("SENTINEL_INCIDENTS", raising=False)
    monkeypatch.delenv("SENTINEL_INCIDENTS_DIR", raising=False)
    monkeypatch.setenv("SENTINEL_STATE_DIR", "/data")
    import importlib
    reloaded = importlib.reload(incidents)
    try:
        _eq("путь единого файла в каталоге данных",
            str(reloaded.STORE_PATH), "/data/incidents.log.jsonl")
        _eq("каталог помесячных файлов в каталоге данных", str(reloaded.STORE_DIR), "/data")
        module_dir = str(Path(reloaded.__file__).resolve().parent)
        assert not str(reloaded.STORE_PATH).startswith(module_dir), \
            f"хранилище инцидентов внутри рабочего дерева: {reloaded.STORE_PATH}"
    finally:
        # Возвращаем модуль в чистое состояние для остальных тестов.
        importlib.reload(incidents)


def test_concurrent_upsert_no_lost_events():
    """Гонка: конкурентный upsert из многих потоков (имитация такта агента и обработчиков) не
    теряет события и не мешает строки в помесячном журнале."""
    tmp = _fresh()
    threads_count = 12
    per_thread = 20
    barrier = threading.Barrier(threads_count)

    # Отпечаток маскирует цифры (числа в причине заменяются на #), поэтому уникальность причин
    # задаём буквами, иначе все причины схлопнулись бы в один отпечаток.
    letters = "abcdefghijklmnopqrstuvwxyz"

    def _tag(tid: int, i: int) -> str:
        return letters[tid % 26] + letters[i % 26] + letters[(tid + i) % 26]

    def worker(tid: int):
        barrier.wait()
        for i in range(per_thread):
            v = {"status": "incident", "detectors": ["D5"],
                 "root_cause": f"уникальная причина поток {_tag(tid, i)}"}
            incidents.upsert(v)

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(threads_count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    expected = threads_count * per_thread
    # Каждая причина уникальна, значит групп ровно столько же, сколько upsert.
    _eq("все группы созданы", len(incidents.list_groups()), expected)
    # Все строки журнала валидны: конкурентная запись не порвала строки.
    month_files = sorted(tmp.glob("incidents-????-??.log.jsonl"))
    lines = []
    for p in month_files:
        lines += [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    _eq("все события в журнале", len(lines), expected)
    for l in lines:
        json.loads(l)
    # После перезапуска восстанавливаются все группы.
    incidents.load()
    _eq("все группы восстановлены", len(incidents.list_groups()), expected)
