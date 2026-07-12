"""Тесты каталога детекторов и байесовского скоринга. Собираемый вид pytest.

Запуск: cd services/rca && python3 -m pytest -q test_detectors.py
"""
from aggregator import aggregate
from detectors import detect
from scoring import score
from test_aggregator import RECORDS

BASELINE_RECORDS = [
    {"_ts_ns": 1, "level": "info", "service": "api", "msg": "health check",
     "event": "http.request", "http.status": 200, "trace_id": "b1"},
    {"_ts_ns": 2, "level": "info", "service": "worker", "msg": "job done",
     "event": "job.done", "trace_id": "b1"},
]


def _fired_ids(dets):
    return [d["id"] for d in dets if d["fired"]]


def test_fired_without_baseline():
    # Окно значимо по доле ошибок (2 из 6). Срабатывают всплеск, сеть и 5xx. D11 не
    # срабатывает: радиус по максимальной оси равен двум подам, а порог значимости три.
    # D8 структурный сосед срабатывает: ошибающийся api имеет ребро к тоже ошибающемуся
    # worker, но в скоринге структурный детектор не голосует (проверяется отдельно).
    f = aggregate(RECORDS)
    assert _fired_ids(detect(f)) == ["D1", "D5", "D8", "D10"]


def test_group_max_prevents_double_counting():
    # D1 и D5 порождены одной волной и делят группу spike: голос группы это максимум,
    # а не произведение, поэтому две стороны одного всплеска не считаются дважды.
    f = aggregate(RECORDS)
    s = score(detect(f))
    assert s["group_max"] == {"spike": 8.0, "http": 6.0}
    assert s["odds"] == round(0.1 * 8.0 * 6.0, 4)
    assert s["band"] == "uncertain"


def test_baseline_raises_confidence():
    f = aggregate(RECORDS)
    base = aggregate(BASELINE_RECORDS)
    s = score(detect(f))
    s_b = score(detect(f, base))
    assert set(_fired_ids(detect(f, base))) >= {"D1", "D2", "D3", "D5", "D10"}
    assert s_b["confidence"] > s["confidence"]
    assert s_b["band"] == "high"


def test_delta_lowers_confidence_and_band():
    f = aggregate(RECORDS)
    s = score(detect(f))
    s_low = score(detect(f), delta=0.5)
    assert s_low["confidence"] < s["confidence"]
    assert s_low["band"] == "low"


def test_noise_gate_suppresses_single_flap():
    # Негативная проверка: единичный сбойный лог на фоне здорового потока это шум, а не
    # инцидент. Объёмные детекторы под гейтом значимости не голосуют.
    # Поток непрерывен во времени (метки 0..200 без разрыва), чтобы проверялся именно
    # гейт значимости объёмных детекторов, а не временные детекторы перерыва и молчания.
    noise = [{"level": "info", "service": "api", "msg": "ok", "trace_id": f"n{i}", "_ts_ns": i}
             for i in range(200)]
    noise.append({"level": "error", "service": "worker", "msg": "one flaky i/o timeout",
                  "trace_id": "e1", "pod": "w-1", "_ts_ns": 200})
    assert _fired_ids(detect(aggregate(noise))) == []


def test_correlated_wave_does_not_explode():
    # Негативная проверка завышения: одна волна из немногих строк порождает несколько
    # коррелированных детекторов (D1, D5, D10, D11), но группировка держит уверенность
    # разумной. Она высокая по нескольким НЕЗАВИСИМЫМ группам, но не из двух строк:
    # вклад spike учитывается один раз, а не как произведение D1 на D5.
    wave = [{"msg": "ok", "level": "info", "_ts_ns": i} for i in range(6)]
    wave += [{"msg": "upstream connection refused", "level": "error", "service": "api",
              "http.status": 503, "pod": f"p{i}", "namespace": "prod", "container": "api",
              "_ts_ns": 100 + i} for i in range(4)]
    d = detect(aggregate(wave))
    s = score(d)
    # В этой фикстуре между здоровой ранней частью (метки 0..5) и волной ошибок (метки
    # 100..105) лежит настоящий перерыв в потоке логов, поэтому D6 закономерно
    # срабатывает как независимое свидетельство обрыва потока.
    assert set(_fired_ids(d)) == {"D1", "D5", "D6", "D10", "D11"}
    # Группа spike вносит вклад один раз (максимум 8.0), а не 8*7.
    assert s["group_max"]["spike"] == 8.0
    assert "network" not in s["group_max"]


def test_bayesian_update_is_two_sided():
    # Применимый, но несработавший детектор понижает шансы (LR<1), а не оставляет их
    # прежними. Раньше отсутствие ожидаемого симптома игнорировалось.
    dets = [
        {"id": "D1", "name": "s", "fired": False, "lr": 8.0, "group": "spike",
         "applicable": True, "lr_absent": 0.6},
        {"id": "D10", "name": "h", "fired": False, "lr": 6.0, "group": "http",
         "applicable": True, "lr_absent": 0.6},
    ]
    s = score(dets)
    assert s["odds"] == round(0.1 * 0.6 * 0.6, 4)
    assert s["odds"] < 0.1  # ниже априорных шансов


def test_non_applicable_stub_does_not_contribute():
    # Честность стабов: неприменимый детектор (нет временного ряда) не влияет ни в одну
    # сторону, поэтому шансы остаются априорными.
    dets = [{"id": "D6", "name": "gap", "fired": False, "lr": 5.0, "group": "gap",
             "applicable": False}]
    assert score(dets)["odds"] == round(0.1, 4)


def test_timeseries_detectors_applicable_when_input_present():
    # При наличии меток времени и рёбер топологии D6, D7, D8, D12 применимы: вход подан.
    d = {x["id"]: x for x in detect(aggregate(RECORDS))}
    for sid in ("D6", "D7", "D8", "D12"):
        assert d[sid]["applicable"] is True


def test_timeseries_detectors_not_applicable_when_input_absent():
    # Без меток времени временной ряд не строится, без полей цели вызова нет рёбер, и
    # опирающиеся на них детекторы честно неприменимы, а не выдаются за рабочие.
    recs = [{"level": "error", "service": "s", "msg": "connection refused"} for _ in range(4)]
    d = {x["id"]: x for x in detect(aggregate(recs))}
    for sid in ("D6", "D7", "D12"):
        assert d[sid]["applicable"] is False
    assert d["D8"]["applicable"] is False  # рёбер топологии нет


def test_log_gap_fires_on_interrupted_stream():
    # Существенный поток логов обрывается и возобновляется много позже: D6 срабатывает.
    recs = [{"level": "info", "service": "api", "msg": "ok", "_ts_ns": i, "trace_id": f"a{i}"}
            for i in range(10)]
    recs += [{"level": "info", "service": "api", "msg": "ok", "_ts_ns": 1000 + i,
              "trace_id": f"b{i}"} for i in range(10)]
    assert "D6" in _fired_ids(detect(aggregate(recs)))


def test_source_silence_fires_when_service_goes_dark():
    # Сервис db эмитирует существенный объём в начале окна и полностью замолкает, тогда
    # как web продолжает писать до конца окна: D7 срабатывает на замолчавший источник.
    recs = [{"level": "info", "service": "db", "msg": "query", "_ts_ns": i} for i in range(6)]
    recs += [{"level": "info", "service": "web", "msg": "req", "_ts_ns": i} for i in range(20)]
    d = {x["id"]: x for x in detect(aggregate(recs))}
    assert d["D7"]["fired"] is True
    assert "db" in d["D7"]["evidence"]


def test_structural_neighbor_fires_but_does_not_vote():
    # api ошибается и зовёт тоже ошибающийся worker: D8 срабатывает как структурный
    # сигнал локализации, но в скоринге группа structural голоса не подаёт.
    recs = [{"level": "error", "service": "api", "msg": "upstream failed", "target": "worker",
             "_ts_ns": i} for i in range(3)]
    recs += [{"level": "error", "service": "worker", "msg": "connection refused", "target": "db",
              "_ts_ns": 3 + i} for i in range(3)]
    d = detect(aggregate(recs))
    dd = {x["id"]: x for x in d}
    assert dd["D8"]["fired"] is True
    assert "structural" not in score(d)["group_max"]


def test_structural_neighbor_fires_on_silent_downstream():
    # Вскрыто настоящим сквозным прогоном: корневой сервис db упал и МОЛЧИТ (не пишет
    # ни одной строки ошибки), а api ошибается, вызывая его. Структурный сосед обязан
    # опознать замолчавший db как отказавший корень, а не пропустить его.
    recs = [{"level": "info", "service": "db", "msg": "ready", "_ts_ns": i} for i in range(6)]
    recs += [{"level": "error", "service": "api", "msg": "connection refused",
              "target": "db", "_ts_ns": 6 + i} for i in range(20)]
    d = {x["id"]: x for x in detect(aggregate(recs))}
    assert d["D8"]["fired"] is True
    assert "db" in d["D8"]["evidence"]
    assert "silent" in d["D8"]["evidence"]


def test_recovery_damper_fires_and_lowers_confidence():
    # Ошибки сосредоточены в ранней половине окна и затухают к поздней: D12 срабатывает
    # и понижает уверенность через демпфер восстановления.
    recs = [{"level": "error", "service": "api", "msg": "boom", "_ts_ns": i} for i in range(5)]
    recs += [{"level": "info", "service": "api", "msg": "ok", "_ts_ns": 5 + i} for i in range(20)]
    d = detect(aggregate(recs))
    dd = {x["id"]: x for x in d}
    assert dd["D12"]["fired"] is True
    assert score(d)["damper"] < 1.0


def test_blast_fires_on_wide_pod_reach():
    wide = [{"level": "error", "service": "worker", "msg": "connection refused",
             "trace_id": f"w{i}", "pod": f"worker-{i}", "namespace": "prod", "_ts_ns": i}
            for i in range(4)]
    assert "D11" in _fired_ids(detect(aggregate(wide)))


def test_ceiling_caps_confidence():
    huge = [{"id": "X", "name": "x", "fired": True, "lr": 1e6, "group": "g"}]
    assert score(huge)["band"] == "high"
    assert score(huge)["confidence"] <= 0.999


def test_recent_change_accepts_any_release_synonym():
    # D9 срабатывает на любой синоним изменения, а не строго на событие "deploy".
    for ev in ("rollout", "release", "helm-upgrade", "apply"):
        recs = [{"level": "info", "service": "s", "msg": "x", "event": ev, "_ts_ns": 1}]
        d = {x["id"]: x for x in detect(aggregate(recs))}
        assert d["D9"]["fired"], ev
