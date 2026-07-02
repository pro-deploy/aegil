"""Модульный тест детекторов D1-D12 и байесовского скоринга (ADR-0032, Часть B).
Запуск без зависимостей: python3 services/rca/test_detectors.py
"""
from aggregator import aggregate
from detectors import detect
from scoring import score
from test_aggregator import RECORDS

BASELINE_RECORDS = [
    {"ts": "2026-06-30T12:00:01Z", "level": "info", "service": "api", "msg": "health check",
     "event": "http.request", "http.status": 200, "trace_id": "b1"},
    {"ts": "2026-06-30T12:00:02Z", "level": "info", "service": "worker", "msg": "job done",
     "event": "job.done", "trace_id": "b1"},
]


def _eq(name, got, want):
    assert got == want, f"{name}: got {got!r}, want {want!r}"


def _fired_ids(dets):
    return [d["id"] for d in dets if d["fired"]]


def main() -> None:
    facts = aggregate(RECORDS)

    # Окно значимо по доле ошибок (2 из 6). Без baseline срабатывают D1 (всплеск),
    # D5 (сеть), D10 (5xx). D11 не срабатывает: радиус по максимальной оси равен двум
    # (2 тенанта, 2 джоба), а порог значимой широты поражения три.
    dets = detect(facts)
    _eq("fired no-baseline", _fired_ids(dets), ["D1", "D5", "D10"])

    s = score(dets)
    # group-max: spike=max(8,7)=8 (D1 и D5 как две стороны одного всплеска), http=6
    # → odds=0.1*8*6=4.8. Маленькое окно с двумя ошибками честно попадает в uncertain.
    _eq("odds", s["odds"], 4.8)
    _eq("group_max", s["group_max"], {"spike": 8.0, "http": 6.0})
    _eq("confidence", s["confidence"], 0.8276)
    _eq("band", s["band"], "uncertain")
    _eq("fired list", sorted(s["fired"]), ["D1", "D10", "D5"])

    # С baseline дополнительно срабатывают D2 (новый шаблон) и D3 (рост ошибок).
    baseline = aggregate(BASELINE_RECORDS)
    dets_b = detect(facts, baseline)
    _eq("fired with-baseline", _fired_ids(dets_b), ["D1", "D2", "D3", "D5", "D10"])
    s_b = score(dets_b)
    assert s_b["confidence"] > s["confidence"], "baseline должен повышать уверенность"
    _eq("band with-baseline", s_b["band"], "high")

    # Коэффициент полноты δ понижает итог и может опустить полосу доверия.
    s_low = score(dets, delta=0.5)
    _eq("delta halves confidence", s_low["confidence"], round(4.8 / 5.8 * 0.5, 4))
    _eq("delta lowers band", s_low["band"], "low")

    # Гейт значимости: единичный сбойный лог на фоне здорового потока это шум, а не
    # инцидент. Объёмные детекторы (D1, D5, D10, D11) под гейтом не голосуют.
    noise = [{"level": "info", "service": "api", "msg": "ok", "trace_id": f"n{i}"} for i in range(200)]
    noise.append({"level": "error", "service": "worker", "msg": "one flaky timeout",
                  "trace_id": "e1", "error_signal": "timeout", "tenant_id": "T", "job_id": "J"})
    nf = aggregate(noise)
    _eq("noise gate suppresses", _fired_ids(detect(nf)), [])

    # D11 срабатывает при значимой широте поражения (три и более сущности по оси).
    wide = [{"level": "error", "service": "worker", "msg": "fail", "trace_id": f"w{i}",
             "error_signal": "timeout", "tenant_id": f"T{i}", "job_id": f"J{i}"} for i in range(4)]
    _eq("blast fires wide", "D11" in _fired_ids(detect(aggregate(wide))), True)

    # Потолок в тысячу крат: уверенность не превышает 0,999.
    huge = [{"id": "X", "name": "x", "fired": True, "lr": 1e6, "group": "g", "evidence": ""}]
    _eq("ceiling band", score(huge)["band"], "high")
    assert score(huge)["confidence"] <= 0.999, "потолок 0,999 нарушен"

    print("detectors+scoring: all asserts passed")


if __name__ == "__main__":
    main()
