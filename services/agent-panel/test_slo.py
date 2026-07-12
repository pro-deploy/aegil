"""Тесты целей уровня обслуживания и бюджета ошибок. Собираемый вид pytest.

Запуск: cd services/agent-panel && python3 -m pytest -q test_slo.py
"""
import slo


def test_disabled_without_target():
    # Без объявленной цани SLO слой выключен и гейт никого не сдерживает.
    st = slo.evaluate(0.5, tgt=None)
    assert st["enabled"] is False
    assert st["severity"] == slo.OK
    assert slo.gate(st, mode=slo.GATE_CRITICAL) is True


def test_burn_rate_severity_bands():
    # Цель 0.99 даёт бюджет ошибок 0.01. Скорость прожигания это доля ошибок делить на бюджет.
    assert slo.evaluate(0.005, tgt=0.99)["severity"] == slo.OK          # burn 0.5
    at = slo.evaluate(0.07, tgt=0.99)                                    # burn 7 >= 6
    assert at["severity"] == slo.AT_RISK
    assert at["burn_rate"] == 7.0
    crit = slo.evaluate(0.2, tgt=0.99)                                   # burn 20 >= 14.4
    assert crit["severity"] == slo.CRITICAL
    assert crit["breached"] is True


def test_gate_modes():
    ok = slo.evaluate(0.001, tgt=0.99)      # OK
    risk = slo.evaluate(0.07, tgt=0.99)     # AT_RISK
    crit = slo.evaluate(0.2, tgt=0.99)      # CRITICAL
    # off: никогда не сдерживает.
    assert slo.gate(ok, mode=slo.GATE_OFF) is True
    # at_risk: разрешает при умеренном и быстром прожиге, но не при спокойном.
    assert slo.gate(ok, mode=slo.GATE_AT_RISK) is False
    assert slo.gate(risk, mode=slo.GATE_AT_RISK) is True
    assert slo.gate(crit, mode=slo.GATE_AT_RISK) is True
    # critical: разрешает только при быстром прожиге.
    assert slo.gate(risk, mode=slo.GATE_CRITICAL) is False
    assert slo.gate(crit, mode=slo.GATE_CRITICAL) is True


def test_sli_is_one_minus_error_rate():
    st = slo.evaluate(0.03, tgt=0.99)
    assert st["sli"] == 0.97
    assert st["error_budget"] == 0.01
