"""Tool-chain / composition limits (OWASP ASI02).

The per-step checks (value_range, max_rate) can be walked around by an agent
that takes many individually legal steps. These tests prove the cumulative
checks close that hole:

- a salami attack (repeated small in-limit steps) is stopped once total drift
  leaves the allowance;
- a call storm is stopped by the call budget;
- legitimate slow operation still works;
- neither limit is reset by restarting the gateway.
"""

from __future__ import annotations

import pytest

from otgate.backends.fake import FakeBackend
from otgate.engine import PolicyEngine
from otgate.models import Access, Action, ActionType, DecisionType, Policy, Rule
from otgate.policy import PolicyError, parse_policy
from otgate.rate_history import InMemoryRateHistory, JsonlRateHistory

from conftest import commit_write, SP, ManualClock

pytestmark = pytest.mark.asi02


def _drift_policy(**kwargs):
    """A plain-write tag with a cumulative drift allowance of +/-10 over 3600s."""
    defaults = dict(
        tag=SP,
        access=Access.WRITE,
        value_range=(0.0, 500.0),
        cumulative_range=(-10.0, 10.0),
        cumulative_interval=3600.0,
    )
    defaults.update(kwargs)
    return Policy(rules={SP: Rule(**defaults)})


# --- salami attack: many legal steps, illegal total ---

async def test_salami_attack_is_blocked(backend):
    """Repeated small steps are refused once cumulative drift exceeds the range."""
    clock = ManualClock()
    engine = PolicyEngine(
        _drift_policy(), backend, clock=clock, history=InMemoryRateHistory()
    )

    value = 50.0
    commit_write(engine, backend, SP, value)  # baseline inside the window

    # Four steps of +2.5 stay within +/-10 drift.
    for _ in range(4):
        clock.advance(60.0)
        value += 2.5
        decision = await engine.evaluate(Action(ActionType.WRITE, SP, value))
        assert decision.type is DecisionType.ALLOW, decision.reason
        commit_write(engine, backend, SP, value)

    assert value == 60.0  # drifted exactly the allowed 10

    # The next step of the same size is individually tiny, but pushes the total
    # drift past the allowance — this is the attack, and it must be denied.
    clock.advance(60.0)
    decision = await engine.evaluate(Action(ActionType.WRITE, SP, value + 2.5))
    assert decision.type is DecisionType.DENY
    assert "cumulative drift" in decision.reason


async def test_moving_back_towards_baseline_is_allowed(backend):
    """Drift is measured against the baseline, so retreating is never blocked."""
    clock = ManualClock()
    engine = PolicyEngine(
        _drift_policy(), backend, clock=clock, history=InMemoryRateHistory()
    )
    commit_write(engine, backend, SP, 50.0)
    clock.advance(60.0)
    commit_write(engine, backend, SP, 60.0)  # at the edge of the allowance

    clock.advance(60.0)
    decision = await engine.evaluate(Action(ActionType.WRITE, SP, 52.0))
    assert decision.type is DecisionType.ALLOW


async def test_drift_allowance_refreshes_after_window(backend):
    """Once the old writes age out of the window, a new drift budget applies."""
    clock = ManualClock()
    engine = PolicyEngine(
        _drift_policy(), backend, clock=clock, history=InMemoryRateHistory()
    )
    commit_write(engine, backend, SP, 50.0)
    clock.advance(60.0)
    commit_write(engine, backend, SP, 60.0)

    # Long after the window has passed, 60 is the new baseline.
    clock.advance(7200.0)
    decision = await engine.evaluate(Action(ActionType.WRITE, SP, 69.0))
    assert decision.type is DecisionType.ALLOW

    decision = await engine.evaluate(Action(ActionType.WRITE, SP, 75.0))
    assert decision.type is DecisionType.DENY
    assert "cumulative drift" in decision.reason


async def test_no_history_opens_the_window_at_the_live_value(backend):
    """With no series yet, the drift window opens wherever the tag actually is.

    This test previously asserted ALLOW for a write of 400.0 onto a setpoint
    sitting at 55.0, on the reasoning that "there is no baseline to measure
    drift from". That was the hole: a tag carrying a drift allowance had no
    drift check at all until otgate happened to write to it once, so a fresh
    process — or a restart without persisted history — handed the agent an
    unbounded first move.
    """
    clock = ManualClock()
    engine = PolicyEngine(
        _drift_policy(), backend, clock=clock, history=InMemoryRateHistory()
    )
    # SP is live at 55.0 and the allowance is +/-10, so +345 is refused ...
    far = await engine.evaluate(Action(ActionType.WRITE, SP, 400.0))
    assert far.type is DecisionType.DENY
    assert "cumulative drift" in far.reason
    assert "55" in far.reason, f"must name the live baseline: {far.reason}"
    # ... while a move inside the allowance passes.
    near = await engine.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert near.type is DecisionType.ALLOW, near.reason


async def test_cumulative_check_fails_closed_when_the_tag_cannot_be_read(backend):
    """An unverifiable drift baseline denies, like an unverifiable interlock."""
    engine = PolicyEngine(
        _drift_policy(), backend, clock=ManualClock(), history=InMemoryRateHistory()
    )
    backend.set_down(True)
    decision = await engine.evaluate(Action(ActionType.WRITE, SP, 56.0))
    assert decision.type is DecisionType.DENY
    assert "failing closed" in decision.reason


async def test_cumulative_check_fails_closed_on_a_missing_tag():
    """A tag in the policy but absent from the backend has no drift baseline."""
    engine = PolicyEngine(
        _drift_policy(), FakeBackend({"Other": 1.0}), clock=ManualClock(),
        history=InMemoryRateHistory(),
    )
    decision = await engine.evaluate(Action(ActionType.WRITE, SP, 56.0))
    assert decision.type is DecisionType.DENY
    assert "failing closed" in decision.reason


async def test_manual_intervention_does_not_lock_the_agent_out(backend):
    """The deliberate asymmetry with the rate check, pinned.

    Cumulative drift bounds *otgate's own series*, so an operator moving the tag
    by hand must not make every later agent nudge read as a huge drift. Judging
    this check against the live value would lock the agent out of the tag for a
    whole window after any manual intervention. The live value is used only to
    open a window when no series exists.

    A process moved far by something other than otgate is the rate check's job —
    see tests/test_rate_live_baseline.py.
    """
    clock = ManualClock()
    engine = PolicyEngine(
        _drift_policy(), backend, clock=clock, history=InMemoryRateHistory()
    )
    commit_write(engine, backend, SP, 55.0)  # otgate's series starts at 55.0

    backend.set(SP, 75.0)  # an operator moves it 20 units by hand
    clock.advance(10.0)

    # The agent nudges the tag by 1 from where the operator left it. Judged
    # against otgate's own series (55.0) this is +21 and would be refused; the
    # check is explicitly not about that.
    decision = await engine.evaluate(Action(ActionType.WRITE, SP, 76.0))
    assert decision.type is DecisionType.DENY
    assert "cumulative drift" in decision.reason
    assert "55" in decision.reason, (
        "drift must still be measured from otgate's own series, not the live "
        f"value the operator left behind: {decision.reason}"
    )


async def test_cumulative_limit_survives_restart(backend, tmp_path):
    """A restart must not hand the agent a fresh drift budget."""
    path = tmp_path / "rate.jsonl"
    clock = ManualClock()

    engine1 = PolicyEngine(
        _drift_policy(), backend, clock=clock, history=JsonlRateHistory(path)
    )
    commit_write(engine1, backend, SP, 50.0)
    clock.advance(60.0)
    commit_write(engine1, backend, SP, 60.0)

    # Restart: new engine, same persistent history, same window.
    clock.advance(60.0)
    engine2 = PolicyEngine(
        _drift_policy(), backend, clock=clock, history=JsonlRateHistory(path)
    )
    decision = await engine2.evaluate(Action(ActionType.WRITE, SP, 65.0))
    assert decision.type is DecisionType.DENY
    assert "cumulative drift" in decision.reason


# --- call budget: storms and recursion ---

def _budget_policy(max_calls=3, calls_interval=60.0):
    return Policy(
        rules={
            SP: Rule(
                tag=SP,
                access=Access.WRITE,
                value_range=(0.0, 500.0),
                max_calls=max_calls,
                calls_interval=calls_interval,
            )
        }
    )


async def test_call_storm_is_blocked(backend):
    clock = ManualClock()
    engine = PolicyEngine(
        _budget_policy(), backend, clock=clock, history=InMemoryRateHistory()
    )

    for i in range(3):
        clock.advance(1.0)
        decision = await engine.evaluate(Action(ActionType.WRITE, SP, 50.0 + i))
        assert decision.type is DecisionType.ALLOW
        commit_write(engine, backend, SP, 50.0 + i)

    clock.advance(1.0)
    decision = await engine.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert decision.type is DecisionType.DENY
    assert "call budget" in decision.reason


async def test_call_budget_refreshes_after_interval(backend):
    clock = ManualClock()
    engine = PolicyEngine(
        _budget_policy(), backend, clock=clock, history=InMemoryRateHistory()
    )
    for i in range(3):
        commit_write(engine, backend, SP, 50.0 + i)

    assert (await engine.evaluate(Action(ActionType.WRITE, SP, 60.0))).type is DecisionType.DENY

    clock.advance(61.0)  # the whole window ages out
    decision = await engine.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert decision.type is DecisionType.ALLOW


async def test_call_budget_survives_restart(backend, tmp_path):
    path = tmp_path / "rate.jsonl"
    clock = ManualClock()
    engine1 = PolicyEngine(
        _budget_policy(), backend, clock=clock, history=JsonlRateHistory(path)
    )
    for i in range(3):
        commit_write(engine1, backend, SP, 50.0 + i)

    engine2 = PolicyEngine(
        _budget_policy(), backend, clock=clock, history=JsonlRateHistory(path)
    )
    decision = await engine2.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert decision.type is DecisionType.DENY
    assert "call budget" in decision.reason


# --- policy validation ---

def test_cumulative_range_requires_interval():
    with pytest.raises(PolicyError, match="requires 'cumulative_interval'"):
        parse_policy([{"tag": "t", "access": "write", "cumulative_range": [-5, 5]}])


def test_cumulative_interval_without_range():
    with pytest.raises(PolicyError, match="without 'cumulative_range'"):
        parse_policy([{"tag": "t", "access": "write", "cumulative_interval": 60}])


def test_cumulative_range_must_include_zero():
    with pytest.raises(PolicyError, match="must include 0"):
        parse_policy(
            [{"tag": "t", "access": "write",
              "cumulative_range": [5, 10], "cumulative_interval": 60}]
        )


def test_max_calls_requires_interval():
    with pytest.raises(PolicyError, match="requires 'calls_interval'"):
        parse_policy([{"tag": "t", "access": "write", "max_calls": 5}])


def test_max_calls_must_be_integer():
    with pytest.raises(PolicyError, match="must be an integer"):
        parse_policy(
            [{"tag": "t", "access": "write", "max_calls": 2.5, "calls_interval": 60}]
        )


def test_max_calls_must_be_positive():
    with pytest.raises(PolicyError, match="must be positive"):
        parse_policy(
            [{"tag": "t", "access": "write", "max_calls": 0, "calls_interval": 60}]
        )


def test_valid_cumulative_policy_parses():
    policy = parse_policy(
        [{
            "tag": "t",
            "access": "write",
            "cumulative_range": [-10, 10],
            "cumulative_interval": 3600,
            "max_calls": 20,
            "calls_interval": 600,
        }]
    )
    rule = policy.get("t")
    assert rule.cumulative_range == (-10.0, 10.0)
    assert rule.cumulative_interval == 3600.0
    assert rule.max_calls == 20
    assert rule.calls_interval == 600.0
