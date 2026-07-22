"""Engine tests — one per policy rule, per the spec's test checklist."""

from __future__ import annotations

import pytest

from otgate.engine import PolicyEngine
from otgate.models import (
    Access,
    Action,
    ActionType,
    DecisionType,
    Interlock,
    Policy,
    Rule,
)

from conftest import ESD, PV, SP, ManualClock


def make_engine(policy, backend, clock=None):
    return PolicyEngine(policy, backend, clock=clock or (lambda: 0.0))


async def test_write_in_range_reaches_approval(policy, backend):
    """A setpoint inside the range clears range/interlock/rate and asks for approval."""
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert d.type is DecisionType.ASK


async def test_write_out_of_range_denied(policy, backend):
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 200.0))
    assert d.type is DecisionType.DENY
    assert "range" in d.reason


async def test_write_below_range_denied(policy, backend):
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 10.0))
    assert d.type is DecisionType.DENY
    assert "range" in d.reason


async def test_interlock_active_denied(policy, backend):
    backend.set(ESD, True)
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert d.type is DecisionType.DENY
    assert "interlock" in d.reason


async def test_interlock_inactive_does_not_block(policy, backend):
    backend.set(ESD, False)
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert d.type is DecisionType.ASK  # only blocked by approval, not interlock


async def test_max_rate_exceeded_denied(policy, backend):
    clock = ManualClock()
    eng = PolicyEngine(policy, backend, clock=clock)
    # Establish history via a first executed write.
    eng.record_write(SP, 50.0)
    clock.advance(1.0)  # 1 second later
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 75.0))  # +25 in 1s
    assert d.type is DecisionType.DENY
    assert "rate" in d.reason


async def test_max_rate_within_limit_ok(policy, backend):
    clock = ManualClock()
    eng = PolicyEngine(policy, backend, clock=clock)
    eng.record_write(SP, 50.0)
    clock.advance(1.0)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 50.05))  # tiny change
    assert d.type is DecisionType.ASK  # passes rate, then asks


async def test_rate_allows_full_step_after_interval(policy, backend):
    clock = ManualClock()
    eng = PolicyEngine(policy, backend, clock=clock)
    eng.record_write(SP, 50.0)
    clock.advance(60.0)  # a full rate_interval later
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 54.9))  # +4.9 <= 5
    assert d.type is DecisionType.ASK


async def test_first_write_no_history_not_rate_limited(policy, backend):
    eng = PolicyEngine(policy, backend)
    # No prior write recorded; a big-but-in-range value must not be rate-denied.
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 80.0))
    assert d.type is DecisionType.ASK


async def test_write_with_approval_asks(policy, backend):
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 55.0))
    assert d.type is DecisionType.ASK


async def test_write_readonly_tag_denied(policy, backend):
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, PV, 60.0))
    assert d.type is DecisionType.DENY
    assert "read-only" in d.reason


async def test_write_tag_not_in_policy_denied(policy, backend):
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, "ns=2;s=Unknown", 1.0))
    assert d.type is DecisionType.DENY
    assert "policy" in d.reason


async def test_plain_write_access_allows(backend):
    """An access=write tag with no other constraints yields ALLOW, not ASK."""
    p = Policy(rules={SP: Rule(tag=SP, access=Access.WRITE, value_range=(40.0, 80.0))})
    eng = PolicyEngine(p, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert d.type is DecisionType.ALLOW


async def test_read_allowed(policy, backend):
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.READ, PV))
    assert d.type is DecisionType.ALLOW


async def test_read_tag_not_in_policy_denied(policy, backend):
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.READ, "ns=2;s=Unknown"))
    assert d.type is DecisionType.DENY


async def test_read_deny_access(backend):
    p = Policy(rules={SP: Rule(tag=SP, access=Access.DENY)})
    eng = PolicyEngine(p, backend)
    d = await eng.evaluate(Action(ActionType.READ, SP))
    assert d.type is DecisionType.DENY


async def test_interlock_missing_tag_fails_closed(backend):
    p = Policy(
        rules={
            SP: Rule(
                tag=SP,
                access=Access.WRITE,
                interlocks=(Interlock("ns=2;s=Missing", "==", True),),
            )
        }
    )
    eng = PolicyEngine(p, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 60.0))
    assert d.type is DecisionType.DENY
    assert "unavailable" in d.reason


async def test_check_order_range_before_interlock(policy, backend):
    """Out-of-range wins even when an interlock would also fire."""
    backend.set(ESD, True)
    eng = PolicyEngine(policy, backend)
    d = await eng.evaluate(Action(ActionType.WRITE, SP, 200.0))
    assert d.type is DecisionType.DENY
    assert "range" in d.reason  # range check precedes interlock check
