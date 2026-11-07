"""The rate check must measure against the live process, not otgate's memory.

Until v0.2 ``_check_rate`` compared the proposed value only against the last
write otgate itself had let through. Anything else that moved the tag — an
operator at the HMI, a cascade controller, the PLC program, a second agent not
behind the gateway — left the gateway's idea of "current" stale, and a stale
baseline makes an arbitrarily large real jump look like a small legal step.

``test_stale_baseline_cannot_be_used_to_smuggle_a_jump`` is the regression for
that hole and is the reason this file exists. The rest pin the surrounding
behaviour so the fix cannot be quietly reverted or over-tightened.
"""

from __future__ import annotations

import pytest

from conftest import SP, ManualClock, commit_write
from otgate.backends.fake import FakeBackend
from otgate.engine import PolicyEngine
from otgate.models import Action, ActionType, DecisionType
from otgate.policy import parse_policy

pytestmark = pytest.mark.asi02

# A single rate-limited tag: no interlocks, no approval, no cumulative limits,
# so nothing but the rate check can produce a DENY here.
RATE_ONLY = parse_policy(
    [
        {
            "tag": "T",
            "access": "write",
            "value_range": [0, 300],
            "max_rate": 5,
            "rate_interval": 60,
        }
    ]
)


def engine(backend, clock=None):
    return PolicyEngine(RATE_ONLY, backend, clock=clock or ManualClock())


async def test_stale_baseline_cannot_be_used_to_smuggle_a_jump():
    """The regression: a 144-unit jump under a 5-per-60s policy.

    Pre-v0.2 this returned ALLOW. The gateway had recorded 52.0, an operator
    then moved the tag to 200.0 outside the gateway, and a write of 56.0 looked
    like a 4-unit step against the recorded value while actually dropping the
    process by 144 units in one move.
    """
    backend = FakeBackend({"T": 50.0})
    clock = ManualClock()
    eng = engine(backend, clock)

    commit_write(eng, backend, "T", 52.0)

    # Something other than otgate moves the tag. This is the whole point: the
    # gateway is a soft layer and cannot assume it is the only writer that has
    # ever touched the process.
    backend.set("T", 200.0)

    clock.advance(60.0)  # a full interval: a 5-unit step is now allowed

    decision = await eng.evaluate(Action(ActionType.WRITE, "T", 56.0))

    assert decision.type is DecisionType.DENY, (
        "a 144-unit move was allowed because the baseline was otgate's own "
        f"memory (52.0) rather than the live value (200.0): {decision.reason}"
    )
    assert "rate of change too high" in decision.reason
    assert "200" in decision.reason, (
        f"the reason must name the live baseline it judged against: {decision.reason}"
    )


async def test_live_baseline_does_not_block_a_legitimate_step():
    """The fix must not over-tighten: with both baselines agreeing, a step
    inside the allowance still passes."""
    backend = FakeBackend({"T": 50.0})
    clock = ManualClock()
    eng = engine(backend, clock)

    commit_write(eng, backend, "T", 50.0)
    clock.advance(60.0)

    decision = await eng.evaluate(Action(ActionType.WRITE, "T", 54.9))
    assert decision.type is DecisionType.ALLOW, decision.reason


async def test_worse_of_the_two_baselines_wins():
    """History may be the worse baseline — then history must decide.

    The live value drifting *towards* the proposed value must not launder a move
    that is too fast relative to what otgate last commanded.
    """
    backend = FakeBackend({"T": 50.0})
    clock = ManualClock()
    eng = engine(backend, clock)

    commit_write(eng, backend, "T", 50.0)
    backend.set("T", 99.0)  # live is now right next to the proposed value
    clock.advance(60.0)

    decision = await eng.evaluate(Action(ActionType.WRITE, "T", 100.0))
    assert decision.type is DecisionType.DENY, decision.reason
    assert "50" in decision.reason  # judged against the recorded write


async def test_first_write_is_bounded_to_one_interval():
    """With no history there is no time base, so one interval's worth of change
    is granted from the live value — not an unbounded step.

    Pre-v0.2 the check was skipped entirely whenever history was empty, which
    handed the first write after every restart a free jump.
    """
    backend = FakeBackend({"T": 50.0})
    eng = engine(backend)

    too_big = await eng.evaluate(Action(ActionType.WRITE, "T", 80.0))
    assert too_big.type is DecisionType.DENY
    assert "no write history yet" in too_big.reason

    within = await eng.evaluate(Action(ActionType.WRITE, "T", 54.0))
    assert within.type is DecisionType.ALLOW, within.reason


async def test_rate_check_fails_closed_when_the_tag_cannot_be_read():
    """An unverifiable rate baseline denies, exactly like an unverifiable
    interlock. otgate must never turn an outage into a silent success."""
    backend = FakeBackend({"T": 50.0})
    eng = engine(backend)
    commit_write(eng, backend, "T", 50.0)

    backend.set_down(True)
    decision = await eng.evaluate(Action(ActionType.WRITE, "T", 51.0))

    assert decision.type is DecisionType.DENY
    assert "failing closed" in decision.reason


async def test_rate_check_fails_closed_on_a_missing_tag():
    """A tag in the policy but absent from the backend cannot be rate-checked."""
    backend = FakeBackend({"Other": 1.0})
    eng = engine(backend)

    decision = await eng.evaluate(Action(ActionType.WRITE, "T", 51.0))
    assert decision.type is DecisionType.DENY
    assert "failing closed" in decision.reason


async def test_restart_without_persistence_is_still_bounded():
    """The live baseline closes most of the gap that rate-history persistence
    was needed for: a fresh process with an empty history still cannot be
    talked into an unbounded first step.

    Persistence remains worth enabling — it restores the *time base*, so the
    limit is a true rate rather than one-interval-per-restart — but losing it
    is no longer a bypass.
    """
    backend = FakeBackend({"T": 50.0})
    clock = ManualClock()

    first = engine(backend, clock)
    commit_write(first, backend, "T", 50.0)

    clock.advance(1.0)
    restarted = engine(backend, clock)  # brand-new in-memory history

    decision = await restarted.evaluate(Action(ActionType.WRITE, "T", 78.0))
    assert decision.type is DecisionType.DENY, decision.reason
