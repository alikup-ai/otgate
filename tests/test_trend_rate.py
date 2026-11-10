"""The recorded-history rate check (``history_rate``), against a fake historian.

The defect this closes, in one sentence: otgate's two rate baselines — the live
value and the last write it let through — are *points*, so movement that
happened and ended between them is invisible. The first test here is that
scenario end to end, and it is the only test in this file that would have
passed before the check existed.

A fake :class:`~otgate.trend.ProcessTrend` is used rather than ottrend, for two
reasons: these tests are about the engine's use of the answer (what it asks,
when it asks, what it does with a refusal), and the unit suite must keep
running with no historian stack installed. The same check driven by real
ottrend is in ``test_trend_ottrend.py``.
"""

from __future__ import annotations

import pytest

from otgate.backends.fake import FakeBackend
from otgate.engine import PolicyEngine
from otgate.models import Access, Action, ActionType, DecisionType, Policy, Rule
from otgate.policy import parse_policy
from otgate.trend import HistoryUnavailable, ObservedMovement

from conftest import ManualClock

TAG = "ns=2;s=Reactor.TIC101.SP"


class FakeTrend:
    """Answers with whatever the test planted, and remembers being asked."""

    def __init__(self, answer=None, *, raises: Exception | None = None) -> None:
        self.answer = answer
        self.raises = raises
        self.calls: list[tuple[str, float, float]] = []
        self.closed = False

    async def observed_movement(self, tag, *, window, bucket):
        self.calls.append((tag, window, bucket))
        if self.raises is not None:
            raise self.raises
        return self.answer

    async def close(self) -> None:
        self.closed = True


def movement(rate_per_interval: float, *, at="2026-11-08T07:59:00+00:00", bucket=6.0):
    return ObservedMovement(
        rate_per_interval=rate_per_interval,
        bucket=bucket,
        good_fraction=1.0,
        at=at,
    )


def nothing_recorded(bucket=6.0):
    return ObservedMovement(
        rate_per_interval=0.0, bucket=bucket, good_fraction=0.0, at=None, recorded=False
    )


def policy_for(**overrides) -> Policy:
    rule = Rule(
        tag=TAG,
        access=Access.WRITE,
        max_rate=5.0,
        rate_interval=60.0,
        **overrides,
    )
    return Policy(rules={TAG: rule})


def engine_for(policy, trend=None, *, live=50.0, clock=None):
    backend = FakeBackend({TAG: live})
    return (
        PolicyEngine(
            policy, backend, clock=clock or ManualClock(), trend=trend
        ),
        backend,
    )


async def write(engine, value=52.0, tag=TAG):
    return await engine.evaluate(Action(ActionType.WRITE, tag, value))


# --- the defect ------------------------------------------------------------
@pytest.mark.asi02
async def test_a_ramp_that_came_and_went_is_now_visible():
    """The whole point, in one test.

    An operator ramps the setpoint 50 -> 194 -> 50 on the HMI inside one rate
    interval. otgate wrote nothing, so there is no record; the live value reads
    50 again, so the proposed +2 looks like a 2-unit step. Every check otgate
    had before this one passes it.

    With the historian asked, the same write is refused — and the reason names
    the evidence, so an operator can go and look at the trend.
    """
    blind = engine_for(policy_for())[0]
    assert (await write(blind)).type is DecisionType.ALLOW

    trend = FakeTrend(movement(1440.0))  # 144 units inside a 6 s bucket
    seeing = engine_for(policy_for(history_rate=True), trend)[0]
    decision = await write(seeing)

    assert decision.type is DecisionType.DENY
    assert "the process itself is moving too fast" in decision.reason
    assert "1440" in decision.reason
    assert "2026-11-08T07:59:00+00:00" in decision.reason, "point a human at it"
    assert "bucket 6s" in decision.reason, "and say how sharp the number was"


async def test_a_calm_history_does_not_block_a_legal_write():
    trend = FakeTrend(movement(1.0))
    engine = engine_for(policy_for(history_rate=True), trend)[0]

    assert (await write(engine)).type is DecisionType.ALLOW


async def test_a_rate_exactly_at_the_limit_is_not_over_it():
    trend = FakeTrend(movement(5.0))
    engine = engine_for(policy_for(history_rate=True), trend)[0]

    assert (await write(engine)).type is DecisionType.ALLOW


# --- what gets asked, and when ---------------------------------------------
async def test_the_window_is_the_rate_interval_and_the_bucket_a_tenth_of_it():
    """Movement from an hour ago is not a rate over this interval."""
    trend = FakeTrend(movement(1.0))
    engine = engine_for(policy_for(history_rate=True), trend)[0]

    await write(engine)

    assert trend.calls == [(TAG, 60.0, 6.0)]


async def test_an_explicit_bucket_is_honoured():
    trend = FakeTrend(movement(1.0))
    engine = engine_for(policy_for(history_rate=True, history_bucket=2.0), trend)[0]

    await write(engine)

    assert trend.calls == [(TAG, 60.0, 2.0)]


async def test_the_historian_is_asked_about_history_tag_when_it_differs():
    """The historian addresses a tag its own way: a PI path, an Ignition path."""
    trend = FakeTrend(movement(1.0))
    engine = engine_for(
        policy_for(history_rate=True, history_tag=r"\\PISERVER\TIC101.SP"), trend
    )[0]

    await write(engine)

    assert trend.calls[0][0] == r"\\PISERVER\TIC101.SP"


async def test_a_tag_without_history_rate_costs_no_round_trip():
    """Opt-in per tag: the check is not free, so it is not implicit."""
    trend = FakeTrend(movement(1440.0))
    engine = engine_for(policy_for(), trend)[0]

    assert (await write(engine)).type is DecisionType.ALLOW
    assert trend.calls == []


async def test_a_write_already_refused_does_not_reach_the_historian():
    """First failing check wins, and a denial needs no further evidence."""
    trend = FakeTrend(movement(1.0))
    engine = engine_for(policy_for(history_rate=True), trend, live=50.0)[0]

    decision = await write(engine, value=500.0)  # far outside max_rate per step

    assert decision.type is DecisionType.DENY
    assert "rate of change too high" in decision.reason
    assert trend.calls == [], "no round trip spent on an already-denied write"


async def test_a_boolean_write_does_not_reach_the_historian():
    trend = FakeTrend(movement(1440.0))
    engine = engine_for(policy_for(history_rate=True), trend)[0]

    await write(engine, value=True)

    assert trend.calls == []


# --- failing closed --------------------------------------------------------
async def test_an_unreachable_historian_denies_rather_than_skips():
    """Same rule as an unverifiable interlock: no evidence, no write."""
    trend = FakeTrend(raises=HistoryUnavailable("historian unreachable: timed out"))
    engine = engine_for(policy_for(history_rate=True), trend)[0]

    decision = await write(engine)

    assert decision.type is DecisionType.DENY
    assert "could not be checked against recorded history" in decision.reason
    assert "failing closed" in decision.reason
    assert "timed out" in decision.reason, "say what went wrong, not just that it did"


async def test_nothing_on_record_is_an_answer_not_a_failure():
    """A quiet tag must not become an unwritable tag.

    Historians store on change. A setpoint nobody has touched for an hour has
    no samples in the last minute, and that is evidence of calm, not a broken
    historian — the other checks decide.
    """
    trend = FakeTrend(nothing_recorded())
    engine = engine_for(policy_for(history_rate=True), trend)[0]

    assert (await write(engine)).type is DecisionType.ALLOW


async def test_an_engine_without_a_historian_refuses_to_start():
    """A check that silently does not run is worse than a missing check.

    The policy says this tag is judged against recorded history. If no
    historian is configured, that is a deployment error, and it surfaces at
    startup rather than as a quietly weaker policy per write.
    """
    with pytest.raises(ValueError, match="history_rate"):
        PolicyEngine(policy_for(history_rate=True), FakeBackend({TAG: 50.0}))


async def test_an_engine_assembled_without_the_guard_still_fails_closed():
    """Belt and braces for an engine built some other way."""
    engine, _ = engine_for(policy_for(history_rate=True), FakeTrend(movement(1.0)))
    engine._trend = None  # noqa: SLF001 - simulating a mis-assembled engine

    decision = await write(engine)

    assert decision.type is DecisionType.DENY
    assert "no historian is configured" in decision.reason


# --- the policy surface ----------------------------------------------------
def test_history_rate_needs_a_rate_limit_to_measure_against():
    with pytest.raises(Exception, match="requires 'max_rate'"):
        parse_policy([{"tag": TAG, "access": "write", "history_rate": True}])


def test_history_keys_without_the_check_are_an_error_not_a_shrug():
    """A key with no effect is how a policy ends up weaker than it reads."""
    with pytest.raises(Exception, match="has no effect"):
        parse_policy([{"tag": TAG, "access": "write", "history_tag": "X"}])


def test_a_bucket_larger_than_the_window_is_rejected():
    with pytest.raises(Exception, match="must not exceed"):
        parse_policy([
            {
                "tag": TAG,
                "access": "write",
                "max_rate": 5,
                "rate_interval": 60,
                "history_rate": True,
                "history_bucket": 120,
            }
        ])


def test_history_rate_must_be_a_boolean():
    with pytest.raises(Exception, match="must be true or false"):
        parse_policy([
            {
                "tag": TAG,
                "access": "write",
                "max_rate": 5,
                "rate_interval": 60,
                "history_rate": "yes",
            }
        ])


def test_a_policy_with_the_check_round_trips_through_yaml():
    policy = parse_policy([
        {
            "tag": TAG,
            "access": "write",
            "max_rate": 5,
            "rate_interval": 60,
            "history_rate": True,
            "history_tag": "ns=4;s=TIC101.SP",
            "history_bucket": 3,
        }
    ])
    rule = policy.get(TAG)

    assert rule is not None
    assert rule.history_rate is True
    assert rule.history_source == "ns=4;s=TIC101.SP"
    assert rule.history_bucket_seconds == 3.0


def test_the_default_bucket_is_derived_from_the_interval():
    rule = Rule(tag=TAG, access=Access.WRITE, max_rate=5.0, rate_interval=30.0)
    assert rule.history_bucket_seconds == 3.0
    assert rule.history_source == TAG


# --- through the gateway ---------------------------------------------------
async def test_the_gateway_audits_a_history_denial(tmp_path):
    """The denial has to reach the audit trail like any other."""
    from otgate.audit import AuditLog
    from otgate.gateway import Gateway

    audit = AuditLog(tmp_path / "audit.jsonl")
    trend = FakeTrend(movement(1440.0))
    gateway = Gateway(
        policy_for(history_rate=True),
        FakeBackend({TAG: 50.0}),
        audit,
        trend=trend,
    )

    result = await gateway.write(TAG, 52.0)
    await gateway.aclose()

    assert result.decision.type is DecisionType.DENY
    assert result.executed is False
    assert trend.closed is True, "aclose must release the historian's session"
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert "the process itself is moving too fast" in lines[-1]
