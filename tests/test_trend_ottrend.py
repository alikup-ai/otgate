"""The same check driven by real ottrend, over its in-memory historian.

``test_trend_rate.py`` proves the engine uses a historian's answer correctly.
This file proves the answers are real: ottrend's ``max_rate`` over
``MemoryTrend``, with an operator's ramp planted in the history exactly as a
historian would have recorded it. Nothing is stubbed between the policy and
the trend data.

``MemoryTrend`` is ottrend's reference semantics — the thing its own OPC UA,
PI and Ignition adapters are tested against — so a check that behaves
correctly here behaves correctly against a plant historian that answers the
same three primitives.

Skipped automatically when ottrend is not installed::

    pip install "otgate[history]"
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

pytest.importorskip("ottrend")

from ottrend import MemoryTrend, Quality, Sample, UnsupportedQuery  # noqa: E402

from otgate.audit import AuditLog  # noqa: E402
from otgate.backends.fake import FakeBackend  # noqa: E402
from otgate.engine import PolicyEngine  # noqa: E402
from otgate.gateway import Gateway  # noqa: E402
from otgate.models import Access, Action, ActionType, DecisionType, Policy, Rule  # noqa: E402
from otgate.trend import HistoryUnavailable, OttrendTrend  # noqa: E402

from conftest import ManualClock  # noqa: E402

pytestmark = pytest.mark.history

TAG = "ns=2;s=Reactor.TIC101.SP"
HIST = "ns=2;s=Reactor.TIC101.SP"
START = 1_793_000_000.0  # a fixed wall clock, so the planted history is exact


def at(offset: float) -> datetime:
    """Wall-clock ``START + offset`` seconds, as the historian would stamp it."""
    return datetime.fromtimestamp(START + offset, tz=timezone.utc)


def history(*points: tuple[float, float], quality: Quality = Quality.GOOD) -> MemoryTrend:
    return MemoryTrend({HIST: [Sample(at(o), v, quality) for o, v in points]})


#: An operator ramp on the HMI: 50 up to 194 and back, inside six seconds,
#: half a minute ago. This is the fourth episode of otgate's demo animation
#: and the subject of the write-up: a 144-unit move the gateway never saw.
OPERATOR_RAMP = ((-30.0, 50.0), (-28.0, 194.0), (-26.0, 50.0))


class CountingTrend(MemoryTrend):
    """MemoryTrend that counts the round trips an answer cost."""

    def __init__(self, source: MemoryTrend) -> None:
        super().__init__()
        self._series = source._series  # noqa: SLF001 - sharing planted history
        self.buckets_calls = 0
        self.raw_calls = 0

    async def buckets(self, *args, **kwargs):
        self.buckets_calls += 1
        return await super().buckets(*args, **kwargs)

    async def raw(self, *args, **kwargs):
        self.raw_calls += 1
        return await super().raw(*args, **kwargs)


def rule(**overrides) -> Rule:
    return Rule(
        tag=TAG,
        access=Access.WRITE,
        max_rate=5.0,
        rate_interval=60.0,
        history_rate=True,
        **overrides,
    )


def setup(trend_data: MemoryTrend, *, live=50.0, clock=None, **rule_kwargs):
    clock = clock or ManualClock(START)
    policy = Policy(rules={TAG: rule(**rule_kwargs)})
    trend = OttrendTrend(trend_data, clock=clock)
    engine = PolicyEngine(
        policy, FakeBackend({TAG: live}), clock=clock, trend=trend
    )
    return engine, trend, clock


async def write(engine, value=52.0):
    return await engine.evaluate(Action(ActionType.WRITE, TAG, value))


# --- the scenario ----------------------------------------------------------
@pytest.mark.asi02
async def test_the_operator_ramp_is_refused_through_real_ottrend():
    engine, _, _ = setup(history(*OPERATOR_RAMP))

    decision = await write(engine)

    assert decision.type is DecisionType.DENY
    assert "the process itself is moving too fast" in decision.reason
    # 144 units inside one 6 s bucket is 24/s, i.e. 1440 per 60 s.
    assert "1440" in decision.reason


async def test_the_denial_lifts_once_the_movement_ages_out_of_the_window():
    """The check bounds a rate, so it is self-clearing. No operator action."""
    engine, _, clock = setup(history(*OPERATOR_RAMP))

    assert (await write(engine)).type is DecisionType.DENY

    clock.advance(120.0)  # the ramp is now outside the 60 s window

    assert (await write(engine)).type is DecisionType.ALLOW


async def test_a_quiet_tag_stays_writable():
    """Historians store on change: nothing in the window is calm, not broken."""
    engine, _, _ = setup(history((-3600.0, 50.0)))

    assert (await write(engine)).type is DecisionType.ALLOW


async def test_a_slow_real_ramp_is_allowed():
    """2 units over a minute is within "5 per 60 s" and must stay allowed."""
    engine, _, _ = setup(
        history((-60.0, 50.0), (-40.0, 50.7), (-20.0, 51.3), (-1.0, 52.0))
    )

    assert (await write(engine)).type is DecisionType.ALLOW


# --- quality and failure ---------------------------------------------------
async def test_a_window_of_bad_data_fails_closed():
    """An envelope judged on bad data is worse than none: it looks like one."""
    engine, _, _ = setup(history(*OPERATOR_RAMP, quality=Quality.BAD))

    decision = await write(engine)

    assert decision.type is DecisionType.DENY
    assert "could not be checked against recorded history" in decision.reason
    assert "good data" in decision.reason


async def test_an_unreachable_historian_fails_closed():
    data = history(*OPERATOR_RAMP)
    data.set_down(True)
    engine, _, _ = setup(data)

    decision = await write(engine)

    assert decision.type is DecisionType.DENY
    assert "failing closed" in decision.reason


async def test_a_history_tag_the_historian_does_not_have_fails_closed():
    """A misconfigured history_tag must not quietly disable the check."""
    engine, _, _ = setup(history(*OPERATOR_RAMP), history_tag="ns=2;s=Nope")

    decision = await write(engine)

    assert decision.type is DecisionType.DENY
    assert "UnknownTag" in decision.reason


# --- which refusals are worth asking again --------------------------------
# All four deny the write. They differ in what an operator holding a parked
# approval should be told: wait and try again, or no. A historian that was
# unreachable or a window too thin to judge can answer differently in a
# minute; a tag that does not exist and a query the adapter cannot express
# cannot, and a request left pending on those two never resolves.


class CannotAggregate(MemoryTrend):
    """A historian that keeps samples but cannot bucket them."""

    async def buckets(self, *args, **kwargs):
        raise UnsupportedQuery("this historian cannot aggregate")


async def ask(provider) -> HistoryUnavailable:
    with pytest.raises(HistoryUnavailable) as caught:
        await OttrendTrend(provider, clock=ManualClock(START)).observed_movement(
            HIST, window=60.0, bucket=6.0
        )
    return caught.value


async def test_an_unreachable_historian_is_worth_asking_again():
    data = history(*OPERATOR_RAMP)
    data.set_down(True)

    assert (await ask(data)).retryable is True


async def test_a_window_of_bad_data_is_worth_asking_again():
    """Thin now, perhaps not in a minute: historians write on change."""
    refusal = await ask(history(*OPERATOR_RAMP, quality=Quality.BAD))

    assert refusal.retryable is True
    assert "good data" in str(refusal)


async def test_an_unknown_history_tag_is_not_worth_asking_again():
    """A healthy historian asked for a tag it has never held: the reason is
    the policy's ``history_tag``, so it will be identical next time."""
    trend = OttrendTrend(history(*OPERATOR_RAMP), clock=ManualClock(START))

    with pytest.raises(HistoryUnavailable) as caught:
        await trend.observed_movement("ns=2;s=Nope", window=60.0, bucket=6.0)

    assert caught.value.retryable is False
    assert "UnknownTag" in str(caught.value)


async def test_a_query_the_adapter_cannot_express_is_not_worth_asking_again():
    refusal = await ask(CannotAggregate({HIST: [Sample(at(-30.0), 50.0, Quality.GOOD)]}))

    assert refusal.retryable is False
    assert "UnsupportedQuery" in str(refusal)


def test_a_foreign_trend_implementation_defaults_to_no_retry():
    """Only an implementation that knows a retry helps may claim it."""
    assert HistoryUnavailable("some other historian").retryable is False


# --- the bucket is the sharpness ------------------------------------------
async def test_a_finer_bucket_sees_a_faster_move():
    """ottrend's answer is a lower bound, and the bucket is what bounds it.

    The same 144-unit ramp measured at 6 s reads as 1440 per minute; measured
    with one bucket covering the whole window it reads as 144, the span. Both
    refuse this write, but the finer answer is the truer one — which is why
    the reason always names the bucket it used.
    """
    data = history(*OPERATOR_RAMP)
    fine = OttrendTrend(data, clock=ManualClock(START))
    coarse = OttrendTrend(data, clock=ManualClock(START))

    sharp = await fine.observed_movement(HIST, window=60.0, bucket=6.0)
    blunt = await coarse.observed_movement(HIST, window=60.0, bucket=60.0)

    assert sharp.rate_per_interval == pytest.approx(1440.0)
    assert blunt.rate_per_interval == pytest.approx(144.0)
    assert sharp.rate_per_interval > blunt.rate_per_interval
    assert sharp.bucket == 6.0 and blunt.bucket == 60.0
    assert sharp.recorded is True
    assert sharp.at == at(-30.0).isoformat(), "points at the bucket of the ramp"


async def test_nothing_recorded_is_distinguished_from_a_refusal():
    """The two ottrend reports the same way; the verdict differs, so we probe."""
    quiet = OttrendTrend(history((-3600.0, 50.0)), clock=ManualClock(START))
    observed = await quiet.observed_movement(HIST, window=60.0, bucket=6.0)

    assert observed.recorded is False
    assert observed.rate_per_interval == 0.0


# --- through the gateway ---------------------------------------------------
async def test_the_gateway_refuses_and_audits_the_real_scenario(tmp_path):
    clock = ManualClock(START)
    audit = AuditLog(tmp_path / "audit.jsonl")
    gateway = Gateway(
        Policy(rules={TAG: rule()}),
        FakeBackend({TAG: 50.0}),
        audit,
        trend=OttrendTrend(history(*OPERATOR_RAMP), clock=clock),
    )

    result = await gateway.write(TAG, 52.0)
    await gateway.aclose()

    assert result.decision.type is DecisionType.DENY
    assert result.executed is False
    assert "moving too fast" in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


async def test_the_check_is_one_question_per_write():
    """It is on the hot path of every write to a history-checked tag.

    ottrend's max_rate costs two reads (min and max buckets) plus, only when
    the window looks empty, one probe. Three round trips in the worst case and
    two in the normal one is the budget this check is allowed.
    """
    counted = CountingTrend(history(*OPERATOR_RAMP))
    engine, _, _ = setup(counted)

    await write(engine)

    assert counted.buckets_calls == 2
    assert counted.raw_calls == 0


class CountingTrend(MemoryTrend):
    """MemoryTrend that counts the round trips an answer cost."""

    def __init__(self, source: MemoryTrend) -> None:
        super().__init__()
        self._series = source._series  # noqa: SLF001 - sharing planted history
        self.buckets_calls = 0
        self.raw_calls = 0

    async def buckets(self, *args, **kwargs):
        self.buckets_calls += 1
        return await super().buckets(*args, **kwargs)

    async def raw(self, *args, **kwargs):
        self.raw_calls += 1
        return await super().raw(*args, **kwargs)

