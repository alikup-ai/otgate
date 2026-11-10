"""The policy engine — the core of otgate.

:func:`PolicyEngine.evaluate` turns a requested :class:`~otgate.models.Action`
into a :class:`~otgate.models.Decision` (ALLOW / DENY / ASK) with a
human-readable ``reason``, applying the process-aware checks that make otgate
more than a text guardrail: access level, value range, interlocks and rate of
change.

Write check order (first failing check wins):

1. Tag not in policy               -> DENY  ("tag not in policy")
2. access == deny / access == read -> DENY
3. value_range violated            -> DENY
4. any interlock fires             -> DENY
5. max_rate exceeded (per step)    -> DENY
5b. the tag's own recorded rate is already over max_rate -> DENY
    (only when the rule sets ``history_rate`` and a historian is configured)
6. cumulative_range exceeded       -> DENY  (series of steps, salami attacks)
7. max_calls exhausted             -> DENY  (call storms)
8. access == write_with_approval   -> ASK
9. otherwise                       -> ALLOW

Reads: tag in policy and access != deny -> ALLOW, else DENY.

Rate of change is measured against the **live value of the tag**, read from the
backend at check time, and — when a prior write through this engine is on record
— against that write as well, taking whichever gives the larger delta. Reading
the live value is what makes the check hold when something other than otgate
moves the tag (an operator at the HMI, a cascade controller, the PLC program,
another agent). A tag that cannot be read fails closed, exactly like an
unverifiable interlock.

Both of those baselines are *points*, and that is their limit: they say nothing
about what the tag did between them. A tag ramped hard on the HMI and put back
before the next write looks untouched to both. Step 5b closes that by asking a
historian how fast the tag has actually been moving over the rate interval and
holding *the process* to the same limit — the only check whose evidence comes
from outside the gateway entirely. It is opt-in per tag (``history_rate``),
costs a round trip, and can only ever *refuse* a write: the recorded rate is a
lower bound on the truth, so "too fast" is definitive while "slow enough" is
not. See :mod:`otgate.trend`.

Cumulative drift deliberately differs: it bounds **the series otgate itself let
through**, because that is a question about the agent, not about the process.
Judging it against the live value would lock the agent out of a tag for a whole
window after any manual intervention. The live value is used only to open the
window when no series exists yet — which is also fail-closed if it cannot be
read. See :meth:`PolicyEngine._check_cumulative` for the full reasoning.
"""

from __future__ import annotations

import time

from otgate.backends.base import Backend, BackendError, BackendPolicyDenied
from otgate.models import (
    Access,
    Action,
    ActionType,
    Decision,
    DecisionType,
    Policy,
    Rule,
    Scalar,
)
from otgate.rate_history import InMemoryRateHistory, RateHistory, WriteRecord
from otgate.trend import HistoryUnavailable, ProcessTrend


class PolicyEngine:
    """Evaluates actions against a policy and a backend.

    Args:
        policy: the loaded policy.
        backend: the backend, used to read current tag values needed for
            interlock and rate checks.
        clock: wall-clock time source (seconds since the epoch). Injectable for
            deterministic tests; defaults to :func:`time.time`. Wall-clock (not
            monotonic) so rate history survives restarts — see
            :mod:`otgate.rate_history`.
        history: storage for the last allowed write per tag. Defaults to a
            non-persistent :class:`~otgate.rate_history.InMemoryRateHistory`;
            pass a :class:`~otgate.rate_history.JsonlRateHistory` to make the
            rate limit durable across restarts.
        trend: a historian (see :mod:`otgate.trend`), required if any rule in
            the policy sets ``history_rate``.

    Raises:
        ValueError: if the policy asks for recorded-history rate checks and no
            historian was given. Discovering that at startup is the point: a
            check that silently does not run is a policy weaker than the
            operator who wrote it believes.
    """

    def __init__(
        self,
        policy: Policy,
        backend: Backend,
        clock=time.time,
        history: RateHistory | None = None,
        trend: ProcessTrend | None = None,
    ) -> None:
        self._policy = policy
        self._backend = backend
        self._clock = clock
        self._history: RateHistory = history or InMemoryRateHistory()
        self._trend = trend
        if trend is None:
            asking = sorted(
                tag for tag, rule in policy.rules.items() if rule.history_rate
            )
            if asking:
                raise ValueError(
                    "policy sets history_rate on "
                    f"{', '.join(asking)} but no historian is configured; "
                    "pass trend= (see otgate.trend) or remove history_rate"
                )

    async def evaluate(self, action: Action) -> Decision:
        """Return the :class:`~otgate.models.Decision` for ``action``."""
        if action.type is ActionType.READ:
            return self._evaluate_read(action)
        return await self._evaluate_write(action)

    def record_write(self, node_id: str, value: Scalar) -> None:
        """Note that a write was actually executed, for future rate checks.

        The server calls this only when a write is truly executed on the backend
        (not in shadow mode and not denied), so rate-of-change reflects real
        process changes.
        """
        if isinstance(value, bool):
            return  # rate is meaningless for booleans
        self._history.put(node_id, WriteRecord(self._clock(), float(value)))

    # --- reads ---

    def _evaluate_read(self, action: Action) -> Decision:
        rule = self._policy.get(action.node_id)
        if rule is None:
            return Decision(DecisionType.DENY, "tag not in policy (deny by default)")
        if rule.access is Access.DENY:
            return Decision(DecisionType.DENY, "tag access is deny")
        return Decision(DecisionType.ALLOW, "read allowed")

    # --- writes ---

    async def _evaluate_write(self, action: Action) -> Decision:
        rule = self._policy.get(action.node_id)

        # 1. Not in policy -> deny by default.
        if rule is None:
            return Decision(DecisionType.DENY, "tag not in policy (deny by default)")

        # 2. Access level.
        if rule.access is Access.DENY:
            return Decision(DecisionType.DENY, "tag access is deny")
        if rule.access is Access.READ:
            return Decision(DecisionType.DENY, "read-only tag")

        value = action.value
        if value is None:
            return Decision(DecisionType.DENY, "write requires a value")

        # 3. Value range.
        range_decision = self._check_range(rule, value)
        if range_decision is not None:
            return range_decision

        # 4. Interlocks.
        interlock_decision = await self._check_interlocks(rule)
        if interlock_decision is not None:
            return interlock_decision

        # 5. Rate of change (per step).
        rate_decision = await self._check_rate(rule, value)
        if rate_decision is not None:
            return rate_decision

        # 6. Cumulative drift over a window (catches salami attacks: many small
        #    legal steps adding up to a move the per-step limits would refuse).
        cumulative_decision = await self._check_cumulative(rule, value)
        if cumulative_decision is not None:
            return cumulative_decision

        # 7. Call budget over a window (catches call storms / recursion).
        calls_decision = self._check_call_budget(rule)
        if calls_decision is not None:
            return calls_decision

        # 8. Approval required.
        if rule.access is Access.WRITE_WITH_APPROVAL:
            return Decision(DecisionType.ASK, "write requires human approval")

        # 9. Plain write.
        return Decision(DecisionType.ALLOW, "write allowed")

    def _check_range(self, rule: Rule, value: Scalar) -> Decision | None:
        if rule.value_range is None:
            return None
        if isinstance(value, bool):
            # A bounded numeric range does not meaningfully apply to a boolean.
            return Decision(
                DecisionType.DENY,
                f"value {value!r} is not numeric but tag has a value_range",
            )
        lo, hi = rule.value_range
        if not (lo <= value <= hi):
            return Decision(
                DecisionType.DENY,
                f"value {value} is outside allowed range [{lo}, {hi}]",
            )
        return None

    async def _check_interlocks(self, rule: Rule) -> Decision | None:
        for interlock in rule.interlocks:
            try:
                current = await self._backend.read(interlock.tag)
            except KeyError:
                # A misconfigured interlock tag is a safety concern: fail closed.
                return Decision(
                    DecisionType.DENY,
                    f"interlock tag {interlock.tag} is unavailable (failing closed)",
                )
            except BackendPolicyDenied as exc:
                # The backend refused the read under its own policy — a bridge
                # whose allowlist excludes this interlock tag, typically. A
                # decision, not an outage, so it does not improve on a retry.
                return Decision(
                    DecisionType.DENY,
                    f"interlock tag {interlock.tag} was refused by the backend "
                    f"({exc}), so it could not be checked (failing closed)",
                )
            except BackendError:
                # Cannot verify the interlock because the backend is unreachable:
                # fail closed rather than allow a write we could not safety-check.
                return Decision(
                    DecisionType.DENY,
                    f"interlock tag {interlock.tag} could not be read "
                    "(backend unreachable, failing closed)",
                    retryable=True,
                )
            if _condition_holds(current, interlock.operator, interlock.threshold):
                return Decision(
                    DecisionType.DENY,
                    f"interlock active: {interlock.describe()} "
                    f"(current {interlock.tag} = {current})",
                )
        return None

    async def _check_rate(self, rule: Rule, value: Scalar) -> Decision | None:
        """Bound how fast the tag may move, measured against the live process.

        The baseline is the value the tag *actually holds right now*, read from
        the backend. That is what the process will jump from, no matter who put
        it there — an operator at the HMI, a cascade controller, the PLC program
        or another agent that does not go through otgate.

        Until v0.2 this check measured only against the last write otgate let
        through, which made it bypassable: move the tag outside the gateway and
        the gateway's idea of "current" goes stale, so an arbitrarily large real
        jump looks like a small legal step. See
        ``tests/test_rate_live_baseline.py`` for the regression that proves it.

        When history *is* available, both baselines are evaluated and the larger
        delta wins — the live value is the truth about the process, the recorded
        write is the truth about what otgate commanded, and a safety gate should
        answer to whichever is worse.

        Both are still only points in time. When the rule opts into
        ``history_rate``, a tag that passes this check then faces
        :meth:`_check_recorded_rate`, which asks a historian what happened
        *between* them.
        """
        if rule.max_rate is None or rule.rate_interval is None:
            return None
        if isinstance(value, bool):
            return None  # rate is meaningless for booleans

        # Live baseline, read once and shared with the recorded-history check. A
        # tag that cannot be read cannot be rate-checked, and an unverifiable
        # safety condition fails closed — same rule as interlocks.
        try:
            live = await self._backend.read(rule.tag)
        except KeyError:
            return Decision(
                DecisionType.DENY,
                f"tag {rule.tag} is unavailable for the rate check (failing closed)",
            )
        except BackendPolicyDenied as exc:
            return Decision(
                DecisionType.DENY,
                f"tag {rule.tag} was refused by the backend ({exc}), so it "
                "could not be read for the rate check (failing closed)",
            )
        except BackendError:
            return Decision(
                DecisionType.DENY,
                f"tag {rule.tag} could not be read for the rate check "
                "(backend unreachable, failing closed)",
                retryable=True,
            )

        step = self._check_step_rate(rule, value, live)
        if step is not None:
            return step
        return await self._check_recorded_rate(rule)

    def _check_step_rate(
        self, rule: Rule, value: Scalar, live: Scalar
    ) -> Decision | None:
        """The per-step rate verdict. No I/O: ``live`` is already in hand."""
        assert rule.max_rate is not None and rule.rate_interval is not None

        # A boolean on a rate-limited numeric tag is a misconfiguration, not a
        # baseline: fall back to history rather than coercing True to 1.0.
        live_delta = (
            None if isinstance(live, bool) else abs(float(value) - float(live))
        )

        record = self._history.get(rule.tag)
        if record is None:
            # No write has gone through the gate, so there is no time base and
            # no rate can be computed. Granting one full interval's worth of
            # change from the live value is the conservative reading of
            # "no faster than max_rate per rate_interval"; skipping the check
            # entirely — the pre-v0.2 behaviour — handed the first write after
            # every restart an unbounded step.
            if live_delta is not None and live_delta > rule.max_rate:
                return Decision(
                    DecisionType.DENY,
                    f"rate of change too high: |{value} - {live}| = {live_delta:g} "
                    f"exceeds {rule.max_rate:g} per {rule.rate_interval:g}s "
                    "(no write history yet, so one interval is allowed)",
                )
            return None

        now = self._clock()
        dt = now - record.wall_ts
        # A negative dt would mean the stored write is in the "future" — e.g. a
        # backwards clock adjustment. Treat it as "no measurable interval" so we
        # fall back to the strict (effective_dt <= 0) branch rather than
        # computing a nonsensical allowance.
        if dt < 0:
            dt = 0.0

        # Worse of the two baselines (see the docstring).
        hist_delta = abs(float(value) - record.value)
        if live_delta is not None and live_delta > hist_delta:
            delta, baseline = live_delta, live
        else:
            delta, baseline = hist_delta, record.value

        # Allowed magnitude of change over the elapsed interval, capped at one
        # full rate_interval so that waiting longer than the interval always
        # permits a full max_rate step.
        effective_dt = min(dt, rule.rate_interval)
        if effective_dt <= 0:
            # Two writes at (effectively) the same instant: any change is
            # infinitely fast. Allow only a zero-magnitude change.
            allowed = 0.0
        else:
            allowed = rule.max_rate * (effective_dt / rule.rate_interval)

        if delta > allowed:
            return Decision(
                DecisionType.DENY,
                f"rate of change too high: |{value} - {baseline}| = {delta:g} "
                f"in {dt:.3g}s exceeds {rule.max_rate:g} per {rule.rate_interval:g}s",
            )
        return None

    async def _check_recorded_rate(self, rule: Rule) -> Decision | None:
        """Hold the *process* to the rate limit, not just this write.

        One question goes to the historian: over the last ``rate_interval``,
        how fast has this tag been moving? The answer is a rate in the same
        units the policy is written in, so it is compared directly against
        ``max_rate`` — a rate limit judged against a measured rate, with no
        unit mixing and no second round trip.

        If the process is already moving faster than its limit, this write is
        refused. Note what that does *not* say: it does not accuse the write.
        The tag is outside its rate envelope right now, something other than
        otgate put it there, and a gateway whose job is to keep a process
        inside an envelope does not add to a move that has already left it.
        The denial lifts by itself once the fast movement ages out of the
        window.

        **Known limit, deliberately not papered over.** This compares one rate
        against one limit; it does not pool a shared budget across actors. An
        operator using 4 of a "5 per 60 s" allowance and an agent then adding
        3 is two legal rates and one illegal total, and this check permits it.
        Summing them would need movement in units and a rate in units/time to
        be added together, which is not a quantity. ``cumulative_range`` is
        the existing answer for series effects.

        Everything the historian cannot answer fails closed, exactly like an
        unverifiable interlock. A tag with *nothing* on record in the window is
        the one exception: that is an answer ("no recorded movement"), not a
        failure, and it leaves the verdict to the other checks.
        """
        if not rule.history_rate:
            return None
        assert rule.max_rate is not None and rule.rate_interval is not None
        bucket = rule.history_bucket_seconds
        assert bucket is not None  # rate_interval is set, so this is defaulted
        source = rule.history_source

        if self._trend is None:
            # The constructor refuses this combination, so reaching here means
            # an engine assembled some other way. Still fail closed: a rule
            # that asks to be checked against history must never pass
            # unchecked.
            return Decision(
                DecisionType.DENY,
                f"tag {source} requires a recorded-history rate check but no "
                "historian is configured (failing closed)",
            )

        try:
            observed = await self._trend.observed_movement(
                source, window=rule.rate_interval, bucket=bucket
            )
        except HistoryUnavailable as exc:
            # Deny either way, but say whether asking again could help: an
            # unreachable historian is worth a retry, a history_tag that does
            # not exist is not. See :class:`~otgate.trend.HistoryUnavailable`.
            return Decision(
                DecisionType.DENY,
                f"tag {source} could not be checked against recorded history "
                f"({exc}) (failing closed)",
                retryable=exc.retryable,
            )

        if observed.rate_per_interval > rule.max_rate:
            return Decision(
                DecisionType.DENY,
                f"the process itself is moving too fast: {source} moved "
                f"{observed.describe} per {rule.rate_interval:g}s in the "
                f"plant's own history, over the limit of {rule.max_rate:g} per "
                f"{rule.rate_interval:g}s — refusing to add to a move otgate "
                "did not make",
            )
        return None

    async def _check_cumulative(self, rule: Rule, value: Scalar) -> Decision | None:
        """Bound total drift from where the tag stood at the start of the window.

        The per-step rate check can be walked around by taking many small legal
        steps (a salami attack). This compares the proposed value against the
        tag's value when the window opened, so the series is bounded regardless
        of how it is sliced. Moving back towards the baseline is always allowed.

        **Scope: this bounds the series otgate itself let through**, which is a
        deliberate difference from :meth:`_check_rate`. Rate takes the worse of
        the live value and the recorded write, because "how fast is the process
        moving right now" is a question about the process. Cumulative drift is a
        question about the agent's own series, and judging it against the live
        value would lock the agent out of a tag for a whole window after any
        manual intervention: an operator moving a setpoint 20 units by hand
        would make every subsequent agent nudge, however small, read as a
        20-unit drift. The live value is therefore used only to *open* a window
        when no series exists yet (below). A process that has been moved far by
        something other than otgate is caught by the rate check, not here.
        """
        if rule.cumulative_range is None or rule.cumulative_interval is None:
            return None
        if isinstance(value, bool):
            return None  # cumulative drift is meaningless for booleans

        now = self._clock()
        window = self._history.window(rule.tag, now - rule.cumulative_interval)
        if window:
            # Value the tag held when the window opened: the value *before* the
            # oldest write in it is unknown, so use that write's value as the
            # baseline — it is the earliest position we can attribute.
            baseline = window[0].value
        else:
            last = self._history.get(rule.tag)
            if last is not None:
                # Nothing written inside the window. The last known write is the
                # current position, and drift from it starts now.
                baseline = last.value
            else:
                # No series at all — a fresh process, or a restart with no
                # persisted history. The window opens at wherever the tag
                # actually is. Returning None here (the pre-v0.2 behaviour) meant
                # a tag with a drift allowance had no drift check whatsoever
                # until otgate happened to write to it once.
                try:
                    live = await self._backend.read(rule.tag)
                except KeyError:
                    return Decision(
                        DecisionType.DENY,
                        f"tag {rule.tag} is unavailable for the cumulative "
                        "drift check (failing closed)",
                    )
                except BackendPolicyDenied as exc:
                    return Decision(
                        DecisionType.DENY,
                        f"tag {rule.tag} was refused by the backend ({exc}), "
                        "so it could not be read for the cumulative drift "
                        "check (failing closed)",
                    )
                except BackendError:
                    return Decision(
                        DecisionType.DENY,
                        f"tag {rule.tag} could not be read for the cumulative "
                        "drift check (backend unreachable, failing closed)",
                        retryable=True,
                    )
                if isinstance(live, bool):
                    # A boolean on a tag carrying a numeric drift allowance is a
                    # policy/plant mismatch, not a baseline. Fail closed and make
                    # the misconfiguration visible rather than skip the check.
                    return Decision(
                        DecisionType.DENY,
                        f"tag {rule.tag} reads as boolean ({live!r}) but has a "
                        "cumulative_range; cannot establish a drift baseline "
                        "(failing closed)",
                    )
                baseline = float(live)

        lo, hi = rule.cumulative_range
        drift = float(value) - baseline
        if drift < lo or drift > hi:
            return Decision(
                DecisionType.DENY,
                f"cumulative drift too large: {value} is {drift:+g} from {baseline:g} "
                f"(the value {rule.cumulative_interval:g}s ago), allowed [{lo:g}, {hi:g}]",
            )
        return None

    def _check_call_budget(self, rule: Rule) -> Decision | None:
        """Bound how many writes may be executed within a window."""
        if rule.max_calls is None or rule.calls_interval is None:
            return None

        now = self._clock()
        used = len(self._history.window(rule.tag, now - rule.calls_interval))
        if used >= rule.max_calls:
            return Decision(
                DecisionType.DENY,
                f"call budget exhausted: {used} writes in the last "
                f"{rule.calls_interval:g}s, limit is {rule.max_calls}",
            )
        return None


def _condition_holds(current: Scalar, operator: str, threshold: Scalar) -> bool:
    """Evaluate ``current <op> threshold`` for the supported operators.

    Booleans are compared as booleans for ``==`` / ``!=``; ordering operators
    coerce to float (Python treats ``True`` as ``1``), which is fine for the
    numeric thresholds this engine deals with.
    """
    if operator == "==":
        return _scalar_eq(current, threshold)
    if operator == "!=":
        return not _scalar_eq(current, threshold)

    # Ordering comparisons — numeric.
    try:
        c = float(current)
        t = float(threshold)
    except (TypeError, ValueError):
        return False
    if operator == ">":
        return c > t
    if operator == ">=":
        return c >= t
    if operator == "<":
        return c < t
    if operator == "<=":
        return c <= t
    return False  # unreachable: operators are validated at load time


def _scalar_eq(current: Scalar, threshold: Scalar) -> bool:
    # If either side is a bool, compare by boolean identity of truthiness so
    # that (True == 1) does not accidentally match a boolean interlock.
    if isinstance(threshold, bool) or isinstance(current, bool):
        return bool(current) == bool(threshold)
    return float(current) == float(threshold)
