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
5. max_rate exceeded               -> DENY
6. access == write_with_approval   -> ASK
7. otherwise                       -> ALLOW

Reads: tag in policy and access != deny -> ALLOW, else DENY.

Rate of change is measured against the last write this engine *let through*
(kept in-memory, per tag, by wall-clock time). This is a deliberate v0.1
limitation documented in the README: it is per-process and resets on restart.
"""

from __future__ import annotations

import time

from otgate.backends.base import Backend, BackendError
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
    """

    def __init__(
        self,
        policy: Policy,
        backend: Backend,
        clock=time.time,
        history: RateHistory | None = None,
    ) -> None:
        self._policy = policy
        self._backend = backend
        self._clock = clock
        self._history: RateHistory = history or InMemoryRateHistory()

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

        # 5. Rate of change.
        rate_decision = self._check_rate(rule, value)
        if rate_decision is not None:
            return rate_decision

        # 6. Approval required.
        if rule.access is Access.WRITE_WITH_APPROVAL:
            return Decision(DecisionType.ASK, "write requires human approval")

        # 7. Plain write.
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
            except BackendError:
                # Cannot verify the interlock because the backend is unreachable:
                # fail closed rather than allow a write we could not safety-check.
                return Decision(
                    DecisionType.DENY,
                    f"interlock tag {interlock.tag} could not be read "
                    "(backend unreachable, failing closed)",
                )
            if _condition_holds(current, interlock.operator, interlock.threshold):
                return Decision(
                    DecisionType.DENY,
                    f"interlock active: {interlock.describe()} "
                    f"(current {interlock.tag} = {current})",
                )
        return None

    def _check_rate(self, rule: Rule, value: Scalar) -> Decision | None:
        if rule.max_rate is None or rule.rate_interval is None:
            return None
        if isinstance(value, bool):
            return None  # rate is meaningless for booleans
        record = self._history.get(rule.tag)
        if record is None:
            # No prior write through the gate: nothing to measure against.
            return None

        now = self._clock()
        dt = now - record.wall_ts
        # A negative dt would mean the stored write is in the "future" — e.g. a
        # backwards clock adjustment. Treat it as "no measurable interval" so we
        # fall back to the strict (effective_dt <= 0) branch rather than
        # computing a nonsensical allowance.
        if dt < 0:
            dt = 0.0
        delta = abs(float(value) - record.value)

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
                f"rate of change too high: |{value} - {record.value}| = {delta:g} "
                f"in {dt:.3g}s exceeds {rule.max_rate:g} per {rule.rate_interval:g}s",
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
