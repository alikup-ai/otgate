"""The gateway: policy + engine + backend + audit + shadow mode, wired together.

This is the transport-independent core that the MCP server (``server.py``) is a
thin adapter over. Keeping it separate means the whole decide/execute/audit flow
— including shadow mode — is unit-testable without an MCP runtime.

Each public method returns a small result object carrying the decision, the
value (for reads/executed writes) and whether the operation actually ran, so the
caller can render a response and the audit trail already has its line.
"""

from __future__ import annotations

from dataclasses import dataclass

from otgate.audit import AuditLog
from otgate.backends.base import Backend, BackendError
from otgate.engine import PolicyEngine
from otgate.models import (
    Action,
    ActionType,
    Decision,
    DecisionType,
    Policy,
    Scalar,
)
from otgate.approval import ApprovalStatus, ApprovalStore
from otgate.rate_history import RateHistory


@dataclass
class ReadResult:
    """Outcome of a :meth:`Gateway.read`."""

    decision: Decision
    value: Scalar | None  # set only when the read was allowed and executed
    executed: bool


@dataclass
class WriteResult:
    """Outcome of a :meth:`Gateway.write`."""

    decision: Decision
    executed: bool  # True only if actually written to the backend
    approval_id: str | None = None  # set when the write was parked for approval


@dataclass
class ApprovalResult:
    """Outcome of resolving an approval request (approve/deny)."""

    status: str  # ApprovalStatus value: APPROVED / DENIED / EXPIRED / not-found
    executed: bool
    reason: str


class Gateway:
    """Applies policy to reads/writes, executes allowed ones, audits everything.

    Args:
        policy: loaded policy.
        backend: backend to read/write.
        audit: audit log to append to.
        shadow: if True, writes that the engine ALLOWs are *not* executed on the
            backend; the audit records them as ``executed=false`` with a
            "WOULD execute" reason. Reads are unaffected by shadow mode.
        rate_history: optional storage for the engine's rate-of-change history.
            Pass a :class:`~otgate.rate_history.JsonlRateHistory` to make the
            rate limit durable across restarts; defaults to non-persistent
            in-memory history.
        approvals: store for parked ``write_with_approval`` requests. Defaults to
            a fresh :class:`~otgate.approval.ApprovalStore` with a 300 s TTL.
    """

    def __init__(
        self,
        policy: Policy,
        backend: Backend,
        audit: AuditLog,
        *,
        shadow: bool = False,
        rate_history: RateHistory | None = None,
        approvals: ApprovalStore | None = None,
        agent_id: str | None = None,
    ) -> None:
        self._policy = policy
        self._backend = backend
        self._audit = audit
        self._shadow = shadow
        self._engine = PolicyEngine(policy, backend, history=rate_history)
        self._approvals = approvals or ApprovalStore()
        self._agent_id = agent_id

    @property
    def shadow(self) -> bool:
        return self._shadow

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def audit(self) -> AuditLog:
        return self._audit

    async def read(self, node_id: str) -> ReadResult:
        """Evaluate and, if allowed, perform a read; always audit.

        If the backend is unreachable during an allowed read, the result is an
        ERROR decision (fail closed) rather than an unhandled exception.
        """
        action = Action(ActionType.READ, node_id)
        decision = await self._engine.evaluate(action)

        value: Scalar | None = None
        executed = False
        if decision.type is DecisionType.ALLOW:
            try:
                value = await self._backend.read(node_id)
                executed = True
            except (BackendError, KeyError) as exc:
                decision = Decision(
                    DecisionType.ERROR,
                    f"backend read failed: {exc}",
                )

        self._audit.record(
            action="read",
            node_id=node_id,
            value=None,  # audit 'value' is for writes; reads log no value
            decision=decision,
            shadow=self._shadow,
            executed=executed,
            agent=self._agent_id,
        )
        return ReadResult(decision=decision, value=value, executed=executed)

    async def write(self, node_id: str, value: Scalar) -> WriteResult:
        """Evaluate a write; execute ALLOW, park ASK for approval, audit all."""
        action = Action(ActionType.WRITE, node_id, value)
        decision = await self._engine.evaluate(action)

        if decision.type is DecisionType.ALLOW:
            outcome, executed = await self._execute_allowed_write(
                node_id, value, decision, agent=self._agent_id
            )
            return WriteResult(decision=outcome, executed=executed)

        if decision.type is DecisionType.ASK:
            # Park the write for a human decision instead of dropping it.
            request = self._approvals.create(node_id, value, agent_id=self._agent_id)
            ask_reason = f"{decision.reason} (approval id: {request.id})"
            self._audit.record(
                action="write",
                node_id=node_id,
                value=value,
                decision=Decision(DecisionType.ASK, ask_reason),
                shadow=self._shadow,
                executed=False,
                agent=self._agent_id,
            )
            return WriteResult(
                decision=Decision(DecisionType.ASK, ask_reason),
                executed=False,
                approval_id=request.id,
            )

        # DENY: nothing to execute, just audit.
        self._audit.record(
            action="write",
            node_id=node_id,
            value=value,
            decision=decision,
            shadow=self._shadow,
            executed=False,
            agent=self._agent_id,
        )
        return WriteResult(decision=decision, executed=False)

    async def approve(self, request_id: str) -> ApprovalResult:
        """Approve a parked write and, if it *still* passes policy, execute it.

        Approving records human intent; it does not blindly execute. The write is
        re-evaluated against the current process state, because an interlock may
        have tripped, the value drifted out of range, or the rate window changed
        while the request waited. A stale approval that no longer passes policy is
        recorded as approved-but-blocked and not executed.
        """
        request = self._approvals.get(request_id)
        if request is None:
            return ApprovalResult(status="NOT_FOUND", executed=False,
                                   reason=f"no approval request with id {request_id!r}")
        if request.status is not ApprovalStatus.PENDING:
            return ApprovalResult(
                status=request.status.value,
                executed=False,
                reason=f"request already resolved: {request.resolution_reason}",
            )

        # Re-run the full policy check now (fail-safe against a stale ASK).
        recheck = await self._engine.evaluate(
            Action(ActionType.WRITE, request.node_id, request.value)
        )
        if recheck.type is DecisionType.DENY:
            reason = f"approved but blocked on re-check: {recheck.reason}"
            self._approvals.mark(request_id, ApprovalStatus.DENIED, reason)
            self._audit.record(
                action="write", node_id=request.node_id, value=request.value,
                decision=Decision(DecisionType.DENY, reason),
                shadow=self._shadow, executed=False, agent=request.agent_id,
            )
            return ApprovalResult(status="DENIED", executed=False, reason=reason)

        # Passed re-check (ALLOW, or ASK again which approval satisfies): execute.
        # Attribute the write to the agent that requested it, not the operator.
        outcome, executed = await self._execute_allowed_write(
            request.node_id,
            request.value,
            Decision(DecisionType.ALLOW, "approved by human"),
            agent=request.agent_id,
        )
        if outcome.type is DecisionType.ERROR:
            # Backend was unreachable while executing the approved write. Leave
            # the request PENDING so the operator can retry once it recovers.
            return ApprovalResult(status="ERROR", executed=False, reason=outcome.reason)

        reason = "approved by human and executed" if executed else (
            "approved by human; not executed (shadow mode)"
        )
        self._approvals.mark(request_id, ApprovalStatus.APPROVED, reason)
        return ApprovalResult(status="APPROVED", executed=executed, reason=reason)

    def deny(self, request_id: str) -> ApprovalResult:
        """Deny a parked write; it will never execute."""
        request = self._approvals.get(request_id)
        if request is None:
            return ApprovalResult(status="NOT_FOUND", executed=False,
                                   reason=f"no approval request with id {request_id!r}")
        if request.status is not ApprovalStatus.PENDING:
            return ApprovalResult(
                status=request.status.value,
                executed=False,
                reason=f"request already resolved: {request.resolution_reason}",
            )
        reason = "denied by human"
        self._approvals.mark(request_id, ApprovalStatus.DENIED, reason)
        self._audit.record(
            action="write", node_id=request.node_id, value=request.value,
            decision=Decision(DecisionType.DENY, reason),
            shadow=self._shadow, executed=False, agent=request.agent_id,
        )
        return ApprovalResult(status="DENIED", executed=False, reason=reason)

    def pending_approvals(self) -> list[dict]:
        """All currently pending approval requests (oldest first)."""
        return [r.to_dict() for r in self._approvals.pending()]

    async def health(self) -> dict:
        """Report gateway liveness and backend reachability.

        Returns a small status dict suitable for a health endpoint. Never raises;
        a backend probe failure is reported as ``backend: "down"``.
        """
        try:
            backend_ok = await self._backend.health()
        except Exception:  # defensive: health() should not raise, but never crash
            backend_ok = False
        return {
            "status": "ok" if backend_ok else "degraded",
            "backend": "up" if backend_ok else "down",
            "pending_approvals": len(self._approvals.pending()),
        }

    def browse(self) -> list[str]:
        """Tags the agent may see (access != deny)."""
        return self._policy.visible_tags()

    def audit_tail(self, limit: int = 50) -> list[dict]:
        """Last ``limit`` audit entries, oldest first."""
        return self._audit.tail(limit)

    # --- internals ---

    async def _execute_allowed_write(
        self, node_id: str, value: Scalar, decision: Decision, *, agent: str | None = None
    ) -> tuple[Decision, bool]:
        """Execute an approved/allowed write (respecting shadow mode); audit it.

        Returns ``(outcome, executed)``. ``outcome`` is the decision to report:
        the original ALLOW, or an ERROR if the backend was unreachable (fail
        closed). ``executed`` is True only if the write actually hit the backend.
        Shared by the direct ALLOW path and the approval path so they behave
        identically. ``agent`` is the identity to attribute in the audit — the
        requesting agent, even when an operator triggers execution via approval.
        """
        executed = False
        outcome = decision
        audit_decision = decision
        if self._shadow:
            audit_decision = Decision(
                DecisionType.ALLOW,
                f"WOULD execute (shadow mode): {decision.reason}",
            )
        else:
            try:
                await self._backend.write(node_id, value)
                # Feed the executed write back into the engine's rate history.
                self._engine.record_write(node_id, value)
                executed = True
            except (BackendError, KeyError) as exc:
                outcome = Decision(DecisionType.ERROR, f"backend write failed: {exc}")
                audit_decision = outcome

        self._audit.record(
            action="write",
            node_id=node_id,
            value=value,
            decision=audit_decision,
            shadow=self._shadow,
            executed=executed,
            agent=agent,
        )
        return outcome, executed

    def close(self) -> None:
        """Release resources (flush and close the audit log)."""
        self._audit.close()
