"""Human-approval workflow for ``write_with_approval`` writes.

When the engine returns ``ASK``, otgate does not silently drop the write (v0.1's
behaviour) nor execute it. Instead it parks a :class:`ApprovalRequest` in an
:class:`ApprovalStore`. A human — via the ``list_pending`` / ``approve`` /
``deny`` MCP tools, a CLI, or the programmatic API — then resolves it.

Two safety properties are non-negotiable and enforced here and in the gateway:

- **Fail-safe expiry.** A request nobody answers within its TTL becomes
  ``EXPIRED`` and is never executed. Silence means "no".
- **Re-evaluation on approve.** Approving marks *intent*; the gateway re-runs the
  full policy check before touching the backend, because the process may have
  moved while the request waited (an interlock tripped, the value drifted out of
  range, the rate window changed). A stale ASK must never execute blindly.

This module owns request state and lifecycle; the gateway owns the decision to
create a request and the re-evaluation + execution on approval.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum

from otgate.models import Scalar


class ApprovalStatus(str, Enum):
    """Lifecycle state of an approval request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"  # human said yes; execution outcome recorded separately
    DENIED = "DENIED"  # human said no
    EXPIRED = "EXPIRED"  # TTL elapsed with no answer -> fail-safe no


@dataclass
class ApprovalRequest:
    """A parked ``write_with_approval`` write awaiting a human decision.

    Attributes:
        id: opaque unique identifier.
        node_id: target tag.
        value: value the agent wants to write.
        created_ts: wall-clock creation time (seconds since epoch).
        ttl: seconds after which the request auto-expires.
        status: current lifecycle state.
        resolution_reason: filled when the request leaves PENDING (why it was
            approved / denied / expired, and the execution outcome on approve).
        agent_id: id of the agent that requested the write (for audit
            attribution when an operator later approves it). ``None`` in
            single-agent mode.
    """

    id: str
    node_id: str
    value: Scalar
    created_ts: float
    ttl: float
    status: ApprovalStatus = ApprovalStatus.PENDING
    resolution_reason: str = ""
    agent_id: str | None = None

    def is_expired(self, now: float) -> bool:
        """True if still PENDING but past its TTL as of ``now``."""
        return self.status is ApprovalStatus.PENDING and (now - self.created_ts) >= self.ttl

    def to_dict(self) -> dict:
        """Serialise for the ``list_pending`` tool / logging."""
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "node_id": self.node_id,
            "value": self.value,
            "created_ts": self.created_ts,
            "ttl": self.ttl,
            "status": self.status.value,
            "resolution_reason": self.resolution_reason,
        }


class ApprovalStore:
    """In-memory store of approval requests with TTL-based expiry.

    Args:
        default_ttl: TTL applied to new requests, in seconds.
        clock: wall-clock time source; injectable for deterministic tests.

    The store is deliberately transport-agnostic: it does not know about MCP or
    the backend. Expiry is lazy — it is applied whenever the store is inspected —
    so no background task is required (a v0.1 simplification; a real deployment
    might sweep periodically).
    """

    def __init__(self, default_ttl: float = 300.0, clock=time.time) -> None:
        if default_ttl <= 0:
            raise ValueError("default_ttl must be positive")
        self._default_ttl = default_ttl
        self._clock = clock
        self._requests: dict[str, ApprovalRequest] = {}

    def create(
        self,
        node_id: str,
        value: Scalar,
        ttl: float | None = None,
        agent_id: str | None = None,
    ) -> ApprovalRequest:
        """Create and store a new PENDING request; return it."""
        request = ApprovalRequest(
            id=uuid.uuid4().hex,
            node_id=node_id,
            value=value,
            created_ts=self._clock(),
            ttl=ttl if ttl is not None else self._default_ttl,
            agent_id=agent_id,
        )
        self._requests[request.id] = request
        return request

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Return a request by id, applying lazy expiry first."""
        self._expire_due()
        return self._requests.get(request_id)

    def pending(self) -> list[ApprovalRequest]:
        """All currently PENDING requests (after applying expiry), oldest first."""
        self._expire_due()
        return sorted(
            (r for r in self._requests.values() if r.status is ApprovalStatus.PENDING),
            key=lambda r: r.created_ts,
        )

    def all(self) -> list[ApprovalRequest]:
        """Every request regardless of status (after expiry), oldest first."""
        self._expire_due()
        return sorted(self._requests.values(), key=lambda r: r.created_ts)

    def mark(self, request_id: str, status: ApprovalStatus, reason: str) -> None:
        """Set the terminal ``status`` and reason on a request."""
        request = self._requests[request_id]
        request.status = status
        request.resolution_reason = reason

    def _expire_due(self) -> None:
        now = self._clock()
        for request in self._requests.values():
            if request.is_expired(now):
                request.status = ApprovalStatus.EXPIRED
                request.resolution_reason = (
                    f"expired after {request.ttl:g}s with no decision (fail-safe deny)"
                )
