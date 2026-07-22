"""Core data models for otgate.

These dataclasses and enums are the shared vocabulary of the whole package:
policies (:class:`Policy`, :class:`Rule`, :class:`Interlock`), the actions an
agent requests (:class:`Action`), the engine's verdict (:class:`Decision`) and
the audit trail (:class:`AuditEntry`).

Everything here is intentionally free of I/O so it can be constructed and
inspected in tests without touching a backend, a file or a network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

# A scalar tag value. v0.1 deliberately supports only scalars.
Scalar = float | int | bool


class Access(str, Enum):
    """Access level a policy grants to a tag."""

    READ = "read"
    WRITE = "write"
    WRITE_WITH_APPROVAL = "write_with_approval"
    DENY = "deny"


class ActionType(str, Enum):
    """The kind of operation an agent requests against a tag."""

    READ = "read"
    WRITE = "write"


class DecisionType(str, Enum):
    """The outcome of a requested action.

    ALLOW / DENY / ASK are policy verdicts from the engine. ERROR is an
    infrastructure failure (e.g. the backend is unreachable): the request could
    not be completed, and otgate fails closed — it is never treated as allowed.
    """

    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK = "ASK"
    ERROR = "ERROR"


# Interlock condition operators supported in v0.1.
INTERLOCK_OPERATORS: tuple[str, ...] = ("==", "!=", ">", ">=", "<", "<=")


@dataclass(frozen=True)
class Interlock:
    """A safety interlock: if ``tag`` satisfies ``condition`` then ``action`` fires.

    In v0.1 the only supported ``action`` is ``deny`` — an interlock can block a
    write but never force one.
    """

    tag: str
    operator: str  # one of INTERLOCK_OPERATORS
    threshold: Scalar
    action: str = "deny"

    def describe(self) -> str:
        """Human-readable rendering, e.g. ``ns=2;s=Reactor.ESD == True``."""
        return f"{self.tag} {self.operator} {self.threshold}"


@dataclass(frozen=True)
class Rule:
    """One policy rule for a single OPC UA tag."""

    tag: str
    access: Access
    value_range: tuple[float, float] | None = None
    max_rate: float | None = None
    rate_interval: float | None = None  # seconds; required when max_rate is set
    interlocks: tuple[Interlock, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Policy:
    """A collection of rules, indexed by tag.

    Tags not present in :attr:`rules` are denied by default (deny-by-default).
    """

    rules: dict[str, Rule]

    def get(self, tag: str) -> Rule | None:
        """Return the rule for ``tag`` or ``None`` if the tag is not covered."""
        return self.rules.get(tag)

    def visible_tags(self) -> list[str]:
        """Tags an agent is allowed to see (access != deny), sorted."""
        return sorted(
            tag for tag, rule in self.rules.items() if rule.access is not Access.DENY
        )


@dataclass(frozen=True)
class Action:
    """A single operation an agent requests against the gateway."""

    type: ActionType
    node_id: str
    value: Scalar | None = None  # set for writes, None for reads


@dataclass(frozen=True)
class Decision:
    """The engine's verdict for an :class:`Action`."""

    type: DecisionType
    reason: str

    @property
    def allowed(self) -> bool:
        """True only for a plain ALLOW (ASK is *not* an allow)."""
        return self.type is DecisionType.ALLOW


@dataclass(frozen=True)
class AuditEntry:
    """One immutable audit-log record."""

    timestamp: str  # ISO 8601
    action: str  # "read" | "write"
    node_id: str
    value: Scalar | None
    decision: str  # "ALLOW" | "DENY" | "ASK"
    reason: str
    shadow: bool
    executed: bool
    agent: str | None = None  # which agent made the call (None in single-agent mode)

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for a JSONL line."""
        return {
            "timestamp": self.timestamp,
            "agent": self.agent,
            "action": self.action,
            "node_id": self.node_id,
            "value": self.value,
            "decision": self.decision,
            "reason": self.reason,
            "shadow": self.shadow,
            "executed": self.executed,
        }
