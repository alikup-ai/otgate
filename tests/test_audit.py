"""Audit-log tests: every decision is recorded with the right fields."""

from __future__ import annotations

import json

import pytest

from otgate.audit import AuditLog
from otgate.backends.fake import FakeBackend
from otgate.gateway import Gateway
from otgate.models import Decision, DecisionType

from conftest import PV, SP

_EXPECTED_FIELDS = {
    "timestamp",
    "agent",
    "action",
    "node_id",
    "value",
    "decision",
    "reason",
    "shadow",
    "executed",
}


def test_record_writes_all_fields(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record(
        action="write",
        node_id=SP,
        value=60.0,
        decision=Decision(DecisionType.ASK, "needs approval"),
        shadow=False,
        executed=False,
        timestamp="2026-07-22T00:00:00Z",
    )
    lines = (tmp_path / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    obj = json.loads(lines[0])
    assert set(obj) == _EXPECTED_FIELDS
    assert obj["decision"] == "ASK"
    assert obj["reason"] == "needs approval"
    assert obj["value"] == 60.0
    assert obj["executed"] is False


def test_append_only_preserves_history(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).record(
        action="read",
        node_id=PV,
        value=None,
        decision=Decision(DecisionType.ALLOW, "ok"),
        shadow=False,
        executed=True,
    )
    # A brand-new instance must append, not truncate.
    AuditLog(path).record(
        action="write",
        node_id=SP,
        value=1,
        decision=Decision(DecisionType.DENY, "no"),
        shadow=False,
        executed=False,
    )
    assert len(path.read_text(encoding="utf-8").splitlines()) == 2


def test_tail_returns_last_entries_oldest_first(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.record(
            action="read",
            node_id=f"tag{i}",
            value=None,
            decision=Decision(DecisionType.ALLOW, "ok"),
            shadow=False,
            executed=True,
        )
    tail = log.tail(limit=3)
    assert [e["node_id"] for e in tail] == ["tag2", "tag3", "tag4"]


def test_tail_missing_file_is_empty(tmp_path):
    assert AuditLog(tmp_path / "nope.jsonl").tail() == []


def test_tail_negative_limit_raises(tmp_path):
    with pytest.raises(ValueError):
        AuditLog(tmp_path / "audit.jsonl").tail(limit=-1)


def test_tail_served_from_memory_matches_disk(tmp_path):
    """The in-memory fast path and a fresh file read must agree."""
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(3):
        log.record(
            action="read",
            node_id=f"tag{i}",
            value=None,
            decision=Decision(DecisionType.ALLOW, "ok"),
            shadow=False,
            executed=True,
        )
    in_memory = log.tail()
    # A second instance has an empty buffer, so it must read the file instead.
    from_disk = AuditLog(tmp_path / "audit.jsonl").tail()
    assert in_memory == from_disk
    assert [e["node_id"] for e in in_memory] == ["tag0", "tag1", "tag2"]


def test_close_flushes_and_is_idempotent(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record(
        action="read",
        node_id=PV,
        value=None,
        decision=Decision(DecisionType.ALLOW, "ok"),
        shadow=False,
        executed=True,
    )
    log.close()
    log.close()  # idempotent, must not raise
    # Data is durable and readable after close.
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_context_manager_closes(tmp_path):
    path = tmp_path / "audit.jsonl"
    with AuditLog(path) as log:
        log.record(
            action="write",
            node_id=SP,
            value=1,
            decision=Decision(DecisionType.DENY, "no"),
            shadow=False,
            executed=False,
        )
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


async def test_every_decision_is_audited(tmp_path):
    """Read (ALLOW), out-of-range write (DENY) and in-range write (ASK) each log a line."""
    from otgate.policy import load_policy
    from conftest import POLICY_PATH

    gw = Gateway(load_policy(POLICY_PATH), FakeBackend(), AuditLog(tmp_path / "a.jsonl"))
    await gw.read(PV)
    await gw.write(SP, 200.0)  # DENY
    await gw.write(SP, 60.0)  # ASK

    tail = gw.audit_tail()
    assert len(tail) == 3
    decisions = [e["decision"] for e in tail]
    assert decisions == ["ALLOW", "DENY", "ASK"]
