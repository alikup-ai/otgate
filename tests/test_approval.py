"""Approval-workflow tests.

Covers the store lifecycle and, more importantly, the gateway guarantees:
approve executes, deny does not, expiry is fail-safe, and — the safety-critical
one — approving re-evaluates against current process state so a stale ASK cannot
execute after an interlock trips or the value drifts out of range.
"""

from __future__ import annotations

import pytest

from otgate.approval import ApprovalStatus, ApprovalStore
from otgate.audit import AuditLog
from otgate.backends.fake import FakeBackend
from otgate.gateway import Gateway
from otgate.models import DecisionType

from conftest import ESD, POLICY_PATH, SP, ManualClock
from otgate.policy import load_policy


# --- store ---

def test_store_create_and_pending():
    store = ApprovalStore(default_ttl=60.0, clock=ManualClock())
    req = store.create(SP, 60.0)
    assert req.status is ApprovalStatus.PENDING
    assert [r.id for r in store.pending()] == [req.id]


def test_store_expiry_is_lazy_and_fail_safe():
    clock = ManualClock()
    store = ApprovalStore(default_ttl=60.0, clock=clock)
    req = store.create(SP, 60.0)
    clock.advance(61.0)
    got = store.get(req.id)
    assert got.status is ApprovalStatus.EXPIRED
    assert "fail-safe" in got.resolution_reason
    assert store.pending() == []


def test_store_rejects_nonpositive_ttl():
    with pytest.raises(ValueError):
        ApprovalStore(default_ttl=0)


def test_store_custom_ttl():
    clock = ManualClock()
    store = ApprovalStore(default_ttl=300.0, clock=clock)
    req = store.create(SP, 1.0, ttl=5.0)
    clock.advance(6.0)
    assert store.get(req.id).status is ApprovalStatus.EXPIRED


# --- gateway flow ---

@pytest.fixture
def gw(tmp_path):
    """A gateway on the example policy with a FakeBackend and its own audit."""
    g = Gateway(load_policy(POLICY_PATH), FakeBackend(), AuditLog(tmp_path / "audit.jsonl"))
    yield g
    g.close()


async def test_ask_parks_request_not_executed(gw):
    result = await gw.write(SP, 60.0)
    assert result.decision.type is DecisionType.ASK
    assert result.approval_id is not None
    assert result.executed is False
    assert len(gw.pending_approvals()) == 1


async def test_approve_executes(gw):
    backend_before = 55.0
    result = await gw.write(SP, 60.0)
    res = await gw.approve(result.approval_id)
    assert res.status == "APPROVED"
    assert res.executed is True
    # The value really landed on the backend.
    assert await gw._backend.read(SP) == 60.0
    assert gw.pending_approvals() == []


async def test_deny_does_not_execute(gw):
    result = await gw.write(SP, 62.0)
    res = gw.deny(result.approval_id)
    assert res.status == "DENIED"
    assert res.executed is False
    assert await gw._backend.read(SP) == 55.0  # unchanged


async def test_approve_reevaluates_and_blocks_stale_ask(gw):
    """Safety-critical: an interlock tripping while the request waits must block
    execution even though a human approved."""
    result = await gw.write(SP, 60.0)
    gw._backend.set(ESD, True)  # emergency shutdown trips during the wait
    res = await gw.approve(result.approval_id)
    assert res.status == "DENIED"
    assert res.executed is False
    assert "re-check" in res.reason
    assert await gw._backend.read(SP) == 55.0  # not executed


async def test_approve_expired_request(tmp_path):
    clock = ManualClock()
    store = ApprovalStore(default_ttl=60.0, clock=clock)
    g = Gateway(load_policy(POLICY_PATH), FakeBackend(), AuditLog(tmp_path / "a.jsonl"), approvals=store)
    try:
        result = await g.write(SP, 60.0)
        clock.advance(61.0)
        res = await g.approve(result.approval_id)
        assert res.status == "EXPIRED"
        assert res.executed is False
        assert await g._backend.read(SP) == 55.0
    finally:
        g.close()


async def test_approve_unknown_id(gw):
    res = await gw.approve("does-not-exist")
    assert res.status == "NOT_FOUND"
    assert res.executed is False


async def test_double_resolution_is_rejected(gw):
    result = await gw.write(SP, 60.0)
    first = await gw.approve(result.approval_id)
    assert first.executed is True
    second = await gw.approve(result.approval_id)  # already resolved
    assert second.executed is False
    assert "already resolved" in second.reason


async def test_deny_unknown_id(gw):
    res = gw.deny("nope")
    assert res.status == "NOT_FOUND"


async def test_approval_is_audited(gw):
    """The ASK and the eventual execution both appear in the audit trail."""
    result = await gw.write(SP, 60.0)
    await gw.approve(result.approval_id)
    tail = gw.audit_tail()
    decisions = [e["decision"] for e in tail]
    # First the ASK when parked, then an ALLOW when approved+executed.
    assert decisions[0] == "ASK"
    assert decisions[-1] == "ALLOW"
    assert tail[-1]["executed"] is True
