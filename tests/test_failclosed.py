"""Fail-closed and health tests.

When the backend is unreachable, otgate must fail closed: reads and writes yield
an ERROR outcome (never a silent success), the failure is audited, an
unverifiable interlock blocks the write, and the health endpoint reports the
outage.

A backend that *refuses* rather than fails is the other half of this file. It
must also fail closed, but it is not an outage and must not be reported as
one — see the second half.
"""

from __future__ import annotations

import pytest

from otgate.audit import AuditLog
from otgate.backends.base import BackendError, BackendPolicyDenied
from otgate.backends.fake import FakeBackend
from otgate.gateway import Gateway
from otgate.models import Access, DecisionType, Policy, Rule
from otgate.policy import load_policy

from conftest import ESD, POLICY_PATH, PV, SP


@pytest.fixture
def gw(tmp_path):
    g = Gateway(load_policy(POLICY_PATH), FakeBackend(), AuditLog(tmp_path / "a.jsonl"))
    yield g
    g.close()


# --- backend health / error convention ---

async def test_fake_health_reflects_down_flag():
    b = FakeBackend()
    assert await b.health() is True
    b.set_down(True)
    assert await b.health() is False


async def test_fake_raises_backend_error_when_down():
    b = FakeBackend()
    b.set_down(True)
    with pytest.raises(BackendError):
        await b.read(PV)
    with pytest.raises(BackendError):
        await b.write(SP, 1.0)


# --- gateway fail-closed ---

async def test_read_fails_closed_when_backend_down(gw):
    gw._backend.set_down(True)
    result = await gw.read(PV)
    assert result.decision.type is DecisionType.ERROR
    assert result.executed is False
    assert gw.audit_tail()[-1]["decision"] == "ERROR"


async def test_write_fails_closed_when_backend_down(tmp_path):
    policy = Policy(rules={SP: Rule(tag=SP, access=Access.WRITE, value_range=(40.0, 80.0))})
    g = Gateway(policy, FakeBackend(), AuditLog(tmp_path / "a.jsonl"))
    try:
        g._backend.set_down(True)
        result = await g.write(SP, 60.0)
        assert result.decision.type is DecisionType.ERROR
        assert result.executed is False
        last = g.audit_tail()[-1]
        assert last["decision"] == "ERROR" and last["executed"] is False
    finally:
        g.close()


@pytest.mark.asi02
async def test_unverifiable_interlock_fails_closed(gw):
    """A write whose interlock cannot be read (backend down) is DENIED, not run."""
    gw._backend.set_down(True)
    result = await gw.write(SP, 60.0)  # SP has an ESD interlock
    assert result.decision.type is DecisionType.DENY
    assert "unreachable" in result.decision.reason


async def test_recovery_after_outage(gw):
    gw._backend.set_down(True)
    assert (await gw.read(PV)).decision.type is DecisionType.ERROR
    gw._backend.set_down(False)
    result = await gw.read(PV)
    assert result.decision.type is DecisionType.ALLOW
    assert result.value == 55.0


# --- approval during outage ---

async def test_approve_during_outage_does_not_execute(gw):
    result = await gw.write(SP, 60.0)  # parked while healthy
    assert result.decision.type is DecisionType.ASK
    gw._backend.set_down(True)
    res = await gw.approve(result.approval_id)
    assert res.executed is False
    assert res.status == "ERROR"
    assert "re-check" in res.reason
    assert [request["id"] for request in gw.pending_approvals()] == [result.approval_id]
    assert gw.audit_tail()[-1]["decision"] == "ERROR"

    gw._backend.set_down(False)
    assert await gw._backend.read(SP) == 55.0
    retried = await gw.approve(result.approval_id)
    assert retried.status == "APPROVED"
    assert retried.executed is True
    assert await gw._backend.read(SP) == 60.0


# --- gateway health dict ---

async def test_gateway_health_ok(gw):
    h = await gw.health()
    assert h["status"] == "ok"
    assert h["backend"] == "up"


async def test_gateway_health_degraded(gw):
    gw._backend.set_down(True)
    h = await gw.health()
    assert h["status"] == "degraded"
    assert h["backend"] == "down"


# --- HTTP /health endpoint ---

testclient = pytest.importorskip("starlette.testclient")


def test_health_endpoint_open_and_reports_status(tmp_path):
    from otgate.server import build_agent_server, build_http_app

    backend = FakeBackend()
    gw = Gateway(load_policy(POLICY_PATH), backend, AuditLog(tmp_path / "a.jsonl"))
    try:
        app = build_http_app(build_agent_server(gw), token="TOK", realm="agent", gateway=gw)
        with testclient.TestClient(app) as client:
            # open without auth
            r = client.get("/health")
            assert r.status_code == 200
            assert r.json()["status"] == "ok"

            # reports the outage
            backend.set_down(True)
            r = client.get("/health")
            assert r.status_code == 503
            assert r.json()["backend"] == "down"
            backend.set_down(False)

            # opening /health must not open the MCP endpoint
            assert client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}).status_code == 401
    finally:
        gw.close()


# --- a backend that refuses, rather than fails ----------------------------
# otgate may sit behind a bridge that holds a policy of its own — an OPCUA-MCP
# worker on an operator profile, say — and such a bridge answers "no" for tags
# outside its allowlist instead of attempting them. Every check that reads the
# process has to survive that: a refused read is still an unverifiable safety
# condition, so the write is denied. What it must not do is look like an
# outage, because an outage says "try again" and a refusal will say the same
# thing forever.


class AllowlistBackend(FakeBackend):
    """A backend that refuses some tags under its own policy, before I/O."""

    def __init__(self, excluded: set[str], tags=None) -> None:
        super().__init__(tags)
        self.excluded = excluded

    async def read(self, node_id):
        self._refuse(node_id)
        return await super().read(node_id)

    async def write(self, node_id, value):
        self._refuse(node_id)
        return await super().write(node_id, value)

    def _refuse(self, node_id: str) -> None:
        if node_id in self.excluded:
            raise BackendPolicyDenied(f"{node_id} is outside the bridge allowlist")


def gateway_with(backend, tmp_path, policy=None):
    return Gateway(
        policy or load_policy(POLICY_PATH), backend, AuditLog(tmp_path / "a.jsonl")
    )


async def test_a_refused_interlock_read_denies_the_write(tmp_path):
    """The guard tag is the one the bridge excludes: deny, and do not retry."""
    g = gateway_with(AllowlistBackend({ESD}), tmp_path)
    try:
        result = await g.write(SP, 60.0)
    finally:
        g.close()

    assert result.decision.type is DecisionType.DENY
    assert result.executed is False
    assert "refused by the backend" in result.decision.reason
    assert result.decision.retryable is False
    assert await AllowlistBackend({ESD}).read(SP) == 55.0, "nothing was written"


async def test_a_refused_rate_baseline_read_denies_the_write(tmp_path):
    """The written tag itself is excluded, so its live baseline is refused."""
    g = gateway_with(AllowlistBackend({SP}), tmp_path)
    try:
        result = await g.write(SP, 60.0)
    finally:
        g.close()

    assert result.decision.type is DecisionType.DENY
    assert "rate check" in result.decision.reason
    assert result.decision.retryable is False


async def test_a_refused_cumulative_baseline_read_denies_the_write(tmp_path):
    """No write history yet, so the drift window opens at the live value."""
    policy = Policy(
        rules={
            SP: Rule(
                tag=SP,
                access=Access.WRITE,
                cumulative_range=(-10.0, 10.0),
                cumulative_interval=3600.0,
            )
        }
    )
    g = gateway_with(AllowlistBackend({SP}), tmp_path, policy=policy)
    try:
        result = await g.write(SP, 60.0)
    finally:
        g.close()

    assert result.decision.type is DecisionType.DENY
    assert "cumulative drift" in result.decision.reason
    assert result.decision.retryable is False


async def test_a_refused_read_is_denied_not_errored(tmp_path):
    """A refusal filed as ERROR would sit in the audit beside dropped links."""
    g = gateway_with(AllowlistBackend({PV}), tmp_path)
    try:
        result = await g.read(PV)
    finally:
        g.close()

    assert result.decision.type is DecisionType.DENY
    assert result.executed is False
    assert "backend policy denied read" in result.decision.reason
    assert g.audit_tail()[-1]["decision"] == "DENY"


async def test_a_bridge_tightened_while_parked_resolves_the_approval(tmp_path):
    """The whole chain: a refused re-check must not leave a request pending.

    An approval parked under one bridge profile, and the guard tag dropped
    from the allowlist before the operator gets to it. The re-check cannot
    read the interlock, so the write is refused — and because asking again
    would be refused identically, the request resolves instead of waiting.
    """
    backend = AllowlistBackend(set())
    g = gateway_with(backend, tmp_path)
    try:
        parked = await g.write(SP, 60.0)
        assert parked.decision.type is DecisionType.ASK

        backend.excluded.add(ESD)
        result = await g.approve(parked.approval_id)

        assert result.status == "DENIED"
        assert result.executed is False
        assert g.pending_approvals() == []
        assert await backend.read(SP) == 55.0
    finally:
        g.close()
