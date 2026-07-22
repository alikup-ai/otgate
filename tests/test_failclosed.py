"""Fail-closed and health tests.

When the backend is unreachable, otgate must fail closed: reads and writes yield
an ERROR outcome (never a silent success), the failure is audited, an
unverifiable interlock blocks the write, and the health endpoint reports the
outage.
"""

from __future__ import annotations

import pytest

from otgate.audit import AuditLog
from otgate.backends.base import BackendError
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
    # Either the interlock re-check fails closed (DENIED) or execution errors;
    # in both cases nothing is written.
    assert res.executed is False
    assert res.status in ("DENIED", "ERROR")


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
