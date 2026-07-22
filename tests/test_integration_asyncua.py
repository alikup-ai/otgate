"""End-to-end integration tests against a REAL OPC UA server (asyncua).

These prove otgate's policy engine, approval flow and fail-closed behaviour work
over an actual ``opc.tcp://`` connection — not just the in-memory FakeBackend.
The asyncua reactor simulator from ``examples/opcua_sim_server.py`` is started
in-process on a fresh port per test session.

Skipped automatically when ``asyncua`` is not installed, so the default unit-test
run needs no OPC UA dependency. Run just these with::

    pytest -m integration
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("asyncua")

# Make examples/ importable (opcua_sim_server lives there).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asyncua import Server, ua  # noqa: E402

from otgate.audit import AuditLog  # noqa: E402
from otgate.backends.asyncua_backend import AsyncuaBackend  # noqa: E402
from otgate.gateway import Gateway  # noqa: E402
from otgate.models import DecisionType  # noqa: E402
from otgate.policy import load_policy  # noqa: E402

from conftest import ESD, POLICY_PATH, PV, SP  # noqa: E402

pytestmark = pytest.mark.integration

NAMESPACE_URI = "http://otgate/reactor"
_TAGS = [
    ("Reactor.TIC101.PV", 55.0, ua.VariantType.Double, False),
    ("Reactor.TIC101.SP", 55.0, ua.VariantType.Double, True),
    ("Reactor.PIC201.PV", 3.2, ua.VariantType.Double, False),
    ("Reactor.ESD", False, ua.VariantType.Boolean, True),
]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _make_server(endpoint: str) -> Server:
    server = Server()
    await server.init()
    server.set_endpoint(endpoint)
    idx = await server.register_namespace(NAMESPACE_URI)
    assert idx == 2, f"expected namespace index 2, got {idx}"
    reactor = await server.nodes.objects.add_object(idx, "Reactor")
    for identifier, value, vtype, writable in _TAGS:
        node = await reactor.add_variable(
            ua.NodeId(identifier, idx), identifier.split(".")[-1], ua.Variant(value, vtype)
        )
        if writable:
            await node.set_writable()
    return server


@pytest.fixture
async def endpoint():
    """Start the simulator on a fresh port; yield its endpoint; tear it down."""
    ep = f"opc.tcp://127.0.0.1:{_free_port()}/otgate/test"
    server = await _make_server(ep)
    await server.start()
    # Give the listener a moment.
    await asyncio.sleep(0.2)
    try:
        yield ep, server
    finally:
        with contextlib.suppress(Exception):
            await server.stop()


@pytest.fixture
async def gateway(endpoint, tmp_path):
    ep, _server = endpoint
    backend = AsyncuaBackend(ep)
    await backend.connect()
    gw = Gateway(load_policy(POLICY_PATH), backend, AuditLog(tmp_path / "audit.jsonl"))
    try:
        yield gw, backend
    finally:
        await backend.disconnect()
        gw.close()


async def test_read_over_real_opcua(gateway):
    gw, _ = gateway
    result = await gw.read(PV)
    assert result.decision.type is DecisionType.ALLOW
    assert result.value == 55.0


async def test_out_of_range_denied_over_real_opcua(gateway):
    gw, backend = gateway
    result = await gw.write(SP, 200.0)
    assert result.decision.type is DecisionType.DENY
    assert "range" in result.decision.reason
    # Server value unchanged.
    assert await backend.read(SP) == 55.0


async def test_write_with_approval_over_real_opcua(gateway):
    gw, backend = gateway
    result = await gw.write(SP, 60.0)
    assert result.decision.type is DecisionType.ASK
    assert result.approval_id is not None
    # Not executed until approved.
    assert await backend.read(SP) == 55.0

    res = await gw.approve(result.approval_id)
    assert res.status == "APPROVED"
    assert res.executed is True
    assert await backend.read(SP) == 60.0


async def test_interlock_over_real_opcua(gateway):
    gw, backend = gateway
    # Trip ESD on the real server.
    await backend.write(ESD, True)
    result = await gw.write(SP, 60.0)
    assert result.decision.type is DecisionType.DENY
    assert "interlock" in result.decision.reason
    await backend.write(ESD, False)


async def test_health_over_real_opcua(gateway):
    gw, _ = gateway
    h = await gw.health()
    assert h["status"] == "ok"
    assert h["backend"] == "up"


async def test_fail_closed_when_server_stops(endpoint, tmp_path):
    """Stopping the real server mid-session makes reads fail closed (ERROR)."""
    ep, server = endpoint
    backend = AsyncuaBackend(ep, reconnect_attempts=1, reconnect_backoff=0.0)
    await backend.connect()
    gw = Gateway(load_policy(POLICY_PATH), backend, AuditLog(tmp_path / "a.jsonl"))
    try:
        # Healthy read first.
        assert (await gw.read(PV)).decision.type is DecisionType.ALLOW

        # Kill the server; the next read must fail closed, not hang or crash.
        await server.stop()
        await asyncio.sleep(0.2)

        result = await gw.read(PV)
        assert result.decision.type is DecisionType.ERROR
        assert gw.audit_tail()[-1]["decision"] == "ERROR"

        # Health reports the outage.
        h = await gw.health()
        assert h["backend"] == "down"
    finally:
        with contextlib.suppress(Exception):
            await backend.disconnect()
        gw.close()
