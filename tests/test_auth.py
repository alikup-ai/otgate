"""Auth + channel-isolation tests.

Two things must hold for #2:

1. The Bearer middleware rejects missing/wrong tokens (401) and lets the right
   one through — in constant time.
2. The agent channel does not even *expose* the approval tools, so an agent
   cannot approve its own writes regardless of tokens.
"""

from __future__ import annotations

import pytest

from otgate.audit import AuditLog
from otgate.auth import BearerAuthMiddleware
from otgate.backends.fake import FakeBackend
from otgate.gateway import Gateway
from otgate.policy import load_policy
from otgate.server import (
    build_agent_server,
    build_http_app,
    build_operator_server,
    build_server,
)

from conftest import POLICY_PATH

# Starlette's TestClient needs httpx; skip HTTP tests cleanly if unavailable.
testclient = pytest.importorskip("starlette.testclient")
from starlette.applications import Starlette  # noqa: E402
from starlette.responses import JSONResponse  # noqa: E402
from starlette.routing import Route  # noqa: E402


def _gateway(tmp_path):
    return Gateway(load_policy(POLICY_PATH), FakeBackend(), AuditLog(tmp_path / "a.jsonl"))


# --- middleware unit tests ---

def _trivial_app_with_auth(token: str, realm: str = "test") -> Starlette:
    async def ok(request):
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/x", ok)])
    app.add_middleware(BearerAuthMiddleware, token=token, realm=realm)
    return app


def test_missing_token_is_401():
    client = testclient.TestClient(_trivial_app_with_auth("secret"))
    r = client.get("/x")
    assert r.status_code == 401
    assert 'Bearer realm="test"' in r.headers.get("www-authenticate", "")


def test_wrong_token_is_401():
    client = testclient.TestClient(_trivial_app_with_auth("secret"))
    r = client.get("/x", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_malformed_header_is_401():
    client = testclient.TestClient(_trivial_app_with_auth("secret"))
    r = client.get("/x", headers={"Authorization": "secret"})  # no "Bearer "
    assert r.status_code == 401


def test_correct_token_passes():
    client = testclient.TestClient(_trivial_app_with_auth("secret"))
    r = client.get("/x", headers={"Authorization": "Bearer secret"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}


def test_empty_token_refused_at_construction():
    async def ok(request):
        return JSONResponse({})

    with pytest.raises(ValueError):
        BearerAuthMiddleware(Starlette(routes=[Route("/x", ok)]), token="")


# --- channel isolation ---

async def test_agent_channel_excludes_approval_tools(tmp_path):
    gw = _gateway(tmp_path)
    try:
        tools = sorted(t.name for t in await build_agent_server(gw).list_tools())
        assert tools == ["browse", "read_tag", "write_tag"]
        assert "approve" not in tools
        assert "deny" not in tools
        assert "list_pending" not in tools
    finally:
        gw.close()


async def test_operator_channel_has_only_operator_tools(tmp_path):
    gw = _gateway(tmp_path)
    try:
        tools = sorted(t.name for t in await build_operator_server(gw).list_tools())
        assert tools == ["approve", "deny", "get_audit_log", "list_pending"]
        assert "write_tag" not in tools
    finally:
        gw.close()


async def test_full_server_has_all_tools(tmp_path):
    gw = _gateway(tmp_path)
    try:
        tools = sorted(t.name for t in await build_server(gw).list_tools())
        assert tools == [
            "approve", "browse", "deny", "get_audit_log",
            "list_pending", "read_tag", "write_tag",
        ]
    finally:
        gw.close()


# --- HTTP channel end-to-end (auth enforced on the real MCP endpoint) ---

def test_agent_http_endpoint_requires_token(tmp_path):
    gw = _gateway(tmp_path)
    try:
        app = build_http_app(build_agent_server(gw), token="AGENT", realm="agent")
        with testclient.TestClient(app) as client:
            body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
            assert client.post("/mcp", json=body).status_code == 401
            assert client.post(
                "/mcp", json=body, headers={"Authorization": "Bearer WRONG"}
            ).status_code == 401
            # Correct token passes auth (status is whatever MCP returns, not 401).
            r = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                 "clientInfo": {"name": "t", "version": "1"}}},
                headers={"Authorization": "Bearer AGENT",
                         "Accept": "application/json, text/event-stream"},
            )
            assert r.status_code != 401
    finally:
        gw.close()
