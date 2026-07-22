"""MCP server: otgate exposed as an OPC-UA-like MCP for an agent to connect to.

The agent talks to this server as if it were an ordinary OPC UA MCP. Every tool
call is routed through :class:`~otgate.gateway.Gateway`, which applies the policy
and audits the call before (maybe) touching the real backend.

Configuration is read from environment variables so the backend can be switched
without changing code (the key architectural requirement in the spec):

    OTGATE_BACKEND        "fake" (default) | "asyncua"
    OTGATE_POLICY         path to the policy YAML (default: examples/reactor_policy.yaml)
    OTGATE_AUDIT          path to the audit JSONL (default: audit.jsonl)
    OTGATE_SHADOW         "1"/"true" to enable shadow mode (default: off)
    OTGATE_RATE_HISTORY   path to persist rate history (default: in-memory)
    OTGATE_OPCUA_ENDPOINT endpoint URL, required when backend == "asyncua"

Two transports are provided:

- **stdio** (``otgate`` / ``python -m otgate.server``): a single process with
  *all* tools. Fine for local use where there is no channel boundary to enforce.
- **HTTP** (``otgate-http``): two authenticated channels on separate ports — an
  agent channel (read/write/browse) and an operator channel (audit + approvals) —
  so an agent physically cannot reach the approval tools. Requires:

      OTGATE_AGENT_TOKEN     bearer token for the agent channel   (required)
      OTGATE_OPERATOR_TOKEN  bearer token for the operator channel (required, != agent)
      OTGATE_HOST            bind host  (default: 127.0.0.1)
      OTGATE_AGENT_PORT      default: 8770
      OTGATE_OPERATOR_PORT   default: 8771
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from otgate.audit import AuditLog
from otgate.auth import BearerAuthMiddleware
from otgate.backends import build_backend
from otgate.gateway import Gateway
from otgate.models import Scalar
from otgate.policy import load_policy
from otgate.rate_history import JsonlRateHistory

_DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "examples" / "reactor_policy.yaml"
_TRUE_VALUES = {"1", "true", "yes", "on"}


def _build_backend_from_env():
    """Construct the backend from ``OTGATE_BACKEND`` (+ endpoint for asyncua)."""
    backend_kind = os.environ.get("OTGATE_BACKEND", "fake")
    if backend_kind.lower() == "asyncua":
        endpoint = os.environ.get("OTGATE_OPCUA_ENDPOINT")
        if not endpoint:
            raise RuntimeError(
                "OTGATE_BACKEND=asyncua requires OTGATE_OPCUA_ENDPOINT to be set"
            )
        return build_backend("asyncua", endpoint=endpoint)
    return build_backend(backend_kind)


def _shared_resources_from_env():
    """Build the resources every gateway shares: backend, audit, rate history, approvals.

    In multi-agent mode all agents talk to the *same* backend, write to the
    *same* audit log, share one rate-history (rate limits are per tag, not per
    agent) and one approval store (so an operator sees every agent's pending
    requests).
    """
    from otgate.approval import ApprovalStore

    backend = _build_backend_from_env()
    audit = AuditLog(os.environ.get("OTGATE_AUDIT", "audit.jsonl"))
    shadow = os.environ.get("OTGATE_SHADOW", "").lower() in _TRUE_VALUES
    rate_history_path = os.environ.get("OTGATE_RATE_HISTORY")
    rate_history = JsonlRateHistory(rate_history_path) if rate_history_path else None
    approvals = ApprovalStore()
    return backend, audit, shadow, rate_history, approvals


def _build_gateway_from_env() -> Gateway:
    """Construct a single-agent :class:`Gateway` from environment configuration."""
    policy_path = os.environ.get("OTGATE_POLICY") or str(_DEFAULT_POLICY)
    backend, audit, shadow, rate_history, approvals = _shared_resources_from_env()
    policy = load_policy(policy_path)
    return Gateway(
        policy, backend, audit,
        shadow=shadow, rate_history=rate_history, approvals=approvals,
    )


def _build_agent_gateways_from_env() -> dict[str, Gateway]:
    """Build one :class:`Gateway` per agent from ``OTGATE_AGENTS`` (agents.yaml).

    All gateways share backend, audit, rate history and approval store; they
    differ only in policy and ``agent_id``. Returns a mapping of agent id ->
    gateway. Raises if ``OTGATE_AGENTS`` is unset.
    """
    from otgate.agents import load_agents

    agents_path = os.environ.get("OTGATE_AGENTS")
    if not agents_path:
        raise RuntimeError("multi-agent mode requires OTGATE_AGENTS to be set")

    agent_configs = load_agents(agents_path)
    backend, audit, shadow, rate_history, approvals = _shared_resources_from_env()

    gateways: dict[str, Gateway] = {}
    for cfg in agent_configs:
        gateways[cfg.id] = Gateway(
            cfg.policy, backend, audit,
            shadow=shadow, rate_history=rate_history, approvals=approvals,
            agent_id=cfg.id,
        )
    return gateways


def _register_agent_tools(mcp: FastMCP, gw: Gateway) -> None:
    """Register the tools an agent is allowed to use: read / write / browse.

    These deliberately exclude the approval tools — an agent must never be able
    to approve its own writes. Isolation is by channel, not by convention.
    """

    @mcp.tool()
    async def read_tag(node_id: str) -> str:
        """Read the current value of an OPC UA tag (subject to policy)."""
        result = await gw.read(node_id)
        if not result.decision.allowed:
            return f"DENY: {result.decision.reason}"
        return str(result.value)

    @mcp.tool()
    async def write_tag(node_id: str, value: Scalar) -> str:
        """Write a scalar value to an OPC UA tag (goes through the policy engine)."""
        result = await gw.write(node_id, value)
        d = result.decision
        prefix = d.type.value  # ALLOW / DENY / ASK
        if d.type.value == "ALLOW":
            state = "executed" if result.executed else "shadowed (not executed)"
            return f"ALLOW ({state}): {d.reason}"
        return f"{prefix}: {d.reason}"

    @mcp.tool()
    async def browse() -> list[str]:
        """List the tags the policy allows the agent to see (access != deny)."""
        return gw.browse()


def _register_operator_tools(mcp: FastMCP, gw: Gateway) -> None:
    """Register the human-operator tools: audit + the approval channel.

    These belong on a channel the agent does not have access to.
    """

    @mcp.tool()
    async def get_audit_log(limit: int = 50) -> list[dict]:
        """Return the most recent audit-log entries (oldest first)."""
        return gw.audit_tail(limit)

    @mcp.tool()
    async def list_pending() -> list[dict]:
        """List write requests parked awaiting human approval."""
        return gw.pending_approvals()

    @mcp.tool()
    async def approve(request_id: str) -> str:
        """Approve a parked write.

        Re-checks the policy against the current process state before executing,
        so a stale request that no longer passes (e.g. an interlock tripped) is
        blocked rather than executed.
        """
        result = await gw.approve(request_id)
        state = "executed" if result.executed else "not executed"
        return f"{result.status} ({state}): {result.reason}"

    @mcp.tool()
    async def deny(request_id: str) -> str:
        """Deny a parked write; it will never execute."""
        result = gw.deny(request_id)
        return f"{result.status}: {result.reason}"


def build_agent_server(gateway: Gateway) -> FastMCP:
    """FastMCP server with only the agent tools (read / write / browse)."""
    mcp = FastMCP("otgate-agent")
    _register_agent_tools(mcp, gateway)
    return mcp


def build_operator_server(gateway: Gateway) -> FastMCP:
    """FastMCP server with only the operator tools (audit + approvals)."""
    mcp = FastMCP("otgate-operator")
    _register_operator_tools(mcp, gateway)
    return mcp


def build_server(gateway: Gateway | None = None) -> FastMCP:
    """Create a single FastMCP server with *all* tools (stdio / single-process).

    Convenient for local use and the stdio transport, where there is no channel
    boundary to enforce. For real deployments prefer the two separate HTTP
    servers (:func:`build_agent_server` / :func:`build_operator_server`) so the
    agent physically cannot reach the approval tools.

    Args:
        gateway: an existing gateway; if omitted one is built from the
            environment. Injectable so tests can supply a FakeBackend gateway.
    """
    gw = gateway or _build_gateway_from_env()
    mcp = FastMCP("otgate")
    _register_agent_tools(mcp, gw)
    _register_operator_tools(mcp, gw)
    return mcp


def build_http_app(server: FastMCP, token: str, realm: str, gateway: Gateway | None = None):
    """Wrap a FastMCP server's streamable-HTTP ASGI app with Bearer auth.

    Args:
        server: the FastMCP server whose tools to expose.
        token: required bearer token for this channel.
        realm: label for the auth challenge / errors (e.g. "agent"/"operator").
        gateway: if given, an unauthenticated ``GET /health`` endpoint is added
            reporting gateway/backend liveness (status only, no tag data).

    Returns:
        A Starlette ASGI application, guarded by :class:`BearerAuthMiddleware`
        (which lets ``/health`` through).
    """
    app = server.streamable_http_app()

    if gateway is not None:
        from starlette.responses import JSONResponse

        async def health(request):
            status = await gateway.health()
            code = 200 if status["status"] == "ok" else 503
            return JSONResponse(status, status_code=code)

        app.add_route("/health", health, methods=["GET"])

    app.add_middleware(BearerAuthMiddleware, token=token, realm=realm)
    return app


def _uvicorn_server(app, host: str, port: int):
    import uvicorn

    return uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="info"))


async def _serve(servers) -> None:
    import asyncio

    await asyncio.gather(*(s.serve() for s in servers))


def main_http() -> None:
    """Entry point: run authenticated HTTP channels.

    Single-agent mode (default): requires ``OTGATE_AGENT_TOKEN`` and
    ``OTGATE_OPERATOR_TOKEN``; serves one agent channel and one operator channel.

    Multi-agent mode (``OTGATE_AGENTS`` set to an agents.yaml): serves one agent
    channel *per agent*, each on its own port from ``OTGATE_AGENT_PORT`` upward,
    each behind that agent's own token; plus one operator channel. The agent
    tokens come from agents.yaml, not the environment.

    Common: ``OTGATE_OPERATOR_TOKEN`` (required, must differ from every agent
    token), ``OTGATE_HOST``, ``OTGATE_AGENT_PORT``, ``OTGATE_OPERATOR_PORT``.
    """
    operator_token = os.environ.get("OTGATE_OPERATOR_TOKEN", "")
    if not operator_token:
        raise RuntimeError(
            "HTTP transport requires OTGATE_OPERATOR_TOKEN (refusing to run "
            "the operator channel unauthenticated)"
        )

    host = os.environ.get("OTGATE_HOST", "127.0.0.1")
    base_agent_port = int(os.environ.get("OTGATE_AGENT_PORT", "8770"))
    operator_port = int(os.environ.get("OTGATE_OPERATOR_PORT", "8771"))

    if os.environ.get("OTGATE_AGENTS"):
        _run_multiagent(host, base_agent_port, operator_port, operator_token)
    else:
        _run_single_agent(host, base_agent_port, operator_port, operator_token)


def _run_single_agent(host: str, agent_port: int, operator_port: int, operator_token: str) -> None:
    import asyncio

    agent_token = os.environ.get("OTGATE_AGENT_TOKEN", "")
    if not agent_token:
        raise RuntimeError(
            "single-agent HTTP requires OTGATE_AGENT_TOKEN "
            "(or set OTGATE_AGENTS for multi-agent mode)"
        )
    if agent_token == operator_token:
        raise RuntimeError(
            "OTGATE_AGENT_TOKEN and OTGATE_OPERATOR_TOKEN must differ "
            "(otherwise the agent could reach the operator channel)"
        )

    gateway = _build_gateway_from_env()
    agent_app = build_http_app(build_agent_server(gateway), agent_token, "agent", gateway)
    operator_app = build_http_app(
        build_operator_server(gateway), operator_token, "operator", gateway
    )

    print(f"otgate agent channel    : http://{host}:{agent_port}/mcp")
    print(f"otgate operator channel : http://{host}:{operator_port}/mcp")
    try:
        asyncio.run(
            _serve([
                _uvicorn_server(agent_app, host, agent_port),
                _uvicorn_server(operator_app, host, operator_port),
            ])
        )
    finally:
        gateway.close()


def _run_multiagent(host: str, base_agent_port: int, operator_port: int, operator_token: str) -> None:
    import asyncio

    gateways = _build_agent_gateways_from_env()

    # The operator token must not collide with any agent token.
    from otgate.agents import load_agents

    agent_tokens = {c.id: c.token for c in load_agents(os.environ["OTGATE_AGENTS"])}
    if operator_token in agent_tokens.values():
        raise RuntimeError(
            "OTGATE_OPERATOR_TOKEN must differ from every agent token in agents.yaml"
        )

    # Agent ports occupy [base_agent_port, base_agent_port + N). The operator
    # port must not fall inside that range.
    n_agents = len(gateways)
    agent_port_range = range(base_agent_port, base_agent_port + n_agents)
    if operator_port in agent_port_range:
        raise RuntimeError(
            f"OTGATE_OPERATOR_PORT ({operator_port}) collides with the agent port "
            f"range {base_agent_port}..{base_agent_port + n_agents - 1} "
            f"({n_agents} agents). Set OTGATE_OPERATOR_PORT outside that range."
        )

    servers = []
    port = base_agent_port
    for agent_id, gw in gateways.items():
        app = build_http_app(
            build_agent_server(gw), agent_tokens[agent_id], f"agent:{agent_id}", gw
        )
        servers.append(_uvicorn_server(app, host, port))
        print(f"otgate agent '{agent_id}' : http://{host}:{port}/mcp")
        port += 1

    # One operator channel over shared audit + approval store (any gateway works,
    # since audit and the approval store are shared; give it an explicit id).
    any_gw = next(iter(gateways.values()))
    operator_app = build_http_app(
        build_operator_server(any_gw), operator_token, "operator", any_gw
    )
    servers.append(_uvicorn_server(operator_app, host, operator_port))
    print(f"otgate operator channel : http://{host}:{operator_port}/mcp")

    try:
        asyncio.run(_serve(servers))
    finally:
        for gw in gateways.values():
            gw.close()


def main() -> None:
    """Console-script entry point: run the MCP server over stdio (all tools).

    For a channel-isolated, authenticated deployment use :func:`main_http` /
    the ``otgate-http`` console script instead.
    """
    server = build_server()
    server.run()


if __name__ == "__main__":
    main()
