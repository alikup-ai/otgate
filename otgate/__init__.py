"""otgate — OT-aware authorization gateway between an LLM agent and an OPC UA server.

otgate sits between an MCP client (the agent) and a real OPC UA server. It is
itself an MCP server: the agent talks to it as if it were an ordinary OPC UA
MCP, while otgate intercepts every call and applies a process-aware access
policy (value ranges, rate limits, interlocks, access levels) before touching
the backend. Every call is recorded in an append-only audit log.
"""

__version__ = "0.1.0"
