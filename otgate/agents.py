"""Multi-agent configuration: loading and validating ``agents.yaml``.

Each agent authenticates with its own bearer token and is bound to its own
policy file, so different agents get different rights (a diagnostics agent that
may only read; an optimisation agent that may write setpoints) and every audit
line is attributed to the agent that made the call.

The document is a YAML list::

    - id: diagnostics
      token: "…secret A…"
      policy: examples/policies/diagnostics.yaml
    - id: optimizer
      token: "…secret B…"
      policy: examples/policies/optimizer.yaml

Validation is strict and fail-closed: duplicate ids, duplicate/empty tokens, a
missing policy file, or an unreadable document all raise :class:`AgentsError`
rather than silently starting a mis-scoped or unauthenticated agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from otgate.models import Policy
from otgate.policy import PolicyError, load_policy


class AgentsError(ValueError):
    """Raised when the agents document is malformed or invalid."""


@dataclass(frozen=True)
class AgentConfig:
    """One agent: its id, bearer token, and loaded policy."""

    id: str
    token: str
    policy: Policy
    policy_path: str


def load_agents(path: str | Path) -> list[AgentConfig]:
    """Load and validate ``agents.yaml`` into a list of :class:`AgentConfig`.

    Policy paths are resolved relative to the agents file's directory when not
    absolute, so a config can be moved around as a unit.

    Raises:
        AgentsError: on any malformed or invalid entry.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise AgentsError(f"cannot read agents file {str(path)!r}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise AgentsError(f"invalid YAML in {str(path)!r}: {exc}") from exc

    if raw is None:
        raise AgentsError("agents file is empty (expected a list of agents)")
    if not isinstance(raw, list):
        raise AgentsError(f"agents file must be a list, got {type(raw).__name__}")

    base_dir = path.parent
    agents: list[AgentConfig] = []
    seen_ids: set[str] = set()
    seen_tokens: set[str] = set()

    for index, item in enumerate(raw):
        agent = _parse_agent(item, index, base_dir)
        if agent.id in seen_ids:
            raise AgentsError(f"agent #{index}: duplicate id {agent.id!r}")
        if agent.token in seen_tokens:
            raise AgentsError(
                f"agent #{index}: duplicate token (agent {agent.id!r} shares a "
                "token with another agent)"
            )
        seen_ids.add(agent.id)
        seen_tokens.add(agent.token)
        agents.append(agent)

    if not agents:
        raise AgentsError("agents file defines no agents")
    return agents


_ALLOWED_KEYS = {"id", "token", "policy"}


def _parse_agent(item: object, index: int, base_dir: Path) -> AgentConfig:
    where = f"agent #{index}"
    if not isinstance(item, dict):
        raise AgentsError(f"{where}: each entry must be a mapping, got {type(item).__name__}")

    unknown = set(item) - _ALLOWED_KEYS
    if unknown:
        raise AgentsError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")

    agent_id = item.get("id")
    if not isinstance(agent_id, str) or not agent_id.strip():
        raise AgentsError(f"{where}: 'id' is required and must be a non-empty string")
    where = f"agent {agent_id!r}"

    token = item.get("token")
    if not isinstance(token, str) or not token.strip():
        raise AgentsError(f"{where}: 'token' is required and must be a non-empty string")

    policy_raw = item.get("policy")
    if not isinstance(policy_raw, str) or not policy_raw.strip():
        raise AgentsError(f"{where}: 'policy' is required and must be a path string")

    policy_path = Path(policy_raw)
    if not policy_path.is_absolute():
        policy_path = base_dir / policy_path
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        raise AgentsError(f"{where}: policy {str(policy_path)!r} failed to load: {exc}") from exc

    return AgentConfig(
        id=agent_id,
        token=token,
        policy=policy,
        policy_path=str(policy_path),
    )
