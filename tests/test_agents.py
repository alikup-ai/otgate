"""Multi-agent tests: per-agent policies, audit attribution, agents.yaml validation."""

from __future__ import annotations

import textwrap

import pytest

from otgate.agents import AgentsError, load_agents
from otgate.approval import ApprovalStore
from otgate.audit import AuditLog
from otgate.backends.fake import FakeBackend
from otgate.gateway import Gateway
from otgate.models import Access, DecisionType

from conftest import PV, SP


# --- agents.yaml loading / validation ---

def _write(tmp_path, name, content):
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


@pytest.fixture
def read_policy(tmp_path):
    return _write(tmp_path, "read.yaml", '- tag: "t"\n  access: read\n')


def test_load_valid_agents(tmp_path, read_policy):
    f = _write(
        tmp_path,
        "agents.yaml",
        f"""
        - id: a
          token: tok-a
          policy: {read_policy.name}
        - id: b
          token: tok-b
          policy: {read_policy.name}
        """,
    )
    agents = load_agents(f)
    assert [a.id for a in agents] == ["a", "b"]
    assert agents[0].token == "tok-a"
    assert agents[0].policy.get("t").access is Access.READ


def test_empty_agents_error(tmp_path):
    with pytest.raises(AgentsError, match="empty"):
        load_agents(_write(tmp_path, "a.yaml", ""))


def test_non_list_agents_error(tmp_path):
    with pytest.raises(AgentsError, match="must be a list"):
        load_agents(_write(tmp_path, "a.yaml", "id: x"))


def test_missing_id_error(tmp_path, read_policy):
    with pytest.raises(AgentsError, match="'id' is required"):
        load_agents(_write(tmp_path, "a.yaml", f"- token: t\n  policy: {read_policy.name}"))


def test_missing_token_error(tmp_path, read_policy):
    with pytest.raises(AgentsError, match="'token' is required"):
        load_agents(_write(tmp_path, "a.yaml", f"- id: a\n  policy: {read_policy.name}"))


def test_missing_policy_error(tmp_path):
    with pytest.raises(AgentsError, match="'policy' is required"):
        load_agents(_write(tmp_path, "a.yaml", "- id: a\n  token: t"))


def test_unknown_policy_file_error(tmp_path):
    with pytest.raises(AgentsError, match="failed to load"):
        load_agents(_write(tmp_path, "a.yaml", "- id: a\n  token: t\n  policy: nope.yaml"))


def test_duplicate_id_error(tmp_path, read_policy):
    content = f"""
    - id: a
      token: t1
      policy: {read_policy.name}
    - id: a
      token: t2
      policy: {read_policy.name}
    """
    with pytest.raises(AgentsError, match="duplicate id"):
        load_agents(_write(tmp_path, "a.yaml", content))


def test_duplicate_token_error(tmp_path, read_policy):
    content = f"""
    - id: a
      token: same
      policy: {read_policy.name}
    - id: b
      token: same
      policy: {read_policy.name}
    """
    with pytest.raises(AgentsError, match="duplicate token"):
        load_agents(_write(tmp_path, "a.yaml", content))


def test_unknown_key_error(tmp_path, read_policy):
    with pytest.raises(AgentsError, match="unknown key"):
        load_agents(
            _write(tmp_path, "a.yaml", f"- id: a\n  token: t\n  policy: {read_policy.name}\n  x: 1")
        )


# --- multi-agent gateway behaviour ---

def _shared(tmp_path):
    return (
        FakeBackend(),
        AuditLog(tmp_path / "audit.jsonl"),
        ApprovalStore(),
    )


def _agent_gateway(policy, backend, audit, approvals, agent_id):
    return Gateway(policy, backend, audit, approvals=approvals, agent_id=agent_id)


async def test_per_agent_policies_differ(tmp_path):
    from otgate.policy import load_policy
    from conftest import POLICY_PATH

    # diagnostics: read-only SP; optimizer: the example policy (write_with_approval)
    read_only = load_policy(POLICY_PATH)  # reuse; but make a read-only variant inline
    from otgate.models import Policy, Rule

    diag_policy = Policy(rules={SP: Rule(tag=SP, access=Access.READ),
                                PV: Rule(tag=PV, access=Access.READ)})
    opt_policy = load_policy(POLICY_PATH)

    backend, audit, approvals = _shared(tmp_path)
    diag = _agent_gateway(diag_policy, backend, audit, approvals, "diagnostics")
    opt = _agent_gateway(opt_policy, backend, audit, approvals, "optimizer")
    try:
        assert (await diag.write(SP, 60.0)).decision.type is DecisionType.DENY
        assert (await opt.write(SP, 60.0)).decision.type is DecisionType.ASK
    finally:
        audit.close()


async def test_audit_attributes_agent(tmp_path):
    from otgate.policy import load_policy
    from conftest import POLICY_PATH

    backend, audit, approvals = _shared(tmp_path)
    opt = _agent_gateway(load_policy(POLICY_PATH), backend, audit, approvals, "optimizer")
    try:
        await opt.read(PV)
        entry = opt.audit_tail()[-1]
        assert entry["agent"] == "optimizer"
    finally:
        audit.close()


async def test_shared_approval_store_and_attribution(tmp_path):
    from otgate.policy import load_policy
    from conftest import POLICY_PATH

    backend, audit, approvals = _shared(tmp_path)
    opt = _agent_gateway(load_policy(POLICY_PATH), backend, audit, approvals, "optimizer")
    try:
        w = await opt.write(SP, 60.0)  # ASK -> parked
        pending = opt.pending_approvals()
        assert len(pending) == 1
        assert pending[0]["agent_id"] == "optimizer"

        res = await opt.approve(w.approval_id)
        assert res.executed is True
        # The executed write is attributed to the requesting agent, not an operator.
        assert opt.audit_tail()[-1]["agent"] == "optimizer"
    finally:
        audit.close()


async def test_single_agent_mode_agent_is_none(tmp_path):
    """Backwards compatibility: no agent_id -> audit 'agent' is None."""
    from otgate.policy import load_policy
    from conftest import POLICY_PATH

    gw = Gateway(load_policy(POLICY_PATH), FakeBackend(), AuditLog(tmp_path / "a.jsonl"))
    try:
        await gw.read(PV)
        assert gw.audit_tail()[-1]["agent"] is None
    finally:
        gw.close()


# --- multi-agent server config guards (no network) ---

def test_operator_port_collision_rejected(tmp_path, read_policy, monkeypatch):
    """The operator port must not fall inside the agent port range."""
    from otgate.server import _run_multiagent

    agents = _write(
        tmp_path,
        "agents.yaml",
        f"""
        - id: a
          token: tok-a
          policy: {read_policy.name}
        - id: b
          token: tok-b
          policy: {read_policy.name}
        """,
    )
    monkeypatch.setenv("OTGATE_BACKEND", "fake")
    monkeypatch.setenv("OTGATE_AGENTS", str(agents))
    monkeypatch.setenv("OTGATE_AUDIT", str(tmp_path / "audit.jsonl"))
    # agents occupy 8770, 8771; operator on 8771 collides.
    with pytest.raises(RuntimeError, match="collides with the agent port range"):
        _run_multiagent(host="127.0.0.1", base_agent_port=8770,
                        operator_port=8771, operator_token="op-token")


def test_operator_token_collision_rejected(tmp_path, read_policy, monkeypatch):
    """The operator token must differ from every agent token."""
    from otgate.server import _run_multiagent

    agents = _write(
        tmp_path,
        "agents.yaml",
        f"""
        - id: a
          token: shared-token
          policy: {read_policy.name}
        """,
    )
    monkeypatch.setenv("OTGATE_BACKEND", "fake")
    monkeypatch.setenv("OTGATE_AGENTS", str(agents))
    monkeypatch.setenv("OTGATE_AUDIT", str(tmp_path / "audit.jsonl"))
    with pytest.raises(RuntimeError, match="differ from every agent token"):
        _run_multiagent(host="127.0.0.1", base_agent_port=8770,
                        operator_port=8899, operator_token="shared-token")
