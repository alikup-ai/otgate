"""Shadow-mode tests: an allowed write is recorded but never executed."""

from __future__ import annotations

import pytest

from otgate.audit import AuditLog
from otgate.backends.fake import FakeBackend
from otgate.gateway import Gateway
from otgate.models import Access, DecisionType, Policy, Rule

from conftest import SP


def _write_policy():
    # access=write so the engine returns ALLOW (not ASK) and shadow mode is what
    # suppresses execution.
    return Policy(rules={SP: Rule(tag=SP, access=Access.WRITE, value_range=(40.0, 80.0))})


async def test_shadow_allow_does_not_change_backend(tmp_path):
    backend = FakeBackend()
    before = backend.snapshot()[SP]
    gw = Gateway(_write_policy(), backend, AuditLog(tmp_path / "a.jsonl"), shadow=True)

    result = await gw.write(SP, 70.0)

    assert result.decision.type is DecisionType.ALLOW
    assert result.executed is False
    assert backend.snapshot()[SP] == before  # backend untouched


async def test_shadow_allow_audited_executed_false(tmp_path):
    gw = Gateway(_write_policy(), FakeBackend(), AuditLog(tmp_path / "a.jsonl"), shadow=True)
    await gw.write(SP, 70.0)

    entry = gw.audit_tail()[-1]
    assert entry["decision"] == "ALLOW"
    assert entry["shadow"] is True
    assert entry["executed"] is False
    assert "WOULD execute" in entry["reason"]


async def test_non_shadow_allow_executes(tmp_path):
    """Sanity counterpart: without shadow the same write is executed."""
    backend = FakeBackend()
    gw = Gateway(_write_policy(), backend, AuditLog(tmp_path / "a.jsonl"), shadow=False)

    result = await gw.write(SP, 70.0)

    assert result.executed is True
    assert backend.snapshot()[SP] == 70.0
    entry = gw.audit_tail()[-1]
    assert entry["executed"] is True
    assert entry["shadow"] is False


async def test_shadow_does_not_affect_reads(tmp_path):
    """Reads still execute in shadow mode (shadow only suppresses writes)."""
    from otgate.policy import load_policy
    from conftest import POLICY_PATH, PV

    gw = Gateway(load_policy(POLICY_PATH), FakeBackend(), AuditLog(tmp_path / "a.jsonl"), shadow=True)
    result = await gw.read(PV)
    assert result.decision.type is DecisionType.ALLOW
    assert result.executed is True
    assert result.value == 55.0
