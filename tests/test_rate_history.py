"""Rate-history persistence tests.

These prove the security gap the feature closes: without persistence, a restart
wipes the rate history so the first post-restart write is never rate-checked;
with JsonlRateHistory the limit survives the restart.
"""

from __future__ import annotations

import pytest

from otgate.engine import PolicyEngine
from otgate.models import Action, ActionType, DecisionType
from otgate.rate_history import (
    InMemoryRateHistory,
    JsonlRateHistory,
    WriteRecord,
)

from conftest import SP, ManualClock


# --- store-level tests ---

def test_inmemory_get_put():
    h = InMemoryRateHistory()
    assert h.get("t") is None
    h.put("t", WriteRecord(100.0, 5.0))
    assert h.get("t") == WriteRecord(100.0, 5.0)


def test_jsonl_persists_across_instances(tmp_path):
    path = tmp_path / "rate.jsonl"
    h1 = JsonlRateHistory(path)
    h1.put(SP, WriteRecord(1000.0, 50.0))
    h1.put(SP, WriteRecord(1001.0, 51.0))  # newer wins on reload

    # A fresh instance (simulating a restart) reloads the latest record.
    h2 = JsonlRateHistory(path)
    rec = h2.get(SP)
    assert rec == WriteRecord(1001.0, 51.0)


def test_jsonl_latest_per_tag(tmp_path):
    path = tmp_path / "rate.jsonl"
    h = JsonlRateHistory(path)
    h.put("a", WriteRecord(1.0, 10.0))
    h.put("b", WriteRecord(2.0, 20.0))
    h.put("a", WriteRecord(3.0, 11.0))
    reloaded = JsonlRateHistory(path)
    assert reloaded.get("a") == WriteRecord(3.0, 11.0)
    assert reloaded.get("b") == WriteRecord(2.0, 20.0)


def test_jsonl_skips_corrupt_lines(tmp_path):
    path = tmp_path / "rate.jsonl"
    path.write_text(
        '{"tag": "a", "wall_ts": 1.0, "value": 10.0}\n'
        "not json at all\n"
        '{"tag": "a", "wall_ts": 2.0}\n'  # missing value -> skipped
        '{"tag": "a", "wall_ts": 3.0, "value": 12.0}\n',
        encoding="utf-8",
    )
    h = JsonlRateHistory(path)
    # Latest *valid* line for "a" wins.
    assert h.get("a") == WriteRecord(3.0, 12.0)


def test_jsonl_missing_file_is_empty(tmp_path):
    h = JsonlRateHistory(tmp_path / "nope.jsonl")
    assert h.get("anything") is None


# --- engine-level: the actual security property ---

async def test_rate_limit_survives_restart(policy, backend, tmp_path):
    """After a restart, a too-fast write is still DENIED — the gap is closed."""
    path = tmp_path / "rate.jsonl"
    clock = ManualClock()

    # First engine instance: an approved write is executed and recorded.
    engine1 = PolicyEngine(policy, backend, clock=clock, history=JsonlRateHistory(path))
    engine1.record_write(SP, 50.0)

    # Simulate a restart: brand-new engine, same persistent history, clock has
    # only advanced one second (the attacker restarts and immediately retries).
    clock.advance(1.0)
    engine2 = PolicyEngine(policy, backend, clock=clock, history=JsonlRateHistory(path))

    decision = await engine2.evaluate(Action(ActionType.WRITE, SP, 78.0))  # +28 in 1s
    assert decision.type is DecisionType.DENY
    assert "rate" in decision.reason


async def test_without_persistence_restart_loses_limit(policy, backend):
    """Counter-example: in-memory history is empty after 'restart', so the same
    too-fast write is NOT rate-denied (only ASK). This documents the gap that
    persistence closes."""
    clock = ManualClock()
    engine1 = PolicyEngine(policy, backend, clock=clock, history=InMemoryRateHistory())
    engine1.record_write(SP, 50.0)

    clock.advance(1.0)
    engine2 = PolicyEngine(policy, backend, clock=clock, history=InMemoryRateHistory())
    decision = await engine2.evaluate(Action(ActionType.WRITE, SP, 78.0))
    # No history -> rate check is skipped -> only the approval gate remains.
    assert decision.type is DecisionType.ASK


async def test_persisted_history_allows_slow_change_after_interval(policy, backend, tmp_path):
    """A restart must not over-block either: a legitimate slow change still passes."""
    path = tmp_path / "rate.jsonl"
    clock = ManualClock()
    engine1 = PolicyEngine(policy, backend, clock=clock, history=JsonlRateHistory(path))
    engine1.record_write(SP, 50.0)

    clock.advance(60.0)  # a full rate_interval later
    engine2 = PolicyEngine(policy, backend, clock=clock, history=JsonlRateHistory(path))
    decision = await engine2.evaluate(Action(ActionType.WRITE, SP, 54.9))  # +4.9 <= 5
    assert decision.type is DecisionType.ASK  # passes rate, then asks for approval
