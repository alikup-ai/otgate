"""Shared fixtures and constants for the otgate test suite."""

from __future__ import annotations

import pytest

from otgate.backends.fake import FakeBackend
from otgate.policy import load_policy

# Tags from the example reactor policy / FakeBackend.
SP = "ns=2;s=Reactor.TIC101.SP"
PV = "ns=2;s=Reactor.TIC101.PV"
PIC = "ns=2;s=Reactor.PIC201.PV"
ESD = "ns=2;s=Reactor.ESD"

# Location of the shipped example policy, resolved relative to the repo root.
from pathlib import Path

POLICY_PATH = Path(__file__).resolve().parent.parent / "examples" / "reactor_policy.yaml"


def commit_write(engine, backend, tag, value):
    """Record a write the way :class:`~otgate.gateway.Gateway` does.

    In production ``record_write`` is called only *after* a successful
    ``backend.write`` (see ``Gateway._execute``), so the live value and the rate
    history always agree right after a write. Tests must move both: since v0.2
    the engine reads the live value as its rate baseline, and advancing only the
    history would create a divergence that cannot occur in production.
    """
    backend.set(tag, value)
    engine.record_write(tag, value)


class ManualClock:
    """A controllable monotonic clock for deterministic rate tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def policy():
    """The example reactor policy, freshly loaded."""
    return load_policy(POLICY_PATH)


@pytest.fixture
def backend():
    """A fresh FakeBackend with default reactor tags."""
    return FakeBackend()


@pytest.fixture
def clock():
    """A ManualClock for rate-of-change tests."""
    return ManualClock()
