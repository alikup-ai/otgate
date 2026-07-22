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
