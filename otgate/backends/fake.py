"""In-memory reactor simulator.

A dependency-free backend used by the tests and the demo. It holds a handful of
reactor tags in a dict and lets tests drive the process — e.g. set ``ESD=True``
and check that an interlock fires. Reads and writes are synchronous in-memory
operations wrapped in the async :class:`~otgate.backends.base.Backend` interface.
"""

from __future__ import annotations

from otgate.backends.base import Backend, BackendError
from otgate.models import Scalar

# Default tag set: a minimal reactor. Matches examples/reactor_policy.yaml.
DEFAULT_TAGS: dict[str, Scalar] = {
    "ns=2;s=Reactor.TIC101.PV": 55.0,  # temperature process value (read)
    "ns=2;s=Reactor.TIC101.SP": 55.0,  # temperature setpoint (write_with_approval)
    "ns=2;s=Reactor.PIC201.PV": 3.2,  # pressure process value (read)
    "ns=2;s=Reactor.ESD": False,  # emergency shutdown, bool (read)
}


class FakeBackend(Backend):
    """Dictionary-backed reactor simulator.

    Args:
        tags: initial tag → value mapping. Defaults to a copy of
            :data:`DEFAULT_TAGS` so instances never share mutable state.
    """

    def __init__(self, tags: dict[str, Scalar] | None = None) -> None:
        self._tags: dict[str, Scalar] = dict(tags) if tags is not None else dict(DEFAULT_TAGS)
        # When True, every read/write raises BackendError — used by tests (and
        # the demo) to simulate the real backend going down.
        self._down = False

    async def connect(self) -> None:  # no external resource to open
        return None

    async def disconnect(self) -> None:  # no external resource to close
        return None

    async def read(self, node_id: str) -> Scalar:
        self._guard()
        if node_id not in self._tags:
            raise KeyError(f"unknown tag on fake backend: {node_id!r}")
        return self._tags[node_id]

    async def write(self, node_id: str, value: Scalar) -> None:
        self._guard()
        if node_id not in self._tags:
            raise KeyError(f"unknown tag on fake backend: {node_id!r}")
        self._tags[node_id] = value

    async def health(self) -> bool:
        return not self._down

    # --- test / demo helpers (not part of the Backend interface) ---

    def set(self, node_id: str, value: Scalar) -> None:
        """Force a value directly, bypassing policy. For tests/demo setup only."""
        self._tags[node_id] = value

    def snapshot(self) -> dict[str, Scalar]:
        """Return a copy of the current tag values."""
        return dict(self._tags)

    def set_down(self, down: bool = True) -> None:
        """Simulate the backend going down (True) or recovering (False)."""
        self._down = down

    def _guard(self) -> None:
        if self._down:
            raise BackendError("fake backend is down (simulated outage)")
