"""Backend abstraction for otgate.

A backend is the thing otgate ultimately reads from and writes to. It lives
behind the :class:`~otgate.backends.base.Backend` interface so the exact same
gateway, policy engine and test suite work against either an in-memory
simulator (:class:`~otgate.backends.fake.FakeBackend`) or a real OPC UA server
(:class:`~otgate.backends.asyncua_backend.AsyncuaBackend`), switched by config.
"""

from otgate.backends.base import Backend, BackendError
from otgate.backends.fake import FakeBackend

__all__ = ["Backend", "BackendError", "FakeBackend", "build_backend"]


def build_backend(kind: str, **kwargs) -> Backend:
    """Construct a backend by name.

    ``kind`` is typically read straight from config:

    - ``"fake"`` → :class:`~otgate.backends.fake.FakeBackend` (no dependencies).
    - ``"asyncua"`` → :class:`~otgate.backends.asyncua_backend.AsyncuaBackend`
      (imported lazily so ``asyncua`` is only required when actually used).

    Raises:
        ValueError: if ``kind`` is unknown.
    """
    kind = kind.lower()
    if kind == "fake":
        return FakeBackend(**kwargs)
    if kind == "asyncua":
        # Imported here (not at module top) so that missing ``asyncua`` never
        # breaks FakeBackend, the tests or the demo.
        from otgate.backends.asyncua_backend import AsyncuaBackend

        return AsyncuaBackend(**kwargs)
    raise ValueError(f"unknown backend kind: {kind!r} (expected 'fake' or 'asyncua')")
