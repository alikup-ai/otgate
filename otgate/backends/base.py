"""Abstract backend interface.

Every backend otgate can talk to (fake simulator, real OPC UA server) implements
this small async protocol. Keeping it minimal — connect, disconnect, read,
write, health — is what lets the policy engine and the whole test suite stay
backend agnostic.

Error convention: a missing node raises :class:`KeyError` (a normal "no such
tag" answer, not a failure). A transport/connection failure — the thing that
must make otgate fail closed — raises :class:`BackendError`. Backends should
translate their library's connection exceptions into ``BackendError``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from otgate.models import Scalar


class BackendError(RuntimeError):
    """Raised when the backend cannot be reached or an operation fails at the
    transport level (as opposed to a missing tag, which is a ``KeyError``)."""


class Backend(ABC):
    """Abstract OPC-UA-like backend.

    Implementations must be safe to call after :meth:`connect` and before
    :meth:`disconnect`. All methods are async so a real network backend
    (asyncua) and the in-memory fake share one interface.
    """

    @abstractmethod
    async def connect(self) -> None:
        """Establish the underlying connection (no-op for in-memory backends)."""

    @abstractmethod
    async def disconnect(self) -> None:
        """Tear down the underlying connection (no-op for in-memory backends)."""

    @abstractmethod
    async def read(self, node_id: str) -> Scalar:
        """Return the current scalar value of ``node_id``.

        Raises:
            KeyError: if the node does not exist on the backend.
            BackendError: if the backend cannot be reached.
        """

    @abstractmethod
    async def write(self, node_id: str, value: Scalar) -> None:
        """Write ``value`` to ``node_id``.

        Raises:
            KeyError: if the node does not exist on the backend.
            BackendError: if the backend cannot be reached.
        """

    async def health(self) -> bool:
        """Return True if the backend is reachable.

        The default implementation reports healthy; network backends override it
        with a real liveness probe. Must not raise — it returns False on failure.
        """
        return True

    async def __aenter__(self) -> "Backend":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.disconnect()
