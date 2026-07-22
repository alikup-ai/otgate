"""Real OPC UA backend, built on the ``asyncua`` library.

This module is imported lazily (see :func:`otgate.backends.build_backend`) so
that ``asyncua`` is an *optional* dependency: FakeBackend, the tests and the demo
all run without it installed. Installing it is a one-liner::

    pip install "otgate[opcua]"

and switching to a real server is a config change (backend kind ``asyncua``),
not a code change.

Resilience: OPC UA connections drop. Each operation, if it fails at the
transport level, triggers a bounded reconnect (retry with backoff) and one
retry. If the backend still cannot be reached the operation raises
:class:`~otgate.backends.base.BackendError`, which the gateway turns into a
fail-closed ERROR decision — never a silent success. A missing tag remains a
``KeyError`` and does *not* trigger reconnects.
"""

from __future__ import annotations

import asyncio

from otgate.backends.base import Backend, BackendError
from otgate.models import Scalar


class AsyncuaBackend(Backend):
    """OPC UA backend that proxies reads/writes to a real server via asyncua.

    Args:
        endpoint: OPC UA endpoint URL, e.g. ``opc.tcp://localhost:4840``.
        reconnect_attempts: how many times to try re-establishing the connection
            when an operation fails at the transport level.
        reconnect_backoff: initial delay (seconds) between reconnect attempts;
            doubles each attempt.

    Raises:
        ImportError: at construction time if ``asyncua`` is not installed, with
            an actionable message.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        reconnect_attempts: int = 3,
        reconnect_backoff: float = 0.5,
    ) -> None:
        try:
            from asyncua import Client  # noqa: F401  (import-time availability check)
        except ImportError as exc:  # pragma: no cover - exercised only without asyncua
            raise ImportError(
                "The asyncua backend requires the 'asyncua' package. "
                'Install it with:  pip install "otgate[opcua]"'
            ) from exc

        self._endpoint = endpoint
        self._client = None  # created in connect()
        self._reconnect_attempts = max(0, reconnect_attempts)
        self._reconnect_backoff = reconnect_backoff

    async def connect(self) -> None:
        await self._open()

    async def disconnect(self) -> None:
        await self._close()

    async def read(self, node_id: str) -> Scalar:
        return await self._with_reconnect(lambda c: c.get_node(node_id).read_value())

    async def write(self, node_id: str, value: Scalar) -> None:
        await self._with_reconnect(lambda c: c.get_node(node_id).write_value(value))

    async def health(self) -> bool:
        """Liveness probe: read the server's namespace array. Never raises."""
        try:
            await self._with_reconnect(lambda c: c.get_namespace_array())
            return True
        except BackendError:
            return False

    # --- internals ---

    async def _open(self) -> None:
        from asyncua import Client

        client = Client(url=self._endpoint)
        await client.connect()
        self._client = client

    async def _close(self) -> None:
        if self._client is not None:
            try:
                await self._client.disconnect()
            except Exception:  # pragma: no cover - best-effort teardown
                pass
            self._client = None

    async def _with_reconnect(self, op):
        """Run ``op(client)`` (awaitable), reconnecting once on transport failure.

        ``op`` receives the live client. A missing tag (KeyError) propagates
        unchanged. Any other exception is treated as a transport failure: we try
        to reconnect (bounded) and retry once; failing that we raise BackendError.
        """
        if self._client is None:
            if not await self._try_reconnect():
                raise BackendError(f"backend {self._endpoint} is not connected")

        try:
            return await op(self._client)
        except KeyError:
            raise
        except Exception as first_exc:
            # Assume the connection is bad; drop it and try to re-establish.
            await self._close()
            if not await self._try_reconnect():
                raise BackendError(
                    f"backend {self._endpoint} unreachable: {first_exc}"
                ) from first_exc
            try:
                return await op(self._client)
            except KeyError:
                raise
            except Exception as retry_exc:
                await self._close()
                raise BackendError(
                    f"backend {self._endpoint} failed after reconnect: {retry_exc}"
                ) from retry_exc

    async def _try_reconnect(self) -> bool:
        delay = self._reconnect_backoff
        for _ in range(self._reconnect_attempts):
            try:
                await self._open()
                return True
            except Exception:
                await asyncio.sleep(delay)
                delay *= 2
        # One last direct attempt (covers reconnect_attempts == 0).
        try:
            await self._open()
            return True
        except Exception:
            return False
