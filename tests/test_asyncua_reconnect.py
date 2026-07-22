"""AsyncuaBackend reconnect/backoff behaviour, exercised without a real server.

We drive the private ``_with_reconnect`` path by stubbing ``_open`` and the
operation callable, so we can assert: a transport failure triggers a reconnect
and one retry; a missing tag (KeyError) is *not* retried; and exhausting
reconnects surfaces a BackendError.
"""

from __future__ import annotations

import pytest

pytest.importorskip("asyncua")

from otgate.backends.asyncua_backend import AsyncuaBackend
from otgate.backends.base import BackendError


def _backend():
    # reconnect quickly in tests
    return AsyncuaBackend("opc.tcp://localhost:4840", reconnect_attempts=2, reconnect_backoff=0.0)


async def test_operation_retries_after_reconnect(monkeypatch):
    b = _backend()
    opens = {"n": 0}

    async def fake_open():
        opens["n"] += 1
        b._client = object()  # any non-None marker

    monkeypatch.setattr(b, "_open", fake_open)
    await b.connect()  # opens once

    calls = {"n": 0}

    async def op(client):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionResetError("connection dropped")
        return "ok"

    result = await b._with_reconnect(op)
    assert result == "ok"
    assert calls["n"] == 2  # failed once, retried once
    assert opens["n"] >= 2  # reconnected at least once


async def test_missing_tag_is_not_retried(monkeypatch):
    b = _backend()

    async def fake_open():
        b._client = object()

    monkeypatch.setattr(b, "_open", fake_open)
    await b.connect()

    calls = {"n": 0}

    async def op(client):
        calls["n"] += 1
        raise KeyError("no such node")

    with pytest.raises(KeyError):
        await b._with_reconnect(op)
    assert calls["n"] == 1  # KeyError short-circuits; no retry


async def test_backend_error_when_reconnect_fails(monkeypatch):
    b = _backend()

    # first connect succeeds
    state = {"allow_open": True}

    async def fake_open():
        if not state["allow_open"]:
            raise ConnectionError("server gone")
        b._client = object()

    monkeypatch.setattr(b, "_open", fake_open)
    await b.connect()

    async def op(client):
        raise ConnectionResetError("dropped")

    # after the first failure, no further opens succeed
    state["allow_open"] = False
    with pytest.raises(BackendError):
        await b._with_reconnect(op)


async def test_health_false_when_unreachable(monkeypatch):
    b = _backend()

    async def fake_open():
        raise ConnectionError("unreachable")

    monkeypatch.setattr(b, "_open", fake_open)
    # never connected; health must not raise, just report False
    assert await b.health() is False
