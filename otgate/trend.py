"""The plant's own history as a rate-of-change baseline.

Until now the rate check had two baselines: the value the tag holds right now
(read from the backend) and the last write otgate itself let through. Both are
points. Neither says what happened *between* them, and that gap is where the
defect lives:

    An operator ramps a setpoint 50 -> 194 on the HMI and back to 50, all
    inside one rate interval. otgate's recorded write is old or absent, the
    live value reads 50 again, so an agent's +2 nudge looks like a 2-unit step
    and passes a "no faster than 5 per 60 s" policy. The process moved 144
    units in that minute and the gateway never saw it.

This module closes that gap by asking a historian what the tag has actually
been doing. It is opt-in per tag (``history_rate: true`` in the policy),
because it costs a round trip to a historian that not every deployment has.

**Direction matters, and it is the whole reason this is safe to use.**
ottrend's ``max_rate`` returns a *lower bound* on the true maximum rate: "too
fast" is definitive, "slow enough" only means nothing faster was visible at
this bucket size in the data the historian kept. So the engine uses this to
**refuse** a write, never to justify one. A tag whose history looks calm is
still subject to every other check.

Three layers, so the engine never imports ottrend:

* :class:`ProcessTrend` — the two-method protocol the engine depends on.
* :class:`OttrendTrend` — that protocol over any ottrend provider, including
  ``MemoryTrend`` (which is how the tests run without a historian) and
  ``OpcUaHistoryTrend``.
* :class:`OpcUaHistorian` — a lazily connecting OPC UA HA historian for
  deployments configured from the environment. Deliberately its own
  connection rather than the backend's: a historian is usually a different
  server from the one holding the live tags (always so for PI and Ignition),
  and sharing a control-plane session for bulk history reads is not a
  favour to either.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

__all__ = [
    "HistoryUnavailable",
    "ObservedMovement",
    "OpcUaHistorian",
    "OttrendTrend",
    "ProcessTrend",
]


class HistoryUnavailable(RuntimeError):
    """The historian could not answer.

    Every reason lands here: unreachable, no such tag, cannot express the
    query, or too little good data in the window to answer honestly. The
    engine treats it the way it treats an unverifiable interlock — deny — so
    the distinctions matter for the message, not for the verdict.
    """


@dataclass(frozen=True)
class ObservedMovement:
    """How fast a tag is on record as having moved, and how good that record is.

    Attributes:
        rate_per_interval: the fastest movement visible in the window,
            expressed as a rate over the interval that was asked about — the
            same units a policy's ``max_rate`` / ``rate_interval`` pair is
            written in, so the two are directly comparable. A **lower bound**
            on the truth: see the module docstring.
        bucket: bucket size the answer was computed at, in seconds. The
            sharpness of the number; a coarser bucket can only understate a
            fast transient.
        good_fraction: share of the window covered by good-quality data.
        at: ISO-8601 start of the interval the maximum was observed in, so a
            human reading a denial can go and look at it. ``None`` when
            nothing was recorded.
        recorded: False when the historian holds no samples at all in the
            window. ``rate_per_interval`` is then 0.0, because there is no
            recorded movement — evidence of a quiet tag, not proof of one.
    """

    rate_per_interval: float
    bucket: float
    good_fraction: float
    at: str | None
    recorded: bool = True

    @property
    def describe(self) -> str:
        if not self.recorded:
            return "nothing recorded in the window"
        where = f"fastest at {self.at}, " if self.at else ""
        return (
            f"{self.rate_per_interval:g} "
            f"({where}bucket {self.bucket:g}s, {self.good_fraction:.0%} good data)"
        )


class ProcessTrend(Protocol):
    """What the engine needs from a historian. Two methods, both read-only."""

    async def observed_movement(
        self, tag: str, *, window: float, bucket: float
    ) -> ObservedMovement:
        """Largest movement of ``tag`` recorded in the last ``window`` seconds.

        Raises:
            HistoryUnavailable: the historian could not answer.
        """
        ...

    async def close(self) -> None:
        """Release whatever connection this holds. Must not raise."""
        ...


class OttrendTrend:
    """:class:`ProcessTrend` over an `ottrend <https://github.com/alikup-ai/ottrend>`_ provider.

    Args:
        provider: any ottrend ``TrendProvider`` — ``MemoryTrend`` for tests and
            demos, ``OpcUaHistoryTrend`` for a real OPC UA historian, the PI or
            Ignition adapters once they exist.
        clock: wall-clock source in seconds, injectable for deterministic
            tests. Matches the engine's clock so both agree on "now".
        min_good_fraction: how much of the window must be good-quality data
            before an answer is given at all. ottrend refuses below this, and
            that refusal is a denial here — an envelope judged on mostly-bad
            data is worse than no envelope, because it looks like an answer.
    """

    def __init__(
        self,
        provider: Any,
        *,
        clock=time.time,
        min_good_fraction: float = 0.8,
    ) -> None:
        self._provider = provider
        self._clock = clock
        self._min_good_fraction = min_good_fraction

    async def observed_movement(
        self, tag: str, *, window: float, bucket: float
    ) -> ObservedMovement:
        from ottrend import TrendError, TrendUnavailable, max_rate

        if window <= 0:
            raise ValueError("window must be positive")
        if bucket <= 0:
            raise ValueError("bucket must be positive")

        span = timedelta(seconds=window)
        now = datetime.fromtimestamp(self._clock(), tz=timezone.utc)
        start = now - span

        try:
            result = await max_rate(
                self._provider,
                tag,
                start,
                now,
                bucket=timedelta(seconds=bucket),
                min_good_fraction=self._min_good_fraction,
            )
        except TrendUnavailable as exc:
            # ottrend refuses an empty window and a mostly-bad one with the
            # same exception, and the difference decides the verdict here: a
            # tag with nothing on record has not been seen moving, while a tag
            # whose record is unreadable cannot be checked at all. One cheap
            # probe tells them apart.
            return await self._empty_or_unavailable(tag, start, now, bucket, exc)
        except TrendError as exc:
            # UnknownTag (a history_tag that does not exist) and
            # UnsupportedQuery (a historian that cannot aggregate) are both
            # configuration problems, and both have to fail closed rather than
            # quietly disable the check.
            raise HistoryUnavailable(f"{type(exc).__name__}: {exc}") from exc

        return ObservedMovement(
            rate_per_interval=result.per(span),
            bucket=result.bucket_size.total_seconds(),
            good_fraction=result.good_fraction,
            at=result.at.start.isoformat(),
        )

    async def _empty_or_unavailable(
        self,
        tag: str,
        start: datetime,
        now: datetime,
        bucket: float,
        exc: Exception,
    ) -> ObservedMovement:
        from ottrend import TrendError

        try:
            samples = await self._provider.raw(tag, start, now, limit=1)
        except TrendError as probe_exc:
            raise HistoryUnavailable(
                f"{type(probe_exc).__name__}: {probe_exc}"
            ) from probe_exc
        if samples:
            # There is data; ottrend still refused it. That is a quality
            # refusal, and it stands.
            raise HistoryUnavailable(str(exc)) from exc
        return ObservedMovement(
            rate_per_interval=0.0,
            bucket=bucket,
            good_fraction=0.0,
            at=None,
            recorded=False,
        )

    async def close(self) -> None:
        close = getattr(self._provider, "close", None)
        if close is None:
            return
        try:
            await close()
        except Exception:  # pragma: no cover - best-effort teardown
            pass


class OpcUaHistorian:
    """An OPC UA HA historian that connects on first use and reconnects once.

    The server builds this from the environment, where there is no async
    context to hold ottrend's ``connect()`` open across the process lifetime.
    A failed read drops the session so the next check reconnects, and one
    retry is attempted inline — the same policy as
    :class:`~otgate.backends.asyncua_backend.AsyncuaBackend`, for the same
    reason: a historian that blipped must not turn into a wall of denials, and
    a historian that is really down must not turn into silence.

    Args:
        endpoint: the historian's OPC UA endpoint. Often *not* the endpoint
            holding the live tags.
        timeout: connection timeout in seconds.
        lookback: how far back ottrend may search for a held value.
        clock: wall-clock source, passed through to :class:`OttrendTrend`.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        timeout: float = 4.0,
        lookback: timedelta = timedelta(days=7),
        clock=time.time,
    ) -> None:
        try:
            import ottrend  # noqa: F401  (import-time availability check)
        except ImportError as exc:  # pragma: no cover - exercised only without ottrend
            raise ImportError(
                "recorded-history rate checks need the 'ottrend' package. "
                'Install it with:  pip install "otgate[history]"'
            ) from exc
        self._endpoint = endpoint
        self._timeout = timeout
        self._lookback = lookback
        self._clock = clock
        self._client: Any | None = None
        self._trend: OttrendTrend | None = None

    async def observed_movement(
        self, tag: str, *, window: float, bucket: float
    ) -> ObservedMovement:
        trend = await self._ensure()
        try:
            return await trend.observed_movement(tag, window=window, bucket=bucket)
        except HistoryUnavailable:
            # Could be a dead session rather than a dead historian. Drop it,
            # reconnect, ask once more; if it fails again the denial stands.
            await self.close()
            trend = await self._ensure()
            return await trend.observed_movement(tag, window=window, bucket=bucket)

    async def _ensure(self) -> OttrendTrend:
        if self._trend is not None:
            return self._trend
        from asyncua import Client
        from ottrend import OpcUaHistoryTrend

        client = Client(url=self._endpoint, timeout=self._timeout)
        try:
            await client.connect()
        except Exception as exc:  # noqa: BLE001 - any failure is "no historian"
            raise HistoryUnavailable(
                f"historian {self._endpoint} unreachable: {exc}"
            ) from exc
        self._client = client
        provider = OpcUaHistoryTrend.from_client(client, lookback=self._lookback)
        try:
            await provider.discover_capabilities()
        except Exception:  # noqa: BLE001
            # Discovery is an optimisation (it lets an unsupported aggregate be
            # refused without a round trip). Failing it is not a reason to
            # refuse to try the reads themselves.
            pass
        self._trend = OttrendTrend(provider, clock=self._clock)
        return self._trend

    async def close(self) -> None:
        self._trend = None
        client, self._client = self._client, None
        if client is not None:
            try:
                await client.disconnect()
            except Exception:  # pragma: no cover - best-effort teardown
                pass
