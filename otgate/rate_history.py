"""Persistence for the engine's rate-of-change history.

The rate check compares a proposed write against the *last write otgate let
through* for that tag. In v0.1 that history lived only in memory and was lost on
restart — a real gap: right after a restart the history is empty, so the first
write to a rate-limited tag is never rate-checked, letting an agent slip a large
jump past the limit simply by (or after) a restart.

This module makes the history durable. Two implementations share one small
protocol:

- :class:`InMemoryRateHistory` — the previous behaviour; the default, used by
  tests and by deployments that do not need durability.
- :class:`JsonlRateHistory` — writes each update as one append-only JSONL line
  and reloads the latest-per-tag on startup, so the limit survives restarts.

Timestamps are stored as **wall-clock** seconds (``time.time()``), not
``time.monotonic()``: monotonic clocks reset on restart and cannot be persisted
meaningfully. The engine is given a matching wall-clock source.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class WriteRecord:
    """The last write the engine allowed through for a tag.

    Attributes:
        wall_ts: wall-clock time of the write, in seconds since the epoch.
        value: the numeric value written.
    """

    wall_ts: float
    value: float


class RateHistory(Protocol):
    """Storage for the writes a tag has been allowed to make.

    :meth:`get` serves the per-step rate check (it needs only the previous
    write). :meth:`window` serves the cumulative checks, which need every write
    inside a time window — that is what makes salami attacks visible, where each
    individual step is legal but the series is not.
    """

    def get(self, tag: str) -> WriteRecord | None:
        """Return the last recorded write for ``tag``, or ``None``."""
        ...

    def put(self, tag: str, record: WriteRecord) -> None:
        """Record ``record`` as the latest write for ``tag``."""
        ...

    def window(self, tag: str, since_ts: float) -> list[WriteRecord]:
        """Return this tag's writes at or after ``since_ts``, oldest first."""
        ...


class InMemoryRateHistory:
    """Non-persistent history (previous default behaviour)."""

    def __init__(self) -> None:
        self._records: dict[str, list[WriteRecord]] = {}

    def get(self, tag: str) -> WriteRecord | None:
        records = self._records.get(tag)
        return records[-1] if records else None

    def put(self, tag: str, record: WriteRecord) -> None:
        self._records.setdefault(tag, []).append(record)

    def window(self, tag: str, since_ts: float) -> list[WriteRecord]:
        return [r for r in self._records.get(tag, ()) if r.wall_ts >= since_ts]


class JsonlRateHistory:
    """Append-only, restart-durable history backed by a JSONL file.

    Each :meth:`put` appends one line ``{"tag", "wall_ts", "value"}``. On
    construction the file is replayed so both the last write per tag (per-step
    rate) and the recent window per tag (cumulative checks) survive a restart —
    which is what stops an agent from resetting its cumulative budget by
    restarting the gateway.

    Args:
        path: JSONL file path. Created (with parents) on first write.
        retention: how many seconds of history to keep in memory per tag. The
            file itself stays append-only; this only bounds memory. Must be at
            least as long as the longest ``cumulative_interval`` in the policy.
    """

    DEFAULT_RETENTION = 24 * 3600.0

    def __init__(self, path: str | Path, retention: float | None = None) -> None:
        self._path = Path(path)
        self._retention = retention if retention is not None else self.DEFAULT_RETENTION
        self._records: dict[str, list[WriteRecord]] = {}
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    def get(self, tag: str) -> WriteRecord | None:
        records = self._records.get(tag)
        return records[-1] if records else None

    def put(self, tag: str, record: WriteRecord) -> None:
        bucket = self._records.setdefault(tag, [])
        bucket.append(record)
        self._prune(bucket, now=record.wall_ts)
        self._append(tag, record)

    def window(self, tag: str, since_ts: float) -> list[WriteRecord]:
        return [r for r in self._records.get(tag, ()) if r.wall_ts >= since_ts]

    # --- internals ---

    def _prune(self, bucket: list[WriteRecord], now: float) -> None:
        """Drop in-memory records older than the retention window.

        Always keeps the newest record, so the per-step rate check still has a
        baseline even after a long idle period.
        """
        cutoff = now - self._retention
        if len(bucket) > 1:
            kept = [r for r in bucket[:-1] if r.wall_ts >= cutoff]
            bucket[:] = kept + bucket[-1:]

    def _load(self) -> None:
        if not self._path.exists():
            return
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                tag = obj["tag"]
                self._records.setdefault(tag, []).append(
                    WriteRecord(wall_ts=float(obj["wall_ts"]), value=float(obj["value"]))
                )
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                # A corrupt line must not crash startup; skip it.
                continue
        # Keep replayed history ordered and bounded.
        for tag, bucket in self._records.items():
            bucket.sort(key=lambda r: r.wall_ts)
            if bucket:
                self._prune(bucket, now=bucket[-1].wall_ts)

    def _append(self, tag: str, record: WriteRecord) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {"tag": tag, "wall_ts": record.wall_ts, "value": record.value},
            ensure_ascii=False,
        )
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
