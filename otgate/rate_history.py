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
    """Storage for the most recent allowed write per tag."""

    def get(self, tag: str) -> WriteRecord | None:
        """Return the last recorded write for ``tag``, or ``None``."""
        ...

    def put(self, tag: str, record: WriteRecord) -> None:
        """Record ``record`` as the latest write for ``tag``."""
        ...


class InMemoryRateHistory:
    """Non-persistent history (previous default behaviour)."""

    def __init__(self) -> None:
        self._records: dict[str, WriteRecord] = {}

    def get(self, tag: str) -> WriteRecord | None:
        return self._records.get(tag)

    def put(self, tag: str, record: WriteRecord) -> None:
        self._records[tag] = record


class JsonlRateHistory:
    """Append-only, restart-durable history backed by a JSONL file.

    Each :meth:`put` appends one line ``{"tag", "wall_ts", "value"}``; the
    in-memory map is the last line seen per tag. On construction the file is
    replayed so the latest record per tag is restored.

    Args:
        path: JSONL file path. Created (with parents) on first write.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._records: dict[str, WriteRecord] = {}
        self._load()

    @property
    def path(self) -> Path:
        return self._path

    def get(self, tag: str) -> WriteRecord | None:
        return self._records.get(tag)

    def put(self, tag: str, record: WriteRecord) -> None:
        self._records[tag] = record
        self._append(tag, record)

    # --- internals ---

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
                self._records[tag] = WriteRecord(
                    wall_ts=float(obj["wall_ts"]), value=float(obj["value"])
                )
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                # A corrupt line must not crash startup; skip it. Later valid
                # lines for the same tag still win (last-write-wins on replay).
                continue

    def _append(self, tag: str, record: WriteRecord) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(
            {"tag": tag, "wall_ts": record.wall_ts, "value": record.value},
            ensure_ascii=False,
        )
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
