"""Append-only audit log (JSONL).

Every agent interaction otgate processes becomes exactly one line in a JSONL
file: one JSON object per line, appended and never rewritten. The log is the
tamper-evident record of what the agent asked for and what otgate decided — the
part of the value proposition that survives after the process has moved on.

The writer only ever appends; it exposes no update or delete. Reading back the
tail (:meth:`AuditLog.tail`) is provided for the ``get_audit_log`` MCP tool and
the demo dump.

Performance
-----------
The file handle is opened once and kept open, so each ``record`` is a single
buffered write + flush rather than an open/write/close cycle — the dominant cost
in the naive version. ``tail`` is served from an in-memory mirror of the entries
written by this instance, so the common "read recent audit" path never touches
the disk.

Durability trade-off: writes are flushed to the OS on every record (so they
survive a process crash) but not ``fsync``'d to the physical disk on each line
(which would reintroduce most of the latency). For v0.1's threat model — an
audit trail of agent actions, not a financial ledger — OS-level durability is
the right point on the curve. A stricter mode is a documented TODO.
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path

from otgate.models import AuditEntry, Decision, Scalar


class AuditLog:
    """Append-only JSONL audit writer/reader.

    Args:
        path: JSONL file path. Parent directories are created on first write.
            The file is opened in append mode, so existing history is preserved.

    The instance may be used as a context manager to guarantee the file handle
    is closed::

        with AuditLog("audit.jsonl") as log:
            log.record(...)
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._fh: io.TextIOWrapper | None = None
        # In-memory mirror of entries written *by this instance*, used to serve
        # tail() without re-reading the file. Entries appended by other
        # processes/instances are picked up by falling back to a file read.
        self._buffer: list[dict] = []

    @property
    def path(self) -> Path:
        return self._path

    def record(
        self,
        *,
        action: str,
        node_id: str,
        value: Scalar | None,
        decision: Decision,
        shadow: bool,
        executed: bool,
        agent: str | None = None,
        timestamp: str | None = None,
    ) -> AuditEntry:
        """Append one audit entry and return it.

        Args:
            action: ``"read"`` or ``"write"``.
            node_id: the tag involved.
            value: written value (``None`` for reads).
            decision: the engine's decision.
            shadow: whether the gateway was in shadow mode for this call.
            executed: whether the operation actually ran on the backend.
            agent: id of the agent that made the call (``None`` in single-agent
                mode, where there is no identity to attribute).
            timestamp: ISO 8601 string; defaults to ``now`` in UTC. Injectable
                for deterministic tests.
        """
        entry = AuditEntry(
            timestamp=timestamp or _utc_now_iso(),
            action=action,
            node_id=node_id,
            value=value,
            decision=decision.type.value,
            reason=decision.reason,
            shadow=shadow,
            executed=executed,
            agent=agent,
        )
        self._append(entry)
        return entry

    def tail(self, limit: int = 50) -> list[dict]:
        """Return the last ``limit`` entries as dicts, oldest first.

        Served from the in-memory mirror when this instance wrote every entry
        (the usual case). If the file on disk has more lines than we hold in
        memory — e.g. it pre-existed or another process appended — the file is
        read so nothing is missed.

        Returns an empty list if there is no audit yet. Malformed lines (which an
        append-only writer never produces) are skipped.
        """
        if limit < 0:
            raise ValueError("limit must be non-negative")
        if limit == 0:
            return []

        # Fast path: everything we need is in memory and matches the file.
        on_disk = self._line_count()
        if on_disk <= len(self._buffer):
            return self._buffer[-limit:]

        # Slow path: the file has entries we did not write; read it back.
        return self._read_file_tail(limit)

    def close(self) -> None:
        """Flush and close the underlying file handle (idempotent)."""
        if self._fh is not None:
            self._fh.flush()
            self._fh.close()
            self._fh = None

    def __enter__(self) -> "AuditLog":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:  # best-effort cleanup if close() was not called
        try:
            self.close()
        except Exception:
            pass

    # --- internals ---

    def _append(self, entry: AuditEntry) -> None:
        record = entry.to_dict()
        line = json.dumps(record, ensure_ascii=False)
        fh = self._ensure_open()
        fh.write(line + "\n")
        fh.flush()  # push to the OS so the record survives a process crash
        self._buffer.append(record)

    def _ensure_open(self) -> io.TextIOWrapper:
        if self._fh is None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Buffered append; encoding fixed for cross-platform reproducibility.
            self._fh = self._path.open("a", encoding="utf-8")
        return self._fh

    def _line_count(self) -> int:
        if not self._path.exists():
            return 0
        with self._path.open("r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())

    def _read_file_tail(self, limit: int) -> list[dict]:
        lines = self._path.read_text(encoding="utf-8").splitlines()
        entries: list[dict] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries[-limit:]


def _utc_now_iso() -> str:
    """Current UTC time as an ISO 8601 string with a trailing ``Z``."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
