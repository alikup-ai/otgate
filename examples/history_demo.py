"""otgate demo — the ramp the gateway used to miss, and the check that sees it.

One scenario, run twice against the same gateway code and the same write:

1. **Without a historian.** An operator ramps the setpoint 50 -> 194 -> 50 on
   the HMI inside one rate interval. otgate wrote nothing, so it has no record;
   the live value reads 50 again. The agent's +2 nudge looks like a 2-unit step
   and passes every check otgate had.

2. **With a historian.** The same write is refused, because the plant's own
   record shows the tag moving far faster than its policy allows — and the
   reason names the bucket and the timestamp, so an operator can go and look.

Runs entirely in memory: FakeBackend for the live tags, ottrend's MemoryTrend
standing in for the historian, no network and no OPC UA server. Needs ottrend::

    pip install "otgate[history]"
    python examples/history_demo.py
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dataclasses import replace

from otgate.audit import AuditLog
from otgate.backends.fake import FakeBackend
from otgate.models import Access, Policy
from otgate.gateway import Gateway
from otgate.policy import load_policy
from otgate.trend import OttrendTrend

POLICY = Path(__file__).resolve().parent / "reactor_policy_history.yaml"
PLAIN_POLICY = Path(__file__).resolve().parent / "reactor_policy.yaml"
SP = "ns=2;s=Reactor.TIC101.SP"

#: The operator's ramp, in seconds before "now": up 144 units and back, inside
#: six seconds, half a minute ago.
RAMP = ((-30.0, 50.0), (-28.0, 194.0), (-26.0, 50.0))


def banner(text: str) -> None:
    print(f"\n{text}\n" + "-" * len(text))


def plain_write(path: Path) -> Policy:
    """Load a policy, but let the setpoint be written without approval.

    The shipped policies park a setpoint change for a human (ASK), which is
    right in production and would bury the point here. Dropping that one
    requirement leaves the rate checks as the only thing deciding, which is
    what this demo is about.
    """
    policy = load_policy(path)
    rules = dict(policy.rules)
    rules[SP] = replace(rules[SP], access=Access.WRITE)
    return Policy(rules=rules)


def live_plant() -> FakeBackend:
    """The reactor as it stands now: setpoint back at 50, ESD clear."""
    backend = FakeBackend()
    backend.set(SP, 50.0)
    return backend


def historian(now: float):
    """ottrend's in-memory historian, holding the operator's ramp."""
    from ottrend import MemoryTrend, Sample

    series = [
        Sample(datetime.fromtimestamp(now + offset, tz=timezone.utc), value)
        for offset, value in RAMP
    ]
    return MemoryTrend({SP: series})


async def attempt(gateway: Gateway, label: str) -> None:
    result = await gateway.write(SP, 52.0)
    print(f"  {label:<26} {result.decision.type.value:<5} {result.decision.reason}")


async def main() -> None:
    try:
        import ottrend  # noqa: F401
    except ImportError:
        print('this demo needs ottrend:  pip install "otgate[history]"')
        raise SystemExit(1)

    now = time.time()
    audit_dir = Path(tempfile.mkdtemp(prefix="otgate-history-demo-"))

    print(__doc__.split("Runs entirely")[0].rstrip())

    banner("The plant, as the historian recorded it")
    for offset, value in RAMP:
        stamp = datetime.fromtimestamp(now + offset, tz=timezone.utc).strftime("%H:%M:%S")
        print(f"  {stamp}  setpoint = {value:g}   (operator, on the HMI)")
    print("  ...the setpoint is back at 50. Nothing otgate did, nothing it saw.")

    banner("The agent asks for +2 on the setpoint")

    # 1. The gateway as it was: live value and otgate's own write record only.
    blind = Gateway(
        plain_write(PLAIN_POLICY),
        live_plant(),
        AuditLog(audit_dir / "without.jsonl"),
    )
    await attempt(blind, "without a historian")
    blind.close()

    # 2. The same gateway with the plant's record as evidence.
    seeing = Gateway(
        plain_write(POLICY),
        live_plant(),
        AuditLog(audit_dir / "with.jsonl"),
        trend=OttrendTrend(historian(now)),
    )
    await attempt(seeing, "with a historian")

    banner("A minute later, the ramp has aged out of the window")
    later = Gateway(
        plain_write(POLICY),
        live_plant(),
        AuditLog(audit_dir / "later.jsonl"),
        trend=OttrendTrend(historian(now - 120.0)),
    )
    await attempt(later, "with a historian")
    print("\n  The check bounds a rate, so it clears itself. No operator action,")
    print("  no reset, nothing to remember to switch back on.")

    await seeing.aclose()
    await later.aclose()
    print(f"\nAudit trails: {audit_dir}")


if __name__ == "__main__":
    asyncio.run(main())
