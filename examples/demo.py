"""otgate demo — an agent attempts a series of reads and writes on a reactor.

Runs entirely on the in-memory FakeBackend (no external OPC UA server, no
network). It walks through the scenarios from the spec — a legitimate read, an
in-range setpoint change that needs approval, an out-of-range write, a write
blocked by the emergency-shutdown interlock, and a too-fast rate of change — and
prints otgate's decision and reason for each, then dumps the audit log.

Run it with::

    python examples/demo.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

# Make the package importable when run as `python examples/demo.py` from a
# source checkout (before `pip install`).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from otgate.audit import AuditLog
from otgate.backends.fake import FakeBackend
from otgate.gateway import Gateway
from otgate.policy import load_policy

POLICY_PATH = Path(__file__).resolve().parent / "reactor_policy.yaml"

SP = "ns=2;s=Reactor.TIC101.SP"
PV = "ns=2;s=Reactor.TIC101.PV"
ESD = "ns=2;s=Reactor.ESD"


def banner(text: str) -> None:
    print(f"\n{text}\n" + "-" * len(text))


def show_read(label: str, result) -> None:
    d = result.decision
    value = f" -> {result.value}" if result.executed else ""
    print(f"  {label:<48} {d.type.value:<5} {d.reason}{value}")


def show_write(label: str, result) -> None:
    d = result.decision
    executed = "  [executed]" if result.executed else ""
    print(f"  {label:<48} {d.type.value:<5} {d.reason}{executed}")


async def main() -> None:
    policy = load_policy(POLICY_PATH)
    backend = FakeBackend()

    with tempfile.TemporaryDirectory() as tmp:
        audit = AuditLog(Path(tmp) / "demo_audit.jsonl")
        gateway = Gateway(policy, backend, audit, shadow=False)

        banner("otgate demo — agent interacting with a reactor via the policy gateway")

        # 1. Read the current temperature — allowed.
        show_read("read temperature (PV)", await gateway.read(PV))

        # 2. Set the setpoint to 60 degC, within range — allowed but needs approval.
        #    The write is parked, not dropped; a human then approves it and it runs.
        w = await gateway.write(SP, 60.0)
        show_write("write setpoint = 60 degC (in range)", w)
        res = await gateway.approve(w.approval_id)
        print(f"  {'-> operator approves ' + w.approval_id[:8]:<48} {res.status:<5} {res.reason}")
        print(f"  {'-> backend now reads':<48}       {await backend.read(SP)}")

        # 3. Set the setpoint to 200 degC — outside the 40..80 range.
        show_write("write setpoint = 200 degC (out of range)", await gateway.write(SP, 200.0))

        # 4. Trip the emergency shutdown, then try a legitimate setpoint change.
        backend.set(ESD, True)
        show_write("write setpoint = 60 degC while ESD active", await gateway.write(SP, 60.0))
        backend.set(ESD, False)  # clear ESD for the next scenario

        # 5. Approval is not a rubber stamp: park a write, trip ESD while it waits,
        #    then approve — otgate re-checks and blocks the now-unsafe write.
        #    (Backdate the rate history so this small change clears the rate gate
        #    and actually reaches the approval step, isolating the re-check.)
        _prime_rate_history(gateway, tag=SP, value=58.0, seconds_ago=120.0)
        w = await gateway.write(SP, 58.0)
        show_write("write setpoint = 58 degC (parked)", w)
        backend.set(ESD, True)  # emergency trips before the operator gets to it
        res = await gateway.approve(w.approval_id)
        print(f"  {'-> operator approves, but ESD tripped':<48} {res.status:<5} {res.reason}")
        backend.set(ESD, False)

        # 6. Rate of change: pretend a setpoint of 50 was approved a moment ago,
        #    then try to jump to 78 within one second (in range, but far too fast
        #    for the 5 degC / 60 s limit).
        _prime_rate_history(gateway, tag=SP, value=50.0, seconds_ago=1.0)
        show_write("write setpoint = 78 degC one second later", await gateway.write(SP, 78.0))

        # 7. The patient attack: instead of one big jump, walk the setpoint up in
        #    small steps that each satisfy max_rate. Cumulative drift catches it.
        banner("salami attack — many small legal steps, one illegal total")
        await _salami_demo(audit)

        # Audit dump.
        banner("audit log")
        for entry in gateway.audit_tail():
            print(json.dumps(entry, ensure_ascii=False))

        # Close the audit handle before the temp dir is removed (on Windows a
        # still-open file cannot be deleted).
        gateway.close()


async def _salami_demo(audit) -> None:
    """Walk the setpoint up in small legal steps until cumulative drift stops it.

    Uses its own gateway with a plain-write policy (so each step executes without
    an approval round-trip) and a controllable clock, so the minute-long waits
    between steps happen instantly.
    """
    from otgate.models import Access, Policy, Rule

    class Clock:
        def __init__(self) -> None:
            self.t = 1_000_000.0

        def __call__(self) -> float:
            return self.t

    clock = Clock()
    policy = Policy(
        rules={
            SP: Rule(
                tag=SP,
                access=Access.WRITE,
                value_range=(40.0, 80.0),
                max_rate=5.0,
                rate_interval=60.0,
                cumulative_range=(-10.0, 10.0),
                cumulative_interval=3600.0,
            )
        }
    )
    backend = FakeBackend()
    gw = Gateway(policy, backend, audit)
    gw._engine._clock = clock  # demo-only: drive time by hand

    value = 50.0
    gw._engine.record_write(SP, value)
    print(f"  setpoint starts at {value} degC; each step waits a minute and adds +2.5")

    for step in range(1, 7):
        clock.t += 60.0
        target = value + 2.5
        result = await gw.write(SP, target)
        drift = target - 50.0
        mark = "ALLOW" if result.executed else result.decision.type.value
        print(f"  step {step}: {value:>4} -> {target:<5} (drift {drift:+g})   {mark:<5} {result.decision.reason}")
        if not result.executed:
            break
        value = target


def _prime_rate_history(gateway: Gateway, *, tag: str, value: float, seconds_ago: float) -> None:
    """Simulate a previously-approved-and-executed write for the rate demo.

    Reaches into the engine to seed its rate history without going through an
    ASK/approval round-trip (which v0.1 does not implement), backdated by
    ``seconds_ago`` so the next write appears to happen shortly after.
    """
    import time

    from otgate.rate_history import WriteRecord

    engine = gateway._engine  # demo-only: seed rate history directly
    engine._history.put(tag, WriteRecord(wall_ts=time.time() - seconds_ago, value=value))


if __name__ == "__main__":
    asyncio.run(main())
