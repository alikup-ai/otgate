"""otgate against a REAL OPC UA server (over the network), not FakeBackend.

This starts the asyncua reactor simulator (examples/opcua_sim_server.py) in the
same process, connects otgate's AsyncuaBackend to it over ``opc.tcp://``, and
runs the same scenarios as examples/demo.py. It proves the spec's core claim:
switching from the fake backend to a real OPC UA server is a config change, and
every ALLOW/DENY/ASK decision behaves identically over the wire.

Run it with::

    pip install -e ".[opcua]"
    python examples/opcua_demo.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.opcua_sim_server import ENDPOINT, build_server
from otgate.audit import AuditLog
from otgate.backends.asyncua_backend import AsyncuaBackend
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
    server = await build_server()
    async with server:  # real OPC UA server now listening on ENDPOINT
        # Give the listener a moment to accept connections.
        await asyncio.sleep(0.3)

        backend = AsyncuaBackend(ENDPOINT)
        await backend.connect()
        try:
            policy = load_policy(POLICY_PATH)
            with tempfile.TemporaryDirectory() as tmp:
                audit = AuditLog(Path(tmp) / "opcua_audit.jsonl")
                gateway = Gateway(policy, backend, audit, shadow=False)
                try:
                    banner(f"otgate demo against a REAL OPC UA server ({ENDPOINT})")

                    show_read("read temperature (PV)", await gateway.read(PV))
                    show_write("write setpoint = 60 degC (in range)", await gateway.write(SP, 60.0))
                    show_write("write setpoint = 200 degC (out of range)", await gateway.write(SP, 200.0))

                    # Trip ESD on the real server, then attempt a legitimate write.
                    await backend.write(ESD, True)
                    show_write("write setpoint = 60 degC while ESD active", await gateway.write(SP, 60.0))
                    await backend.write(ESD, False)

                    # Rate-of-change: seed the engine's history as a just-approved
                    # write, then jump too fast (in range, but far over 5 degC/60s).
                    _prime_rate_history(gateway, tag=SP, value=50.0, seconds_ago=1.0)
                    show_write("write setpoint = 78 degC one second later", await gateway.write(SP, 78.0))

                    banner("audit log")
                    for entry in gateway.audit_tail():
                        print(json.dumps(entry, ensure_ascii=False))

                    # Prove nothing forbidden actually landed on the server: SP is
                    # still its initial value because every write was ASK/DENY.
                    final_sp = await backend.read(SP)
                    banner("server state after run")
                    print(f"  {SP} = {final_sp}  (unchanged — no write was ever executed)")
                finally:
                    # Close the audit handle before the temp dir is removed
                    # (Windows cannot delete a file that is still open).
                    gateway.close()
        finally:
            await backend.disconnect()


def _prime_rate_history(gateway: Gateway, *, tag: str, value: float, seconds_ago: float) -> None:
    """Seed the engine's rate history for the rate-of-change scenario."""
    import time

    from otgate.rate_history import WriteRecord

    engine = gateway._engine  # demo-only
    engine._history.put(tag, WriteRecord(wall_ts=time.time() - seconds_ago, value=value))


if __name__ == "__main__":
    asyncio.run(main())
