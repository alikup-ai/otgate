"""A small real OPC UA reactor simulator, built on asyncua.

Unlike FakeBackend (in-memory), this starts an actual OPC UA server listening on
an ``opc.tcp://`` endpoint, exposing the same four reactor tags otgate's example
policy expects — with the exact string NodeIds:

    ns=2;s=Reactor.TIC101.PV   temperature process value  (Double)
    ns=2;s=Reactor.TIC101.SP   temperature setpoint       (Double, writable)
    ns=2;s=Reactor.PIC201.PV   pressure process value     (Double)
    ns=2;s=Reactor.ESD         emergency shutdown flag     (Boolean, writable)

Run it standalone to have a server to point a real OPC UA client (or otgate with
OTGATE_BACKEND=asyncua) at::

    python examples/opcua_sim_server.py
    # then, in another shell:
    OTGATE_BACKEND=asyncua \
    OTGATE_OPCUA_ENDPOINT=opc.tcp://127.0.0.1:4840/otgate/sim \
    otgate

``examples/opcua_demo.py`` starts this server in-process and drives otgate
against it end to end.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asyncua import Server, ua

ENDPOINT = "opc.tcp://127.0.0.1:4840/otgate/sim"
NAMESPACE_URI = "http://otgate/reactor"

# (string identifier, initial value, variant type, writable)
_TAGS = [
    ("Reactor.TIC101.PV", 55.0, ua.VariantType.Double, False),
    ("Reactor.TIC101.SP", 55.0, ua.VariantType.Double, True),
    ("Reactor.PIC201.PV", 3.2, ua.VariantType.Double, False),
    ("Reactor.ESD", False, ua.VariantType.Boolean, True),
]


async def build_server() -> Server:
    """Create and initialise (but do not start) the simulation server.

    The server is configured so that namespace index 2 maps to our reactor
    namespace, which is what makes the string NodeIds resolve as
    ``ns=2;s=Reactor.*`` exactly as the policy expects.
    """
    server = Server()
    await server.init()
    server.set_endpoint(ENDPOINT)
    server.set_server_name("otgate reactor simulator")

    # asyncua reserves ns=0 (OPC UA base) and ns=1 (server's own uri). Our first
    # registered namespace therefore becomes index 2.
    idx = await server.register_namespace(NAMESPACE_URI)
    assert idx == 2, f"expected reactor namespace at index 2, got {idx}"

    objects = server.nodes.objects
    reactor = await objects.add_object(idx, "Reactor")

    for identifier, value, vtype, writable in _TAGS:
        node = await reactor.add_variable(
            ua.NodeId(identifier, idx),
            identifier.split(".")[-1],  # browse name: PV / SP / ESD
            ua.Variant(value, vtype),
        )
        if writable:
            await node.set_writable()

    return server


async def main() -> None:
    server = await build_server()
    async with server:
        print(f"otgate reactor simulator listening on {ENDPOINT}")
        print("tags: ns=2;s=Reactor.TIC101.PV | .SP | ns=2;s=Reactor.PIC201.PV | ns=2;s=Reactor.ESD")
        print("Ctrl+C to stop.")
        while True:
            await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nstopped.")
