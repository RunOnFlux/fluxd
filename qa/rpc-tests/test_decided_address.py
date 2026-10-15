"""The node's decided address: the IPv4 address its peers report in their version
messages, taken by majority once at least three peers agree.

Each mininode peer reports an address of its choosing as the version message's
addrMe. Regtest admits any valid IPv4, so the addresses need not be routable.
The early confirm on an address change needs a confirmed fluxnode, which the
suite does not run; its logic is covered by the DecidedAddress gtests.
"""

import asyncio
from typing import Any

from conftest import POW_ARGS, NodeFactory
from fluxtest.mininode import NodeConn, NodeConnCB
from fluxtest.node import FluxNode

MIN_PEERS = 3


async def connect_reporting(node: FluxNode, addr_me: str, count: int) -> list[NodeConn]:
    """Open ``count`` peers that each report the node at ``addr_me``."""
    conns = []
    for _ in range(count):
        cb = NodeConnCB()
        conn = NodeConn("127.0.0.1", node.p2p_port, cb, addr_me=addr_me)
        await conn.connect()
        await cb.wait_for_verack()
        await cb.sync_with_ping()
        conns.append(conn)
    return conns


async def decided(node: FluxNode) -> dict[str, Any]:
    return (await node.rpc.getnetworkinfo())["decided_address"]


async def wait_decided(
    node: FluxNode, address: str, peers: int, timeout: float = 30
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        info = await decided(node)
        if info["address"] == address and info["peers"] == peers:
            return info
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"decided_address is {info}, want {address} with {peers} peers")
        await asyncio.sleep(0.1)


async def test_three_peers_decide_the_address(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    assert await decided(node) == {"address": "", "peers": 0, "changed": 0}

    now = await node.advance_mocktime(10)
    conns = await connect_reporting(node, "1.2.3.4", MIN_PEERS)
    info = await wait_decided(node, "1.2.3.4", MIN_PEERS)
    assert info["changed"] == now

    for conn in conns:
        await conn.disconnect_node()
    await wait_decided(node, "", 0)


async def test_two_peers_are_not_enough(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    await connect_reporting(node, "1.2.3.4", MIN_PEERS - 1)
    await connect_reporting(node, "5.6.7.8", 1)
    peers = await node.rpc.getpeerinfo()
    assert len(peers) == MIN_PEERS
    assert sorted(p["addrlocal"].rsplit(":", 1)[0] for p in peers) == [
        "1.2.3.4",
        "1.2.3.4",
        "5.6.7.8",
    ]
    assert await decided(node) == {"address": "", "peers": 0, "changed": 0}


async def test_new_majority_changes_the_address(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    first = await node.advance_mocktime(10)
    await connect_reporting(node, "1.2.3.4", MIN_PEERS)
    assert (await wait_decided(node, "1.2.3.4", MIN_PEERS))["changed"] == first

    # Three peers for the new address tie the old one; the tie goes to the newest peer.
    second = await node.advance_mocktime(10)
    await connect_reporting(node, "5.6.7.8", MIN_PEERS)
    assert (await wait_decided(node, "5.6.7.8", MIN_PEERS))["changed"] == second

    # A fourth peer for the old address takes the majority back.
    third = await node.advance_mocktime(10)
    await connect_reporting(node, "1.2.3.4", 1)
    assert (await wait_decided(node, "1.2.3.4", MIN_PEERS + 1))["changed"] == third
