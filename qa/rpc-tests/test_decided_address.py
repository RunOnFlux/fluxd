"""The node's decided address: the IPv4 address its peers report in their version
messages, taken by majority once enough peers agree: three on mainnet, one on
regtest.

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

PEERS = 3


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
    conns = await connect_reporting(node, "1.2.3.4", PEERS)
    info = await wait_decided(node, "1.2.3.4", PEERS)
    assert info["changed"] == now

    for conn in conns:
        await conn.disconnect_node()
    await wait_decided(node, "", 0)


async def test_one_peer_suffices_on_regtest(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    # No peer reports an address: none is decided.
    assert await decided(node) == {"address": "", "peers": 0, "changed": 0}

    await connect_reporting(node, "1.2.3.4", 1)
    await wait_decided(node, "1.2.3.4", 1)

    # Two peers for another address outvote the one.
    await connect_reporting(node, "5.6.7.8", 2)
    await wait_decided(node, "5.6.7.8", 2)
    peers = await node.rpc.getpeerinfo()
    assert sorted(p["addrlocal"].rsplit(":", 1)[0] for p in peers) == [
        "1.2.3.4",
        "5.6.7.8",
        "5.6.7.8",
    ]


async def test_new_majority_changes_the_address(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    first = await node.advance_mocktime(10)
    await connect_reporting(node, "1.2.3.4", PEERS)
    assert (await wait_decided(node, "1.2.3.4", PEERS))["changed"] == first

    # Three newer peers for another address tie the decided one, which keeps its place.
    await node.advance_mocktime(10)
    await connect_reporting(node, "5.6.7.8", PEERS)
    assert len(await node.rpc.getpeerinfo()) == 2 * PEERS
    assert await decided(node) == {"address": "1.2.3.4", "peers": PEERS, "changed": first}

    # A fourth peer for the new address gives it the majority.
    second = await node.advance_mocktime(10)
    await connect_reporting(node, "5.6.7.8", 1)
    assert (await wait_decided(node, "5.6.7.8", PEERS + 1))["changed"] == second
