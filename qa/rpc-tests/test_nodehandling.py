"""Test node handling: setban/listbanned/clearbanned and disconnectnode."""

import asyncio

from conftest import NodeFactory
from fluxtest.network import connect_nodes, connect_nodes_bi


async def test_banning(node_factory: NodeFactory) -> None:
    node = await node_factory(0)

    assert await node.rpc.listbanned() == []
    await node.rpc.setban("127.0.0.0/24", "add")
    assert len(await node.rpc.listbanned()) == 1
    await node.rpc.setban("127.0.0.0/24", "remove")
    assert await node.rpc.listbanned() == []
    await node.rpc.clearbanned()
    assert await node.rpc.listbanned() == []


async def test_disconnect_and_reconnect(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0)
    node1 = await node_factory(1)
    await connect_nodes_bi(node0, node1)

    peer = f"127.0.0.1:{node1.p2p_port}"
    await node0.rpc.disconnectnode(peer)
    for _ in range(50):
        if not any(p["addr"] == peer for p in await node0.rpc.getpeerinfo()):
            break
        await asyncio.sleep(0.1)
    assert not any(p["addr"] == peer for p in await node0.rpc.getpeerinfo())

    await connect_nodes(node0, node1)
    assert any(p["addr"] == peer for p in await node0.rpc.getpeerinfo())
