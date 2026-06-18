"""Helpers for wiring regtest nodes together and waiting for them to converge."""

import asyncio

from .node import FluxNode


async def connect_nodes(a: FluxNode, b: FluxNode, timeout: float = 30) -> None:
    """Add b as an outbound peer of a and wait for the version handshake.

    Waits for the specific peer to appear and finish handshaking, rather than
    treating an empty peer list (peer not connected yet) as success.
    """
    await a.rpc.addnode(f"127.0.0.1:{b.p2p_port}", "onetry")
    target = f":{b.p2p_port}"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        peers = await a.rpc.getpeerinfo()
        if any(target in peer.get("addr", "") and peer["version"] != 0 for peer in peers):
            return
        if loop.time() > deadline:
            raise AssertionError(
                f"node {a.index} did not connect to node {b.index} within {timeout}s"
            )
        await asyncio.sleep(0.1)


async def connect_nodes_bi(a: FluxNode, b: FluxNode) -> None:
    """Connect a and b to each other."""
    await connect_nodes(a, b)
    await connect_nodes(b, a)


async def sync_blocks(nodes: list[FluxNode], timeout: float = 60) -> None:
    """Wait until every node reports the same block count."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        counts = [await node.rpc.getblockcount() for node in nodes]
        if counts == [counts[0]] * len(counts):
            return
        if loop.time() > deadline:
            raise AssertionError(f"blocks did not sync within {timeout}s: {counts}")
        await asyncio.sleep(0.25)


async def sync_mempools(nodes: list[FluxNode], timeout: float = 60) -> None:
    """Wait until every node has the same transactions in its mempool."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        pool = set(await nodes[0].rpc.getrawmempool())
        if all(set(await node.rpc.getrawmempool()) == pool for node in nodes[1:]):
            return
        if loop.time() > deadline:
            raise AssertionError(f"mempools did not sync within {timeout}s")
        await asyncio.sleep(0.25)
