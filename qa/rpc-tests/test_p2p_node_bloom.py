"""A node enforcing -nopeerbloomfilters drops peers that use bloom filters.

With bloom filtering disabled and enforced, a peer that sends a filteradd is
disconnected, while a harmless filterclear is tolerated. A default node, which
serves bloom filters, keeps the peer in both cases.
"""

import asyncio

from conftest import NodeFactory
from fluxtest.mininode import NodeConn, NodeConnCB, msg_filteradd, msg_filterclear
from fluxtest.node import FluxNode


async def _wait_peer_count(node: FluxNode, expected: int, timeout: float = 30) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while len(await node.rpc.getpeerinfo()) != expected:
        if loop.time() > deadline:
            raise AssertionError(
                f"wanted {expected} peers, have {len(await node.rpc.getpeerinfo())}"
            )
        await asyncio.sleep(0.1)


async def _connect(node: FluxNode) -> tuple[NodeConn, NodeConnCB]:
    cb = NodeConnCB()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb)
    await conn.connect()
    await cb.wait_for_verack()
    return conn, cb


async def test_p2p_node_bloom(node_factory: NodeFactory) -> None:
    nobf = await node_factory(0, extra_args=["-nopeerbloomfilters", "-enforcenodebloom"])
    bf = await node_factory(1, extra_args=[])

    nobf_conn, nobf_cb = await _connect(nobf)
    bf_conn, bf_cb = await _connect(bf)
    assert len(await nobf.rpc.getpeerinfo()) == 1
    assert len(await bf.rpc.getpeerinfo()) == 1

    # A filterclear is harmless: both peers stay connected.
    nobf_conn.send_message(msg_filterclear())
    bf_conn.send_message(msg_filterclear())
    await nobf_cb.sync_with_ping()
    await bf_cb.sync_with_ping()
    assert len(await nobf.rpc.getpeerinfo()) == 1
    assert len(await bf.rpc.getpeerinfo()) == 1

    # A filteradd makes the enforcing node drop the peer; the default node keeps it.
    nobf_conn.send_message(msg_filteradd(b"\x00"))
    bf_conn.send_message(msg_filteradd(b"\x00"))
    await _wait_peer_count(nobf, 0)
    await bf_cb.sync_with_ping()
    assert len(await bf.rpc.getpeerinfo()) == 1

    await nobf_conn.disconnect_node()
    await bf_conn.disconnect_node()
