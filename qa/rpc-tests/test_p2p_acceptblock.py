"""Processing of unrequested blocks, from whitelisted and non-whitelisted peers.

A node accepts an unrequested block that extends its tip, but an unrequested
block that only forks the chain (no more work) is kept as a header unless it
comes from a whitelisted peer. A longer competing chain is stored but not
connected while an intermediate block is missing; once that block arrives (here
prompted by an inv that triggers a getdata) the node reorgs onto it.

The mininode builds blocks from BASE, which is past the regtest difficulty-reset
and eh_epoch ramp windows, and spaces them beyond twice the target so the
min-difficulty rule keeps each at powLimit; mocktime is advanced to cover the
(virtual) span.
"""

import pytest
from conftest import POW_ARGS, NodeFactory
from fluxtest.blocktools import create_block, create_coinbase
from fluxtest.mininode import (
    CInv,
    NodeConn,
    NodeConnCB,
    msg_block,
    msg_getdata,
    msg_inv,
)
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

BASE = 73  # past the difficulty-reset / eh_epoch ramp windows
WINDOW = 288  # MIN_BLOCKS_TO_KEEP: how far ahead of its tip a node stores blocks
# Block-time spacing: just over 2x the 120s target so each block stays
# min-difficulty (powLimit), while keeping the whole ~290-block span under the
# 24h tip-age that would otherwise leave the stuck node in initial block download
# (which disables the block-download scheduler this test relies on).
STEP = 241


class _AcceptNode(NodeConnCB):
    def __init__(self) -> None:
        super().__init__()
        self.last_getdata: msg_getdata | None = None

    def on_getdata(self, conn: NodeConn, message: msg_getdata) -> None:
        self.last_getdata = message


async def _connect(node: FluxNode) -> tuple[NodeConn, _AcceptNode]:
    cb = _AcceptNode()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb)
    await conn.connect()
    await cb.wait_for_verack()
    return conn, cb


def _status(tips: list[dict], block_hash: str) -> str:
    return next(t["status"] for t in tips if t["hash"] == block_hash)


@pytest.mark.slow
async def test_p2p_acceptblock(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0, extra_args=POW_ARGS)
    node1 = await node_factory(1, extra_args=[*POW_ARGS, "-whitelist=127.0.0.1"])
    conn0, cb0 = await _connect(node0)  # not whitelisted
    conn1, cb1 = await _connect(node1)  # whitelisted

    base_time = []
    for n in (node0, node1):
        await n.mine(BASE)
        tip_time = (await n.rpc.getblock(await n.rpc.getbestblockhash()))["time"]
        base_time.append(tip_time)
        await n.set_mocktime_at_least(tip_time + (WINDOW + 3) * STEP)
    tips = [int(await n.rpc.getbestblockhash(), 16) for n in (node0, node1)]

    def build(prev: int, height: int, extra: int, idx: int):
        block = create_block(
            prev, create_coinbase(height, extra), base_time[idx] + (height - BASE) * STEP
        )
        block.solve()
        return block

    # A block building on each tip is accepted by both nodes.
    h2 = [build(tips[i], BASE + 1, 0, i) for i in range(2)]
    conn0.send_message(msg_block(h2[0]))
    conn1.send_message(msg_block(h2[1]))
    await cb0.sync_with_ping()
    await cb1.sync_with_ping()
    assert await node0.rpc.getblockcount() == BASE + 1
    assert await node1.rpc.getblockcount() == BASE + 1

    # A competing block is only processed by the whitelisted node.
    h2f = [build(tips[i], BASE + 1, 1, i) for i in range(2)]
    conn0.send_message(msg_block(h2f[0]))
    conn1.send_message(msg_block(h2f[1]))
    await cb0.sync_with_ping()
    await cb1.sync_with_ping()
    assert _status(await node0.rpc.getchaintips(), h2f[0].hash) == "headers-only"
    assert _status(await node1.rpc.getchaintips(), h2f[1].hash) == "valid-headers"

    # A block on the fork: node0 stays stuck (missing the intermediate block) but
    # stores it as more work; node1 reorgs to the longer chain.
    h3 = [build(h2f[i].sha256, BASE + 2, 0, i) for i in range(2)]
    conn0.send_message(msg_block(h3[0]))
    conn1.send_message(msg_block(h3[1]))
    await cb0.sync_with_ping()
    await cb1.sync_with_ping()
    assert _status(await node0.rpc.getchaintips(), h3[0].hash) == "headers-only"
    await node0.rpc.getblock(h3[0].hash)  # stored, does not raise
    assert await node1.rpc.getblockcount() == BASE + 2

    # WINDOW more blocks on each fork. node0 (not whitelisted) stores them only
    # up to its window and ignores the last as too far ahead; node1 (whitelisted)
    # is not subject to that bound and connects the whole chain, reorging onto it.
    chain = [h3[0], h3[1]]
    node0_blocks = []
    for j in range(2):
        conn = conn0 if j == 0 else conn1
        for i in range(WINDOW):
            nb = build(chain[j].sha256, BASE + 3 + i, 0, j)
            conn.send_message(msg_block(nb))
            if j == 0:
                node0_blocks.append(nb)
            chain[j] = nb
    await cb0.sync_with_ping()
    await cb1.sync_with_ping()
    for stored in node0_blocks[:-1]:
        await node0.rpc.getblock(stored.hash)  # present
    with pytest.raises(JSONRPCError):
        await node0.rpc.getblock(node0_blocks[-1].hash)  # too far ahead, ignored
    assert await node1.rpc.getbestblockhash() == chain[1].hash  # whitelisted: full chain
    assert await node1.rpc.getblockcount() == BASE + 2 + WINDOW

    # Re-sending the fork block to node0 is still ignored: it is unrequested and
    # carries no more work than the active tip.
    conn0.send_message(msg_block(h2f[0]))
    await cb0.sync_with_ping()
    assert await node0.rpc.getblockcount() == BASE + 1

    # An inv for the height-(BASE+2) block makes node0 mark the peer as having
    # that chain and request the still-missing intermediate block.
    cb0.last_getdata = None
    conn0.send_message(msg_inv([CInv(2, h3[0].sha256)]))
    await cb0.sync_with_ping()
    assert cb0.last_getdata is not None
    assert cb0.last_getdata.inv[0].hash == h2f[0].sha256

    # Delivering it (now requested) connects the chain and node0 reorgs onto the
    # fork, up to the last block it was willing to store.
    conn0.send_message(msg_block(h2f[0]))
    await cb0.sync_with_ping()
    assert await node0.rpc.getblockcount() == BASE + 1 + WINDOW

    await conn0.disconnect_node()
    await conn1.disconnect_node()
