"""A headers announcement whose parent the node lacks: the other side of a split.

The node holds its own tip at height BASE. The mininode holds a competing branch
of more work that forks at that tip. It announces the branch from its second
block, so each announcement's first header names a parent the node does not have.
The node answers each with getheaders and scores the peer only at every
MAX_UNCONNECTING_HEADERS-th announcement in a row; when the peer finally sends
headers that connect, the node fetches the branch, reorganises onto it, and
resets the count.

Blocks are spaced beyond twice the target (as test_p2p_acceptblock does) so the
min-difficulty rule keeps each at powLimit, and mocktime is advanced to cover the
span so the newest header is recent enough for the node to download its blocks.
"""

import asyncio

from conftest import POW_ARGS, NodeFactory
from fluxtest.blocktools import create_block, create_coinbase
from fluxtest.mininode import (
    CBlock,
    CBlockHeader,
    NodeConn,
    NodeConnCB,
    msg_block,
    msg_getdata,
    msg_getheaders,
    msg_headers,
)
from fluxtest.node import FluxNode

BASE = 73  # past the difficulty-reset / eh_epoch ramp windows
STEP = 241  # over twice the 120s target, so each block stays at powLimit
MAX_UNCONNECTING_HEADERS = 10
BRANCH = 13  # blocks on the competing branch (> MAX, so the fork is longer work)


class _Peer(NodeConnCB):
    def __init__(self) -> None:
        super().__init__()
        self.getheaders = 0
        self.closed = False
        self.blocks: dict[int, CBlock] = {}

    def on_getheaders(self, conn: NodeConn, message: msg_getheaders) -> None:
        self.getheaders += 1

    def on_getdata(self, conn: NodeConn, message: msg_getdata) -> None:
        for inv in message.inv:
            if inv.hash in self.blocks:
                conn.send_message(msg_block(self.blocks[inv.hash]))

    def on_close(self, conn: NodeConn) -> None:
        self.closed = True


def _headers(*blocks: CBlock) -> msg_headers:
    message = msg_headers()
    message.headers = [CBlockHeader(b) for b in blocks]
    return message


async def _inbound(node: FluxNode) -> dict:
    peers = [p for p in await node.rpc.getpeerinfo() if p["inbound"]]
    assert len(peers) == 1, peers
    return peers[0]


async def test_p2p_unconnecting_headers(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    await node.mine(BASE)
    tip_hash = await node.rpc.getbestblockhash()
    tip = await node.rpc.getblock(tip_hash)
    base_time = await node.set_mocktime_at_least(tip["time"] + (BRANCH + 3) * STEP)

    cb = _Peer()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb)
    await conn.connect()
    await cb.wait_for_verack()
    await cb.sync_with_ping()

    # A longer branch forking at the node's tip, at powLimit so it is valid.
    branch: list[CBlock] = []
    prev = int(tip_hash, 16)
    for i in range(BRANCH):
        block = create_block(prev, create_coinbase(BASE + 1 + i), tip["time"] + (i + 1) * STEP)
        block.solve()
        cb.blocks[block.sha256] = block
        branch.append(block)
        prev = block.sha256

    # Announced from the second block, each header's parent is unknown to the node.
    # The node asks for the missing headers and does not ban; it scores the peer
    # only at the MAX_UNCONNECTING_HEADERS-th announcement in a row.
    for n, block in enumerate(branch[1 : MAX_UNCONNECTING_HEADERS + 2], start=1):
        asked = cb.getheaders
        conn.send_message(_headers(block))
        await cb.sync_with_ping()
        assert cb.getheaders == asked + 1, f"no getheaders after announcement {n}"
        assert not cb.closed, f"disconnected after announcement {n}"
        assert (await _inbound(node))["banscore"] == (20 if n >= MAX_UNCONNECTING_HEADERS else 0), n
    assert await node.rpc.getbestblockhash() == tip_hash

    # Headers that connect at the node's tip: it fetches the branch (answering our
    # getdata) and reorganises onto it.
    conn.send_message(_headers(*branch))
    for _ in range(600):
        if await node.rpc.getbestblockhash() == branch[-1].hash:
            break
        await asyncio.sleep(0.1)
    assert await node.rpc.getbestblockhash() == branch[-1].hash, "did not reorganise onto the branch"
    assert await node.rpc.getblockcount() == BASE + BRANCH
    assert not cb.closed

    # The count has reset: nine more unconnecting announcements in a row (one short
    # of the limit from zero) add nothing. Had the count carried over from the
    # eleven above, the nineteenth-to-twentieth would have scored.
    orphans = []
    prev = branch[-1].sha256 ^ 1  # a parent the node does not have
    for i in range(MAX_UNCONNECTING_HEADERS - 1):
        orphan = create_block(prev, create_coinbase(BASE + BRANCH + 1 + i), base_time + (i + 1) * STEP)
        orphan.solve()
        orphans.append(orphan)
        prev = orphan.sha256
    for orphan in orphans:
        conn.send_message(_headers(orphan))
    await cb.sync_with_ping()
    assert not cb.closed
    assert (await _inbound(node))["banscore"] == 20

