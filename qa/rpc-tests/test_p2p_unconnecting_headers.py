"""A headers announcement whose parent the node lacks: the other side of a split.

The node holds tip T at height BASE. The mininode holds a competing branch that
forks at T's parent and has more work. It announces that branch one header at a
time, each naming a parent the node lacks. The node answers each announcement
with getheaders, scores the peer only at every MAX_UNCONNECTING_HEADERS-th one
in a row, and once the peer sends headers that connect, it fetches the branch,
reorganises onto it and resets the count.
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
STEP = 241  # over twice the target spacing, so each block stays at powLimit
MAX_UNCONNECTING_HEADERS = 10
BRANCH = 12  # blocks on the competing branch


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


async def _banscore(node: FluxNode) -> int:
    peers = [p for p in await node.rpc.getpeerinfo() if p["inbound"]]
    assert len(peers) == 1, peers
    return peers[0]["banscore"]


async def test_p2p_unconnecting_headers(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    await node.mine(BASE)
    tip = await node.rpc.getblock(await node.rpc.getbestblockhash())
    fork = int(tip["previousblockhash"], 16)
    await node.set_mocktime_at_least(tip["time"] + (BRANCH + 2) * STEP)

    cb = _Peer()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb)
    await conn.connect()
    await cb.wait_for_verack()
    await cb.sync_with_ping()

    branch: list[CBlock] = []
    prev = fork
    for i in range(BRANCH):
        block = create_block(prev, create_coinbase(BASE + i, 1), tip["time"] + (i + 1) * STEP)
        block.solve()
        cb.blocks[block.sha256] = block
        branch.append(block)
        prev = block.sha256

    # Each block after the first, announced alone, names a parent the node lacks.
    for n, block in enumerate(branch[1 : MAX_UNCONNECTING_HEADERS + 2], start=1):
        asked = cb.getheaders
        conn.send_message(_headers(block))
        await cb.sync_with_ping()
        assert cb.getheaders == asked + 1, f"no getheaders after announcement {n}"
        assert not cb.closed, f"disconnected after announcement {n}"
        assert await _banscore(node) == (20 if n >= MAX_UNCONNECTING_HEADERS else 0), n
    assert await node.rpc.getbestblockhash() == tip["hash"]

    # Headers that connect: the node fetches the branch and reorganises onto it.
    conn.send_message(_headers(*branch))
    for _ in range(300):
        if await node.rpc.getbestblockhash() == branch[-1].hash:
            break
        await asyncio.sleep(0.1)
    assert await node.rpc.getbestblockhash() == branch[-1].hash
    assert await node.rpc.getblockcount() == BASE - 1 + BRANCH
    assert not cb.closed

    # The count started again: as many unconnecting announcements as the limit
    # allows, less one, add nothing to the score.
    for i in range(MAX_UNCONNECTING_HEADERS - 1):
        orphan = create_block(i + 1, create_coinbase(BASE + BRANCH, 2), branch[-1].nTime + STEP)
        orphan.solve()
        conn.send_message(_headers(orphan))
    await cb.sync_with_ping()
    assert not cb.closed
    assert await _banscore(node) == 20
