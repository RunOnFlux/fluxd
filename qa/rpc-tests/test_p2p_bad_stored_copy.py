"""A stored block whose copy fails on data its hash does not commit to.

The node holds its tip at height BASE. The mininode announces three blocks on
that tip, a, b and c, and delivers b and c first, so both are stored before
their parent and are not checked against the chain. The test then replaces the
stored b with a copy that has b's header and another coinbase: its hash is b's
and its merkle root does not match, the failure CheckBlock flags as a possibly
corrupt copy. That is the class a damaged proof-of-node block signature belongs
to; regtest mints no node-signed block, so the stored copy is damaged on disk.

When a arrives the node connects it and fails on the stored b. It drops that
copy, leaves b's hash usable, asks the peer for b again, connects the good copy
and then c, which was held while its parent was missing.

Blocks are spaced beyond twice the target so the min-difficulty rule keeps each
at powLimit, and mocktime covers the span so the node downloads them.
"""

import asyncio
import copy

from conftest import POW_ARGS, NodeFactory
from fluxtest.blocktools import create_block, create_coinbase
from fluxtest.mininode import (
    CBlock,
    CBlockHeader,
    NodeConn,
    NodeConnCB,
    msg_block,
    msg_getdata,
    msg_headers,
)
from fluxtest.node import FluxNode

BASE = 73  # past the difficulty-reset / eh_epoch ramp windows
STEP = 241  # over twice the 120s target, so each block stays at powLimit
DROPPED = "failed on data outside its hash (bad-txnmrklroot)"


class _Peer(NodeConnCB):
    def __init__(self) -> None:
        super().__init__()
        self.blocks: dict[int, CBlock] = {}
        self.asked: dict[int, int] = {}

    def on_getdata(self, conn: NodeConn, message: msg_getdata) -> None:
        for inv in message.inv:
            self.asked[inv.hash] = self.asked.get(inv.hash, 0) + 1
            if inv.hash in self.blocks:
                conn.send_message(msg_block(self.blocks[inv.hash]))


async def _has_block(node: FluxNode, block: CBlock) -> bool:
    try:
        await node.rpc.getblock(block.hash)
    except Exception:
        return False
    return True


async def _wait(predicate, what: str, timeout: float = 60) -> None:
    for _ in range(int(timeout * 10)):
        if await predicate():
            return
        await asyncio.sleep(0.1)
    raise AssertionError(what)


def _replace_stored_copy(node: FluxNode, block: CBlock, coinbase_extra: int, height: int) -> None:
    """Overwrite the stored block with one of the same header and another coinbase."""
    other = copy.deepcopy(block)
    other.vtx = [create_coinbase(height, coinbase_extra)]
    good, bad = block.serialize(), other.serialize()
    assert CBlockHeader(other).serialize() == CBlockHeader(block).serialize()
    assert len(bad) == len(good) and bad != good

    path = node.datadir / "regtest" / "blocks" / "blk00000.dat"
    data = path.read_bytes()
    assert data.count(good) == 1, "the stored block was not found exactly once"
    with path.open("r+b") as blockfile:
        blockfile.seek(data.index(good))
        blockfile.write(bad)


async def test_bad_stored_copy_is_dropped_and_fetched_again(node_factory: NodeFactory) -> None:
    # Whitelisted: the peer that delivered the block is scored for the copy on disk.
    node = await node_factory(0, extra_args=[*POW_ARGS, "-whitelist=127.0.0.1"])
    await node.mine(BASE)
    tip_hash = await node.rpc.getbestblockhash()
    tip = await node.rpc.getblock(tip_hash)
    await node.set_mocktime_at_least(tip["time"] + 6 * STEP)

    cb = _Peer()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb)
    await conn.connect()
    await cb.wait_for_verack()
    await cb.sync_with_ping()

    chain: list[CBlock] = []
    prev = int(tip_hash, 16)
    for i in range(3):
        block = create_block(prev, create_coinbase(BASE + 1 + i, 1), tip["time"] + (i + 1) * STEP)
        block.solve()
        assert block.sha256 is not None
        chain.append(block)
        prev = block.sha256
    a, b, c = chain
    assert a.sha256 is not None and b.sha256 is not None and c.sha256 is not None

    # b and c are served and stored; a is withheld, so neither is connected.
    cb.blocks = {b.sha256: b, c.sha256: c}
    announcement = msg_headers()
    announcement.headers = [CBlockHeader(block) for block in chain]
    conn.send_message(announcement)

    async def b_and_c_stored() -> bool:
        return await _has_block(node, b) and await _has_block(node, c)

    await _wait(b_and_c_stored, "b and c were not stored")
    assert await node.rpc.getbestblockhash() == tip_hash
    assert cb.asked[b.sha256] == 1

    _replace_stored_copy(node, b, coinbase_extra=2, height=BASE + 2)

    # a connects; the stored b fails; the node asks for b again and reaches c.
    cb.blocks[a.sha256] = a
    conn.send_message(msg_block(a))

    async def at_c() -> bool:
        return await node.rpc.getbestblockhash() == c.hash

    await _wait(at_c, "the node did not fetch b again and reach c")
    assert await node.rpc.getblockcount() == BASE + 3
    assert cb.asked[b.sha256] == 2
    assert cb.asked[c.sha256] == 1

    log = (node.datadir / "regtest" / "debug.log").read_text(errors="replace")
    assert log.count(DROPPED) == 1
    assert f"block {b.hash} {DROPPED}" in log

    # The copy now stored is the good one: the node serves b and builds on c.
    assert (await node.rpc.getblock(b.hash))["merkleroot"] == f"{b.hashMerkleRoot:064x}"
    await node.mine(1)
    assert await node.rpc.getblockcount() == BASE + 4
