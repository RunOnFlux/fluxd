"""The node bounds how many blocks it requests in flight from one peer.

A peer announces many block inventories; the node may request each at most once
and keeps the number of outstanding getdata requests under a cap. The mininode
never answers the getdata, so the in-flight slots stay full and the node stops
asking, which is exactly the flood protection under test.
"""

import asyncio
import random

from conftest import POW_ARGS, NodeFactory
from fluxtest.mininode import CInv, NodeConn, NodeConnCB, msg_getdata, msg_inv

MAX_REQUESTS = 128


class _GetdataCounter(NodeConnCB):
    def __init__(self) -> None:
        super().__init__()
        self.block_req_counts: dict[int, int] = {}

    def on_getdata(self, conn: NodeConn, message: msg_getdata) -> None:
        for inv in message.inv:
            self.block_req_counts[inv.hash] = self.block_req_counts.get(inv.hash, 0) + 1


async def test_maxblocksinflight(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=[*POW_ARGS, "-whitelist=127.0.0.1"])
    await node.mine(1)  # leave initial block download

    cb = _GetdataCounter()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb)
    await conn.connect()
    await cb.wait_for_verack()

    for count in (8, 16, 128, 1024):
        invs = [CInv(2, random.randrange(0, 1 << 256)) for _ in range(count)]
        conn.send_message(msg_inv(invs))
        await cb.sync_with_ping()
        await asyncio.sleep(2)  # let the node's send loop issue any getdata

        assert all(c <= 1 for c in cb.block_req_counts.values()), (
            "a block was requested more than once"
        )
        assert sum(cb.block_req_counts.values()) <= MAX_REQUESTS, (
            "too many blocks requested in flight"
        )

    await conn.disconnect_node()
