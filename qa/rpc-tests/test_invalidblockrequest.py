"""Block request handling for valid, malleated and over-funded blocks.

A valid block on the tip is accepted. A block whose merkle root is malleated by
a duplicated transaction is rejected, yet the honest block carrying the same hash
is still accepted afterwards (the duplicate must not poison the block index). A
block whose coinbase claims more than the subsidy is rejected.

The whole chain -- the spendable coinbase, the 100 maturity blocks and the test
blocks -- is built and equihash-solved by the mininode, each block stamped with
the difficulty the regtest schedule requires (see fluxtest.pow). Blocks are
spaced beyond twice the target so they stay at min-difficulty.
"""

import copy
from collections.abc import AsyncIterator

from conftest import POW_ARGS, NodeFactory
from fluxtest import pow as fluxpow
from fluxtest.blocktools import COIN, create_block, create_coinbase, create_transaction
from fluxtest.comptool import TestInstance, TestManager
from fluxtest.mininode import CBlock
from fluxtest.node import FluxNode
from fluxtest.script import OP_TRUE, CScript

STEP = 241  # > 2x the 120s target so a test block stays at min-difficulty (powLimit)
MATURITY = 100


class _InvalidBlockRequest:
    def __init__(self, node: FluxNode) -> None:
        self.node = node
        self.tip = 0
        self.tip_time = 0
        self.height = 0

    def _next(self, *, extra: int = 0) -> CBlock:
        self.height += 1
        block_time = self.tip_time + STEP
        nbits = fluxpow.next_bits(self.height, self.tip_time, block_time)
        block = create_block(self.tip, create_coinbase(self.height, extra), block_time, nbits=nbits)
        block.solve()
        assert block.sha256 is not None
        self.tip = block.sha256
        self.tip_time = block_time
        return block

    async def _advance_clock(self) -> None:
        """Keep mocktime level with the tip so the node stays out of initial block
        download (a tip more than maxtipage behind the clock would silence the P2P
        handlers this test depends on)."""
        await self.node.rpc.setmocktime(self.tip_time)

    async def get_tests(self) -> AsyncIterator[TestInstance]:
        g = await self.node.rpc.getblock(await self.node.rpc.getbestblockhash())
        self.tip = int(g["hash"], 16)
        self.tip_time = g["time"]

        # 1. A valid block extending the tip is accepted; its coinbase is
        #    anyone-can-spend so later transactions can spend it.
        block1 = self._next()
        await self._advance_clock()
        yield TestInstance([[block1, True]])

        # Mature block1's coinbase with 100 more blocks (delivered as one batch,
        # only the final block's acceptance checked).
        test = TestInstance(sync_every_block=False)
        for _ in range(MATURITY):
            test.blocks_and_transactions.append([self._next(), True])
        await self._advance_clock()
        yield test

        # 2. A block whose merkle root is malleated by a duplicated transaction is
        #    invalid, but the honest block sharing its hash is accepted.
        block2 = self._next()
        tx1 = create_transaction(block1.vtx[0], 0, CScript([OP_TRUE]), 40 * COIN)
        tx2 = create_transaction(tx1, 0, CScript([OP_TRUE]), 40 * COIN)
        block2.vtx.extend([tx1, tx2])
        block2.hashMerkleRoot = block2.calc_merkle_root()
        block2.rehash()
        block2.solve()
        orig_hash = block2.sha256
        block2_orig = copy.deepcopy(block2)

        block2.vtx.append(tx2)  # duplicate: same merkle root and hash, invalid
        assert block2.hashMerkleRoot == block2.calc_merkle_root()
        assert orig_hash == block2.rehash()
        assert block2_orig.vtx != block2.vtx
        assert block2.sha256 is not None
        self.tip = block2.sha256
        await self._advance_clock()
        yield TestInstance([[block2, False], [block2_orig, True]])

        # 3. A block whose coinbase claims more than the subsidy is rejected.
        block3 = self._next()
        await self._advance_clock()
        block3.vtx[0].vout[0].nValue = 200 * COIN  # exceeds the block subsidy
        block3.vtx[0].sha256 = None
        block3.vtx[0].calc_sha256()
        block3.hashMerkleRoot = block3.calc_merkle_root()
        block3.rehash()
        block3.solve()
        yield TestInstance([[block3, False]])


async def test_invalidblockrequest(node_factory: NodeFactory) -> None:
    # Whitelist the harness peer: rejecting the malleated block scores a ban, and
    # only a whitelisted peer survives it to re-serve the honest block.
    node = await node_factory(0, extra_args=[*POW_ARGS, "-whitelist=127.0.0.1"])
    manager = TestManager(_InvalidBlockRequest(node))
    await manager.add_all_connections([node])
    await manager.run()
