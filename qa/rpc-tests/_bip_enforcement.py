"""Shared driver for the CLTV (BIP65) and DERSIG (BIP66) enforcement tests.

Flux enforces both rules unconditionally -- CLTV via the block script flags
(main.cpp), strict-DER in every signature check (interpreter.cpp) -- with no
version-bits activation. So there is no activation transition to exercise, only
enforcement.

Each test mines two wallet-owned coinbases past maturity, then delivers one block
carrying a valid wallet-signed coinbase spend (accepted) and one whose spend an
``invalidate`` mutator has made rule-violating (rejected). The two blocks spend
*different* coinbases so the invalid one fails for the rule under test, not for a
double spend. Only the test block is mininode-built; the wallet-owned coinbases
have to be node-mined because the spend is wallet-signed.
"""

import io
from collections.abc import AsyncIterator, Callable

from conftest import POW_ARGS, NodeFactory
from fluxtest import pow as fluxpow
from fluxtest.blocktools import create_block, create_coinbase
from fluxtest.comptool import TestInstance, TestManager
from fluxtest.mininode import CTransaction
from fluxtest.node import FluxNode

STEP = 241  # > 2x the 120s target so a test block stays at min-difficulty (powLimit)
MATURITY = 100

Invalidate = Callable[[CTransaction], None]


class _Enforcement:
    def __init__(self, node: FluxNode, invalidate: Invalidate) -> None:
        self.node = node
        self.invalidate = invalidate
        self.tip = 0
        self.tip_time = 0
        self.height = 0

    async def _spend(self, coinbase_hash: str) -> CTransaction:
        """A wallet-signed transaction spending the coinbase's first output."""
        from_txid = (await self.node.rpc.getblock(coinbase_hash))["tx"][0]
        address = await self.node.rpc.getnewaddress()
        raw = await self.node.rpc.createrawtransaction(
            [{"txid": from_txid, "vout": 0}], {address: 1.0}
        )
        signed = await self.node.rpc.signrawtransaction(raw)
        assert signed["complete"], signed
        tx = CTransaction()
        tx.deserialize(io.BytesIO(bytes.fromhex(signed["hex"])))
        tx.calc_sha256()
        return tx

    async def get_tests(self) -> AsyncIterator[TestInstance]:
        coinbases = await self.node.mine(2)  # two wallet-owned coinbases
        await self.node.mine(MATURITY)
        tip = await self.node.rpc.getbestblockhash()
        self.tip = int(tip, 16)
        self.tip_time = (await self.node.rpc.getblock(tip))["time"]
        self.height = await self.node.rpc.getblockcount()

        for valid, coinbase in ((True, coinbases[0]), (False, coinbases[1])):
            spend = await self._spend(coinbase)
            if not valid:
                self.invalidate(spend)
                spend.rehash()
            height = self.height + 1
            block_time = self.tip_time + STEP
            nbits = fluxpow.next_bits(height, self.tip_time, block_time)
            await self.node.rpc.setmocktime(block_time)
            block = create_block(self.tip, create_coinbase(height), block_time, nbits=nbits)
            block.vtx.append(spend)
            block.hashMerkleRoot = block.calc_merkle_root()
            block.rehash()
            block.solve()
            if valid:  # only the accepted block advances the tip
                assert block.sha256 is not None
                self.tip, self.tip_time, self.height = block.sha256, block_time, height
            yield TestInstance([[block, valid]])


async def run_enforcement_test(node_factory: NodeFactory, invalidate: Invalidate) -> None:
    # Whitelist so the harness peer survives the ban scored against the invalid block.
    node = await node_factory(0, extra_args=[*POW_ARGS, "-whitelist=127.0.0.1"])
    manager = TestManager(_Enforcement(node, invalidate))
    await manager.add_all_connections([node])
    await manager.run()
