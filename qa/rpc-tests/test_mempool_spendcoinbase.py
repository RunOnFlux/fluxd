"""Coinbase spends enter the mempool only once the coinbase is mature."""

from decimal import Decimal

import pytest
from conftest import POW_ARGS, NodeFactory
from fluxtest.rpc import JSONRPCError


async def test_spend_immature_coinbase(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=[*POW_ARGS, "-checkmempool"])
    await node.mine(101)
    height = await node.rpc.getblockcount()
    address = await node.rpc.getnewaddress()

    # A coinbase needs COINBASE_MATURITY (100) confirmations. Spent in the next
    # block, the coinbase at `mature` height has exactly 100 (accepted); the one
    # above it is one short (rejected).
    mature = height - 99
    immature = mature + 1

    async def spend(block_height: int) -> str:
        block = await node.rpc.getblock(await node.rpc.getblockhash(block_height))
        coinbase_txid = block["tx"][0]
        coinbase = await node.rpc.getrawtransaction(coinbase_txid, 1)
        # Spend the whole coinbase output minus a normal fee, so the spend is
        # rejected on maturity rather than an absurd-fee check.
        amount = coinbase["vout"][0]["value"] - Decimal("0.0001")
        rawtx = await node.rpc.createrawtransaction(
            [{"txid": coinbase_txid, "vout": 0}], {address: amount}
        )
        signed = await node.rpc.signrawtransaction(rawtx)
        assert signed["complete"] is True
        return await node.rpc.sendrawtransaction(signed["hex"])

    spend_id = await spend(mature)

    with pytest.raises(JSONRPCError):
        await spend(immature)

    info = await node.rpc.getmempoolinfo()
    assert info["size"] == 1
    assert await node.rpc.getrawmempool() == [spend_id]

    # The accepted spend confirms in the next block and leaves the mempool.
    await node.mine(1)
    assert await node.rpc.getrawmempool() == []
    best = await node.rpc.getblock(await node.rpc.getbestblockhash())
    assert spend_id in best["tx"]
