"""Mempool eviction once the total transaction-cost limit is exceeded.

Flux caps the mempool by a *cost* budget (``-mempooltxcostlimit``), not a raw
transaction count. Each transaction's cost is ``max(its memory usage, 4000)``,
so a small transparent spend always costs the 4000-zatoshi floor. A limit of
8000 therefore holds exactly two such transactions, and a limit of 12000 holds
three: when a further transaction pushes the total over the budget, the daemon
evicts one (randomly, weighted by eviction weight) back down to the cap. Mining
a block then clears the mempool entirely.
"""

from decimal import Decimal

from conftest import POW_ARGS, NodeFactory
from fluxtest.node import FluxNode

# Each small transparent spend costs the MIN_TX_COST floor of 4000 zatoshi, so a
# cost limit sized as a whole multiple of it maps to an exact transaction count.
COST_LIMIT_TWO = 8000
COST_LIMIT_THREE = 12000


async def _spend_coinbase(node: FluxNode, coinbase_txid: str, to_address: str) -> str:
    """Sign a one-input spend of a matured coinbase, less a tiny fee.

    The full coinbase value (minus a normal fee) is forwarded so the spend is
    not rejected by the absurd-fee check that a small hardcoded output would
    trip on Flux's ~150 FLUX coinbases.
    """
    coinbase = await node.rpc.getrawtransaction(coinbase_txid, 1)
    amount = coinbase["vout"][0]["value"] - Decimal("0.0001")
    rawtx = await node.rpc.createrawtransaction(
        [{"txid": coinbase_txid, "vout": 0}], {to_address: amount}
    )
    signed = await node.rpc.signrawtransaction(rawtx)
    assert signed["complete"] is True
    return signed["hex"]


async def _matured_coinbase_txids(node: FluxNode, count: int) -> list[str]:
    """The coinbase txids of the first ``count`` blocks, now matured and spendable."""
    return [
        (await node.rpc.getblock(await node.rpc.getblockhash(height)))["tx"][0]
        for height in range(1, count + 1)
    ]


async def test_mempool_evicts_down_to_cost_limit(node_factory: NodeFactory) -> None:
    """A third transaction over an 8000 cost limit is evicted back down to two."""
    node = await node_factory(
        0, extra_args=[*POW_ARGS, f"-mempooltxcostlimit={COST_LIMIT_TWO}", "-debug=mempool"]
    )
    # Mature the first few coinbases so node owns spendable, signable inputs.
    # The highest spent block needs 100 confirmations on top of it.
    await node.mine(105)
    coinbases = await _matured_coinbase_txids(node, 3)

    spends = [
        await _spend_coinbase(node, txid, await node.rpc.getnewaddress()) for txid in coinbases
    ]

    # Two transactions exactly fill the 8000 cost budget.
    await node.rpc.sendrawtransaction(spends[0])
    await node.rpc.sendrawtransaction(spends[1])
    assert len(await node.rpc.getrawmempool()) == 2

    # The third pushes the total cost over the limit, so the daemon evicts one
    # transaction and the mempool settles back at the cap of two.
    await node.rpc.sendrawtransaction(spends[2])
    assert len(await node.rpc.getrawmempool()) == 2

    # Mining a block clears the mempool of the surviving transactions.
    await node.mine(1)
    assert len(await node.rpc.getrawmempool()) == 0


async def test_higher_cost_limit_holds_more(node_factory: NodeFactory) -> None:
    """A 12000 cost limit holds three transactions before evicting the fourth."""
    node = await node_factory(
        0,
        extra_args=[*POW_ARGS, f"-mempooltxcostlimit={COST_LIMIT_THREE}", "-debug=mempool"],
    )
    await node.mine(105)
    coinbases = await _matured_coinbase_txids(node, 4)

    spends = [
        await _spend_coinbase(node, txid, await node.rpc.getnewaddress()) for txid in coinbases
    ]

    # Three transactions exactly fill the 12000 cost budget; all survive.
    for spend in spends[:3]:
        await node.rpc.sendrawtransaction(spend)
    assert len(await node.rpc.getrawmempool()) == 3

    # The fourth exceeds the limit and is evicted back down to the cap of three.
    await node.rpc.sendrawtransaction(spends[3])
    assert len(await node.rpc.getrawmempool()) == 3

    await node.mine(1)
    assert len(await node.rpc.getrawmempool()) == 0
