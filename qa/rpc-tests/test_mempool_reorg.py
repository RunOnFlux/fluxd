"""Re-org handling of a mempool holding direct and indirect coinbase spends.

Exercises three ways a coinbase ends up spent in the mempool -- a direct
coinbase spend, a coinbase spent in a block whose child is in the mempool, and
a coinbase whose spend and grandchild are both mined -- plus a block-height
timelocked transaction that is only valid once the chain is tall enough.

Two invalidateblock waves then verify mempool maintenance: disconnecting the
last block resurrects the freshly-mined spend and evicts the now-non-final
timelock, and disconnecting the block that introduced the spent coinbases
(re-orging them out of the chain) makes every coinbase spend immature and
empties the mempool entirely.
"""

import asyncio
from decimal import Decimal

import pytest
from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# A coinbase needs 100 confirmations before it can be spent, so the four
# coinbases under test are matured by mining 100 further blocks on top of them.
MATURITY_DEPTH = 100


async def _sync_mempools(nodes: list[FluxNode], timeout: float = 60) -> None:
    """Wait until every node holds the same set of mempool transactions."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        pools = [set(await node.rpc.getrawmempool()) for node in nodes]
        if all(pool == pools[0] for pool in pools[1:]):
            return
        if loop.time() > deadline:
            raise AssertionError(f"mempools did not sync within {timeout}s: {pools}")
        await asyncio.sleep(0.25)


async def _create_tx(node: FluxNode, from_txid: str, to_address: str) -> str:
    """Sign a one-input, one-output spend of a coinbase, less a tiny fee.

    The whole coinbase value (minus a normal fee) is sent on, so the spend is
    rejected only on coinbase maturity -- not the absurd-fee check that a small
    hardcoded output would trip on Flux's ~150 FLUX coinbases.
    """
    coinbase = await node.rpc.getrawtransaction(from_txid, 1)
    amount = coinbase["vout"][0]["value"] - Decimal("0.0001")
    rawtx = await node.rpc.createrawtransaction(
        [{"txid": from_txid, "vout": 0}], {to_address: amount}
    )
    signed = await node.rpc.signrawtransaction(rawtx)
    assert signed["complete"] is True
    return signed["hex"]


async def test_mempool_coinbase_spend_reorg(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0, extra_args=[*POW_ARGS, "-checkmempool", "-debug=mempool"])
    node1 = await node_factory(1, extra_args=[*POW_ARGS, "-checkmempool", "-debug=mempool"])
    await connect_nodes_bi(node1, node0)

    # node0 mines the four coinbase-bearing blocks (it owns the keys, so it can
    # sign their spends), then matures them by mining MATURITY_DEPTH more on top.
    # new_blocks[0] is the block that introduces the first spent coinbase:
    # re-orging it out later strips all four coinbases.
    new_blocks = await node0.mine(4)
    await node0.mine(MATURITY_DEPTH)
    await sync_blocks([node0, node1])

    node0_address = await node0.rpc.getnewaddress()
    node1_address = await node1.rpc.getnewaddress()

    # The four matured coinbases. Three scenarios for re-orging coinbase spends
    # in the mempool plus one block-height timelocked spend:
    #   1. direct coinbase spend                                   : spend_101
    #   2. coinbase spent in a block, child in the mempool         : spend_102 / spend_102_1
    #   3. coinbase spend and its child both mined                 : spend_103 / spend_103_1
    coinbase_txids = [
        (await node0.rpc.getblock(h))["tx"][0]
        for h in [await node0.rpc.getblockhash(n) for n in range(1, 5)]
    ]
    spend_101_raw = await _create_tx(node0, coinbase_txids[1], node1_address)
    spend_102_raw = await _create_tx(node0, coinbase_txids[2], node0_address)
    spend_103_raw = await _create_tx(node0, coinbase_txids[3], node0_address)

    # A block-height timelocked spend of the first coinbase, invalid until the
    # chain grows two blocks taller. The input sequence is forced non-final
    # (ffffffff -> 11111111) so the appended nLockTime is enforced, and the
    # trailing 4 little-endian locktime bytes are spliced on by hand.
    timelock_amount = (await node0.rpc.getrawtransaction(coinbase_txids[0], 1))["vout"][0][
        "value"
    ] - Decimal("0.0001")
    timelock_tx = await node0.rpc.createrawtransaction(
        [{"txid": coinbase_txids[0], "vout": 0}], {node0_address: timelock_amount}
    )
    timelock_tx = timelock_tx.replace("ffffffff", "11111111", 1)
    timelock_tx = timelock_tx[:-8] + hex(await node0.rpc.getblockcount() + 2)[2:] + "000000"
    timelock_tx = (await node0.rpc.signrawtransaction(timelock_tx))["hex"]
    with pytest.raises(JSONRPCError):
        await node0.rpc.sendrawtransaction(timelock_tx)

    # Broadcast and mine spend_102 and spend_103.
    spend_102_id = await node0.rpc.sendrawtransaction(spend_102_raw)
    spend_103_id = await node0.rpc.sendrawtransaction(spend_103_raw)
    await node0.mine(1)
    # Still one block too short for the timelock.
    with pytest.raises(JSONRPCError):
        await node0.rpc.sendrawtransaction(timelock_tx)

    # Children of the now-mined spends.
    spend_102_1_raw = await _create_tx(node0, spend_102_id, node1_address)
    spend_103_1_raw = await _create_tx(node0, spend_103_id, node1_address)

    # Broadcast and mine spend_103_1.
    spend_103_1_id = await node0.rpc.sendrawtransaction(spend_103_1_raw)
    last_block = await node0.mine(1)
    # The chain is now tall enough: the timelock becomes final and is accepted.
    timelock_tx_id = await node0.rpc.sendrawtransaction(timelock_tx)

    # ... now put spend_101 and spend_102_1 in the mempool.
    spend_101_id = await node0.rpc.sendrawtransaction(spend_101_raw)
    spend_102_1_id = await node0.rpc.sendrawtransaction(spend_102_1_raw)

    await sync_blocks([node0, node1])
    await _sync_mempools([node0, node1])

    assert set(await node0.rpc.getrawmempool()) == {
        spend_101_id,
        spend_102_1_id,
        timelock_tx_id,
    }

    # Disconnect the last block: spend_103_1 resurrects, and the timelock is
    # evicted because the shorter chain makes it non-final again.
    for node in (node0, node1):
        await node.rpc.invalidateblock(last_block[0])
    assert set(await node0.rpc.getrawmempool()) == {
        spend_101_id,
        spend_102_1_id,
        spend_103_1_id,
    }

    # Re-org out the block that introduced the spent coinbases: every coinbase
    # spend becomes immature, so the mempool drains to empty.
    for node in (node0, node1):
        await node.rpc.invalidateblock(new_blocks[0])

    await sync_blocks([node0, node1])

    assert set(await node0.rpc.getrawmempool()) == set()
