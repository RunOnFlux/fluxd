"""The insight fields getrawtransaction attaches when ``-insightexplorer`` is set.

Verbose ``getrawtransaction`` gains spent-index data once ``fSpentIndex`` is on:
a non-coinbase input reports the value/address of the output it consumes, and an
output reports the txid/index/height of the input that later spends it. A
transaction in a block carries that block's ``height``; one still in the mempool
carries none, and an output spent only by a still-unconfirmed transaction
reports ``spentHeight`` -1. The whole surface is re-checked after restarting
every node, proving the spent index was persisted to disk and reloaded.

The chain is funded in PoW mode (PON pushed past the run) so a coinbase pays the
wallet. Flux's PoW coinbase is a single ~150 FLUX miner output to a fresh
address each block, with no per-block founders/dev-fund second output -- so the
Zcash legacy's fixed 10-FLUX coinbase value does not hold; the consumed
coinbase's value is read back from the chain rather than assumed.
"""

from decimal import Decimal
from typing import Any

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes, sync_blocks, sync_mempools
from fluxtest.node import FluxNode

COIN = 100_000_000

# -insightexplorer turns on the spent index (fSpentIndex); it additionally
# requires -txindex and the experimental-features gate. PoW funding requires the
# PON push so a coinbase pays the wallet.
INSIGHT_ARGS = ["-experimentalfeatures", "-insightexplorer", "-txindex", *POW_ARGS]


def _sat(amount: Decimal) -> int:
    return int((amount * COIN).to_integral_value())


@pytest.fixture
async def insight_network(node_factory: NodeFactory) -> list[FluxNode]:
    """Three insight-enabled PoW nodes (miner, holder, reader), the miner funded."""
    nodes = [await node_factory(i, extra_args=INSIGHT_ARGS) for i in range(3)]
    miner, holder, reader = nodes
    await connect_nodes(miner, holder)
    await connect_nodes(miner, reader)
    await connect_nodes(holder, reader)
    # Mature block 1's premine coinbase so the miner has a spendable balance.
    await miner.mine(COINBASE_MATURITY + 1)
    await sync_blocks(nodes)
    return nodes


async def _restart_all(nodes: list[FluxNode]) -> None:
    """Restart every node so its spent index is flushed to disk and reloaded.

    Every node is brought down before any is brought back up so a restarted node
    recovers its index from its own disk files rather than re-syncing it from a
    peer that never went down.
    """
    for node in nodes:
        await node.stop_daemon()
    for node in nodes:
        await node.start()
    for a, b in ((0, 1), (0, 2), (1, 2)):
        await connect_nodes(nodes[a], nodes[b])
    await sync_blocks(nodes)


def _payment_vout(tx: dict[str, Any], amount: Decimal) -> dict[str, Any]:
    """The output of a verbose tx paying exactly ``amount`` (not the change)."""
    matches = [o for o in tx["vout"] if o["value"] == amount]
    assert len(matches) == 1
    return matches[0]


async def test_getrawtransaction_insight_fields(insight_network: list[FluxNode]) -> None:
    """Spent-index fields appear on getrawtransaction and survive a restart.

    A wallet send from the miner to the holder (txid_a) is confirmed; a second
    send from the holder to the reader (txid_b) spends txid_a's payment output.
    While txid_b is unconfirmed, txid_a's payment output already reports it as the
    spender with spentHeight -1, and txid_b itself carries no block height. Once
    txid_b is mined and every node restarted, the heights become real, txid_a's
    consumed coinbase value (read from the chain, not the Zcash-fixed 10 FLUX) is
    reported on its input, and txid_b's still-unspent output carries no spent
    fields.
    """
    nodes = insight_network
    miner, holder, reader = nodes

    # txid_a: miner -> holder. sendtoaddress leaves change, so the payment output
    # is found by its value rather than by index.
    payment_a = Decimal(2)
    addr_a = await holder.rpc.getnewaddress()
    txid_a = await miner.rpc.sendtoaddress(addr_a, payment_a)
    await sync_mempools(nodes)
    await miner.mine(1)  # confirm txid_a
    await sync_blocks(nodes)
    height_a = await miner.rpc.getblockcount()

    # The coinbase that txid_a consumes; its value is read off the chain.
    txid_a_raw = await miner.rpc.getrawtransaction(txid_a, 1)
    coinbase_txid = txid_a_raw["vin"][0]["txid"]
    coinbase_vout = txid_a_raw["vin"][0]["vout"]
    coinbase_raw = await miner.rpc.getrawtransaction(coinbase_txid, 1)
    coinbase_value = coinbase_raw["vout"][coinbase_vout]["value"]

    # txid_b: holder -> reader, spending the payment txid_a made to addr_a. The
    # holder's only spendable utxo is that payment.
    addr_b = await reader.rpc.getnewaddress()
    holder_utxo = next(u for u in await holder.rpc.listunspent(1) if u["address"] == addr_a)
    assert holder_utxo["spendable"] is True
    payment_b = Decimal(1)
    txid_b = await holder.rpc.sendtoaddress(addr_b, payment_b)
    await sync_mempools(nodes)

    # txid_b is unconfirmed: it has no block height yet.
    tx_b = await reader.rpc.getrawtransaction(txid_b, 1)
    assert "height" not in tx_b

    # txid_a's payment output is already marked spent by txid_b, but with an
    # invalid (-1) spentHeight because that spend is not yet in a block.
    tx_a = await reader.rpc.getrawtransaction(txid_a, 1)
    spent_vout = _payment_vout(tx_a, payment_a)
    assert spent_vout["spentTxId"] == txid_b
    assert spent_vout["spentIndex"] == 0
    assert spent_vout["spentHeight"] == -1
    payment_index = spent_vout["n"]

    await miner.mine(1)  # confirm txid_b
    await sync_blocks(nodes)
    height_b = await miner.rpc.getblockcount()

    # Restart so the spent index is read back from disk rather than from memory.
    await _restart_all(nodes)

    # txid_a: its input consumed the coinbase (value read from the chain), it is
    # confirmed at height_a, and its payment output now records the real spend
    # height of txid_b.
    tx_a = await reader.rpc.getrawtransaction(txid_a, 1)
    assert tx_a["vin"][0]["value"] == coinbase_value
    assert tx_a["vin"][0]["valueSat"] == _sat(coinbase_value)
    assert tx_a["height"] == height_a
    spent_vout = _payment_vout(tx_a, payment_a)
    assert spent_vout["n"] == payment_index
    assert spent_vout["spentTxId"] == txid_b
    assert spent_vout["spentIndex"] == 0
    assert spent_vout["spentHeight"] == height_b

    # txid_b: its input sources addr_a's payment, and its own outputs are still
    # unspent so they carry no spent fields.
    tx_b = await reader.rpc.getrawtransaction(txid_b, 1)
    assert tx_b["vin"][0]["address"] == addr_a
    assert tx_b["vin"][0]["value"] == payment_a
    assert tx_b["vin"][0]["valueSat"] == _sat(payment_a)
    assert tx_b["height"] == height_b
    for out in tx_b["vout"]:
        assert "spentTxId" not in out
        assert "spentIndex" not in out
        assert "spentHeight" not in out
