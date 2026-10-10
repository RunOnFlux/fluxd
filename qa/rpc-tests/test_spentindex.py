"""The spentindex the insight explorer builds when ``-insightexplorer`` is set.

Exercises the spent-tracking surface fluxd exposes once ``fSpentIndex`` is on:
the extra fields ``getrawtransaction`` attaches in verbose mode (a vin's source
``value``/``valueSat``/``address`` and a vout's ``spentTxId``/``spentIndex``/
``spentHeight`` once it is consumed), the ``getspentinfo`` lookup that maps an
output back to the input that spent it, and the per-transaction input/output
deltas ``getblockdeltas`` reports for a block.

The chain is funded in PoW mode (PON pushed past the run) so a coinbase pays the
wallet. Flux's PoW coinbase is a single ~150 FLUX miner output to a fresh
address each block, with no per-block founders/dev-fund second output -- so the
Zcash legacy's fixed economics (10-FLUX coinbases, a 2.5-FLUX founders vout, a
two-output coinbase) do not hold. Every amount, output count, height and version
asserted here is read back from the chain rather than assumed.
"""

from decimal import Decimal
from typing import Any

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# -insightexplorer turns on the spent/address/timestamp indexes; the spent index
# additionally requires -txindex, and PoW funding requires the PON push.
INSIGHT_ARGS = ["-experimentalfeatures", "-insightexplorer", "-txindex", *POW_ARGS]

# A whole coinbase output is spent less a normal fee so the spend is never
# rejected by the absurd-fee guard a tiny hardcoded amount would trip on Flux's
# ~150 FLUX coinbases.
FEE = Decimal("0.0001")

# getspentinfo raises RPC_INVALID_ADDRESS_OR_KEY for an output with no spend.
RPC_INVALID_ADDRESS_OR_KEY = -5


async def _spendable_coinbase(node: FluxNode) -> dict[str, Any]:
    """Return one mature, signable coinbase utxo.

    listunspent also surfaces the unsignable P2SH fund outputs (spendable
    False) that appear on a few early coinbases; those are filtered out.
    """
    utxos = [u for u in await node.rpc.listunspent(1) if u["spendable"]]
    assert utxos, "no spendable coinbase available"
    return utxos[0]


async def _spend_whole(
    node: FluxNode, source: dict[str, Any], to_address: str
) -> tuple[str, Decimal]:
    """Spend one whole utxo (less a fee) to ``to_address`` and broadcast it.

    Returns the txid and the payment amount. The single payment output keeps the
    spent-index assertions unambiguous: there is no change output to filter past.
    """
    value = source["amount"] - FEE
    rawtx = await node.rpc.createrawtransaction(
        [{"txid": source["txid"], "vout": source["vout"]}], {to_address: value}
    )
    signed = await node.rpc.signrawtransaction(rawtx)
    assert signed["complete"] is True
    txid = await node.rpc.sendrawtransaction(signed["hex"])
    return txid, value


@pytest.fixture
async def insight_network(node_factory: NodeFactory) -> list[FluxNode]:
    """Three insight-enabled PoW nodes (miner, holder, reader), node0 funded."""
    nodes = [await node_factory(i, extra_args=INSIGHT_ARGS) for i in range(3)]
    miner, holder, reader = nodes
    await connect_nodes(miner, holder)
    await connect_nodes(miner, reader)
    await connect_nodes(holder, reader)
    # Mature block 1's coinbase so the miner has a spendable balance.
    await miner.mine(COINBASE_MATURITY + 1)
    await sync_blocks(nodes)
    return nodes


async def _restart_all(nodes: list[FluxNode]) -> None:
    """Restart every node so its index files are flushed and reloaded.

    Each node is brought down before any is brought back up, mirroring the
    legacy stop-all/start-all and avoiding a restarted node syncing from a peer
    rather than from its own on-disk index.
    """
    for node in nodes:
        await node.stop_daemon()
    for node in nodes:
        await node.start()
    for a, b in ((0, 1), (0, 2), (1, 2)):
        await connect_nodes(nodes[a], nodes[b])
    await sync_blocks(nodes)


async def test_getrawtransaction_spent_fields(insight_network: list[FluxNode]) -> None:
    """A spent output gains spentTxId/spentIndex/spentHeight; an unspent one does not.

    The funding tx's vin reports the consumed coinbase's real value, and the
    height fields follow confirmation: an unconfirmed tx has no height, a
    confirmed one does. The whole chain is exercised after a restart to prove the
    spent index was persisted and recovered, not merely held in memory.
    """
    nodes = insight_network
    miner, holder, reader = nodes

    addr1 = await holder.rpc.getnewaddress()
    coinbase = await _spendable_coinbase(miner)
    coinbase_value = coinbase["amount"]
    txid1, payment1 = await _spend_whole(miner, coinbase, addr1)
    await sync_blocks(nodes)
    await miner.mine(1)  # height 102: confirms txid1
    await sync_blocks(nodes)
    height1 = await miner.rpc.getblockcount()

    addr2 = await reader.rpc.getnewaddress()
    # The holder's only spendable utxo is the payment from addr1.
    holder_utxo = next(u for u in await holder.rpc.listunspent(1) if u["address"] == addr1)
    txid2, _payment2 = await _spend_whole(holder, holder_utxo, addr2)
    await sync_mempools(nodes)

    # Unconfirmed: txid2 is in the mempool, so it carries no block height yet.
    tx2_unconfirmed = await reader.rpc.getrawtransaction(txid2, 1)
    assert "height" not in tx2_unconfirmed

    await miner.mine(1)  # height 103: confirms txid2
    await sync_blocks(nodes)
    height2 = await miner.rpc.getblockcount()

    await _restart_all(nodes)

    # txid1's vin is the consumed coinbase; its value is read from the chain.
    tx1 = await reader.rpc.getrawtransaction(txid1, 1)
    assert tx1["vin"][0]["value"] == coinbase_value
    assert tx1["vin"][0]["valueSat"] == int(coinbase_value * 100000000)
    assert tx1["height"] == height1
    payment_vout = next(o for o in tx1["vout"] if o["value"] == payment1)
    assert payment_vout["spentTxId"] == txid2
    assert payment_vout["spentIndex"] == 0
    assert payment_vout["spentHeight"] == height2
    spent_index = payment_vout["n"]

    # txid2's vin sources addr1's payment output; its outputs are still unspent.
    tx2 = await reader.rpc.getrawtransaction(txid2, 1)
    assert tx2["vin"][0]["address"] == addr1
    assert tx2["vin"][0]["value"] == payment1
    assert tx2["vin"][0]["valueSat"] == int(payment1 * 100000000)
    assert "spentTxId" not in tx2["vout"][0]
    assert "spentIndex" not in tx2["vout"][0]
    assert "spentHeight" not in tx2["vout"][0]
    assert tx2["height"] == height2

    # getspentinfo maps txid1's payment output to the input that spent it.
    spent = await reader.rpc.getspentinfo({"txid": txid1, "index": spent_index})
    assert spent["txid"] == txid2
    assert spent["index"] == 0
    assert spent["height"] == height2

    # An output that has not been spent has no spent info.
    with pytest.raises(JSONRPCError) as excinfo:
        await holder.rpc.getspentinfo({"txid": txid2, "index": 0})
    assert excinfo.value.error["message"] == "Unable to get spent info"
    assert excinfo.value.code == RPC_INVALID_ADDRESS_OR_KEY


async def test_getblockdeltas(insight_network: list[FluxNode]) -> None:
    """getblockdeltas reports each tx's input/output deltas and the block metadata.

    The Zcash founders assumptions (a two-output coinbase, a 2.5-FLUX founders
    vout) are dropped: Flux's PoW coinbase here is a single miner output, so the
    coinbase delta's output count and values are read from the chain. The spend
    deltas are checked for the satoshi sign convention (inputs negative, outputs
    positive), the prevtxid/prevout links, and the block's confirmations / height
    / version / hash / previous- and next-block links.
    """
    nodes = insight_network
    miner, holder, reader = nodes

    addr1 = await holder.rpc.getnewaddress()
    coinbase = await _spendable_coinbase(miner)
    txid1, payment1 = await _spend_whole(miner, coinbase, addr1)
    await sync_blocks(nodes)
    block_hash1 = (await miner.mine(1))[0]  # confirms txid1
    await sync_blocks(nodes)
    height1 = await miner.rpc.getblockcount()

    addr2 = await reader.rpc.getnewaddress()
    holder_utxo = next(u for u in await holder.rpc.listunspent(1) if u["address"] == addr1)
    txid2, payment2 = await _spend_whole(holder, holder_utxo, addr2)
    await sync_mempools(nodes)
    block_hash2 = (await miner.mine(1))[0]  # confirms txid2
    await sync_blocks(nodes)
    block_hash_next = (await miner.mine(1))[0]
    await sync_blocks(nodes)

    # Block version is read from the chain rather than hardcoded to the legacy 4.
    block1_version = (await reader.rpc.getblock(block_hash1))["version"]
    block2_version = (await reader.rpc.getblock(block_hash2))["version"]

    # --- The block confirming txid1: [coinbase, txid1]. ---
    deltas1 = await reader.rpc.getblockdeltas(block_hash1)
    chain_height = await reader.rpc.getblockcount()
    assert deltas1["confirmations"] == chain_height - height1 + 1
    assert deltas1["height"] == height1
    assert deltas1["version"] == block1_version
    assert deltas1["hash"] == block_hash1
    assert deltas1["nextblockhash"] == block_hash2
    blk1 = deltas1["deltas"]
    assert len(blk1) == 2

    coinbase1 = blk1[0]
    assert coinbase1["index"] == 0
    assert coinbase1["inputs"] == []
    # Flux's regular PoW coinbase pays a single miner output; its count and the
    # delta values come from the block itself.
    block1 = await reader.rpc.getblock(block_hash1, True)
    coinbase_txid1 = block1["tx"][0]
    coinbase_tx1 = await reader.rpc.getrawtransaction(coinbase_txid1, 1)
    assert len(coinbase1["outputs"]) == len(coinbase_tx1["vout"])
    for delta_out, chain_out in zip(coinbase1["outputs"], coinbase_tx1["vout"], strict=True):
        assert delta_out["index"] == chain_out["n"]
        assert delta_out["satoshis"] == chain_out["valueSat"]

    to_a = blk1[1]
    assert to_a["index"] == 1
    assert to_a["txid"] == txid1
    assert len(to_a["inputs"]) == 1
    assert to_a["inputs"][0]["index"] == 0
    assert to_a["inputs"][0]["prevout"] == coinbase["vout"]
    assert to_a["inputs"][0]["prevtxid"] == coinbase["txid"]
    # The single consumed coinbase appears as a negative input delta.
    assert to_a["inputs"][0]["satoshis"] == -int(coinbase["amount"] * 100000000)
    payment_out_a = [o for o in to_a["outputs"] if o["address"] == addr1]
    assert len(payment_out_a) == 1
    assert payment_out_a[0]["satoshis"] == int(payment1 * 100000000)

    # --- The block confirming txid2: [coinbase, txid2]. ---
    deltas2 = await reader.rpc.getblockdeltas(block_hash2)
    assert deltas2["confirmations"] == chain_height - (height1 + 1) + 1
    assert deltas2["height"] == height1 + 1
    assert deltas2["version"] == block2_version
    assert deltas2["hash"] == block_hash2
    assert deltas2["previousblockhash"] == block_hash1
    assert deltas2["nextblockhash"] == block_hash_next
    blk2 = deltas2["deltas"]
    assert len(blk2) == 2

    coinbase2 = blk2[0]
    assert coinbase2["index"] == 0
    assert coinbase2["inputs"] == []
    block2 = await reader.rpc.getblock(block_hash2, True)
    coinbase_tx2 = await reader.rpc.getrawtransaction(block2["tx"][0], 1)
    assert len(coinbase2["outputs"]) == len(coinbase_tx2["vout"])
    for delta_out, chain_out in zip(coinbase2["outputs"], coinbase_tx2["vout"], strict=True):
        assert delta_out["index"] == chain_out["n"]
        assert delta_out["satoshis"] == chain_out["valueSat"]

    to_b = blk2[1]
    assert to_b["index"] == 1
    assert to_b["txid"] == txid2
    assert len(to_b["inputs"]) == 1
    assert to_b["inputs"][0]["index"] == 0
    assert to_b["inputs"][0]["prevtxid"] == txid1
    assert to_b["inputs"][0]["satoshis"] == -int(payment1 * 100000000)
    payment_out_b = [o for o in to_b["outputs"] if o["address"] == addr2]
    assert len(payment_out_b) == 1
    assert payment_out_b[0]["satoshis"] == int(payment2 * 100000000)
