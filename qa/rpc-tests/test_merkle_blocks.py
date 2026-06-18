"""Test gettxoutproof / verifytxoutproof."""

from decimal import Decimal

import pytest
from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.rpc import JSONRPCError

TXINDEX_ARGS = [*POW_ARGS, "-txindex"]


async def test_txoutproof(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=TXINDEX_ARGS)
    verifier = await node_factory(1, extra_args=TXINDEX_ARGS)
    await connect_nodes_bi(node, verifier)
    await node.mine(110)  # several mature coinbases to spend
    await sync_blocks([node, verifier])

    utxos = await node.rpc.listunspent(1)
    assert len(utxos) >= 2

    async def spend(utxo: dict) -> str:
        address = await node.rpc.getnewaddress()
        amount = utxo["amount"] - Decimal("0.0001")
        rawtx = await node.rpc.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}], {address: amount}
        )
        signed = await node.rpc.signrawtransaction(rawtx)
        return await node.rpc.sendrawtransaction(signed["hex"])

    txid1 = await spend(utxos[0])
    txid2 = await spend(utxos[1])

    # No proof exists for an unconfirmed transaction.
    with pytest.raises(JSONRPCError):
        await node.rpc.gettxoutproof([txid1])

    blockhash = (await node.mine(1))[0]
    await sync_blocks([node, verifier])

    # The verifier fetches and verifies proofs from the block.
    proof1 = await verifier.rpc.gettxoutproof([txid1])
    assert await verifier.rpc.verifytxoutproof(proof1) == [txid1]

    proof2 = await verifier.rpc.gettxoutproof([txid1, txid2], blockhash)
    assert set(await verifier.rpc.verifytxoutproof(proof2)) == {txid1, txid2}
