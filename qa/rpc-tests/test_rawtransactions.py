"""Exercise the *rawtransaction RPCs over a three-node regtest network.

Verifies: a missing input is rejected with "Missing inputs"; a 2-of-2 multisig
whose keys are both held by one node counts toward that node's balance; a 2-of-3
multisig split across nodes is not counted as spendable; such a 2-of-3 output can
be spent with one partial signature plus a completing signature; and that an
explicit input sequence round-trips through createrawtransaction/decoderawtransaction.
"""

import asyncio
from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# A txid that does not exist on chain, used to provoke the missing-input path.
NONEXISTENT_TXID = "1d1d4e24ed99057e84c3f80fd8fbec79ed9e1acee37da269356ecea000000000"


async def _wait_for_mempool(node: FluxNode, txid: str, timeout: float = 30) -> None:
    """Wait until ``txid`` is in ``node``'s mempool so a miner will include it."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while txid not in await node.rpc.getrawmempool():
        if loop.time() > deadline:
            raise AssertionError(f"tx {txid} did not reach node {node.index} mempool")
        await asyncio.sleep(0.1)


async def _three_funded_nodes(
    node_factory: NodeFactory,
) -> tuple[FluxNode, FluxNode, FluxNode]:
    """Start three connected PoW-mode nodes; node0 holds the matured balance."""
    node0 = await node_factory(0, extra_args=POW_ARGS)
    node1 = await node_factory(1, extra_args=POW_ARGS)
    node2 = await node_factory(2, extra_args=POW_ARGS)

    await connect_nodes_bi(node0, node1)
    await connect_nodes_bi(node1, node2)
    await connect_nodes_bi(node0, node2)

    # Mature block 1's coinbase on node0 and a few spendable later-height blocks.
    await node0.mine(COINBASE_MATURITY + 5)
    await sync_blocks([node0, node1, node2])

    # Seed node2 with a few spendable outputs, as the legacy setup did. node0
    # both sends and mines, so the txs are already in node0's mempool to mine.
    await node0.rpc.sendtoaddress(await node2.rpc.getnewaddress(), Decimal("1.5"))
    await node0.rpc.sendtoaddress(await node2.rpc.getnewaddress(), Decimal("1.0"))
    await node0.rpc.sendtoaddress(await node2.rpc.getnewaddress(), Decimal("5.0"))
    await node0.mine(5)
    await sync_blocks([node0, node1, node2])

    return node0, node1, node2


async def test_sendrawtransaction_missing_input(node_factory: NodeFactory) -> None:
    """A signed tx spending a nonexistent output is rejected as a missing input."""
    node0, _node1, node2 = await _three_funded_nodes(node_factory)

    inputs = [{"txid": NONEXISTENT_TXID, "vout": 1}]
    outputs = {await node0.rpc.getnewaddress(): Decimal("4.998")}
    rawtx = await node2.rpc.createrawtransaction(inputs, outputs)
    signed = await node2.rpc.signrawtransaction(rawtx)

    with pytest.raises(JSONRPCError) as exc:
        await node2.rpc.sendrawtransaction(signed["hex"])
    assert "Missing inputs" in str(exc.value)


async def test_multisig_2of2_counts_toward_balance(node_factory: NodeFactory) -> None:
    """A 2-of-2 multisig with both keys on node2 increases node2's balance."""
    node0, _node1, node2 = await _three_funded_nodes(node_factory)

    addr1 = await node2.rpc.getnewaddress()
    addr2 = await node2.rpc.getnewaddress()
    pub1 = (await node2.rpc.validateaddress(addr1))["pubkey"]
    pub2 = (await node2.rpc.validateaddress(addr2))["pubkey"]

    msig = await node2.rpc.addmultisigaddress(2, [pub1, pub2])
    assert (await node2.rpc.validateaddress(msig))["isvalid"]

    bal = await node2.rpc.getbalance()
    await node0.rpc.sendtoaddress(msig, Decimal("1.2"))
    await node0.mine(1)
    await sync_blocks([node0, node2])

    # node2 owns both keys of the 2-of-2 address, so the output is spendable to it.
    assert await node2.rpc.getbalance() == bal + Decimal("1.2")


async def test_multisig_2of3_not_spendable(node_factory: NodeFactory) -> None:
    """A 2-of-3 multisig split across nodes is not counted as node2's balance."""
    node0, node1, node2 = await _three_funded_nodes(node_factory)

    bal = await node2.rpc.getbalance()
    addr1 = await node1.rpc.getnewaddress()
    addr2 = await node2.rpc.getnewaddress()
    addr3 = await node2.rpc.getnewaddress()
    pub1 = (await node1.rpc.validateaddress(addr1))["pubkey"]
    pub2 = (await node2.rpc.validateaddress(addr2))["pubkey"]
    pub3 = (await node2.rpc.validateaddress(addr3))["pubkey"]

    msig = await node2.rpc.addmultisigaddress(2, [pub1, pub2, pub3])
    assert (await node2.rpc.validateaddress(msig))["isvalid"]

    await node0.rpc.sendtoaddress(msig, Decimal("2.2"))
    await node0.mine(1)
    await sync_blocks([node0, node1, node2])

    # The funds of a 2-of-3 multisig spread across nodes are not marked spendable.
    assert await node2.rpc.getbalance() == bal


async def test_multisig_2of3_partial_then_complete_sign(node_factory: NodeFactory) -> None:
    """A 2-of-3 output needs a completing signature: node1 partial, node2 completes."""
    node0, node1, node2 = await _three_funded_nodes(node_factory)

    addr1 = await node1.rpc.getnewaddress()
    addr2 = await node2.rpc.getnewaddress()
    addr3 = await node2.rpc.getnewaddress()
    pub1 = (await node1.rpc.validateaddress(addr1))["pubkey"]
    pub2 = (await node2.rpc.validateaddress(addr2))["pubkey"]
    pub3 = (await node2.rpc.validateaddress(addr3))["pubkey"]

    msig = await node2.rpc.addmultisigaddress(2, [pub1, pub2, pub3])

    txid = await node0.rpc.sendtoaddress(msig, Decimal("2.2"))
    await node0.mine(1)
    await sync_blocks([node0, node1, node2])

    # Locate the 2.2 output of the funding tx to build a spend from it.
    funding = await node0.rpc.gettransaction(txid, True)
    decoded = await node0.rpc.decoderawtransaction(funding["hex"])
    vout = next(o for o in decoded["vout"] if o["value"] == Decimal("2.2"))

    inputs = [{"txid": txid, "vout": vout["n"], "scriptPubKey": vout["scriptPubKey"]["hex"]}]
    sink = await node0.rpc.getnewaddress()
    outputs = {sink: Decimal("2.199")}
    rawtx = await node2.rpc.createrawtransaction(inputs, outputs)

    # node1 holds only one of the three keys: it cannot complete the 2-of-2 spend.
    partial = await node1.rpc.signrawtransaction(rawtx, inputs)
    assert partial["complete"] is False

    # node2 holds two of the three keys and can complete the signature.
    fully = await node2.rpc.signrawtransaction(rawtx, inputs)
    assert fully["complete"] is True

    bal = await node0.rpc.getbalance()
    spend_txid = await node2.rpc.sendrawtransaction(fully["hex"])
    # node2 broadcast the spend; node0 must see it before it can mine it.
    await _wait_for_mempool(node0, spend_txid)
    spend_hashes = await node0.mine(1)
    await sync_blocks([node0, node1, node2])

    # node0 mined the block containing the spend, so its balance gains that
    # block's miner subsidy, and it receives the 2.199 explicit output. The 2.2
    # input was never counted (the 2-of-3 was not spendable by node0). The 0.001
    # fee is not credited to node0's balance on this chain.
    spend_height = (await node0.rpc.getblock(spend_hashes[0]))["height"]
    subsidy = (await node0.rpc.getblocksubsidy(spend_height))["miner"]
    assert await node0.rpc.getbalance() == bal + subsidy + Decimal("2.199")


async def test_createrawtransaction_sequence_roundtrips(node_factory: NodeFactory) -> None:
    """An explicit input sequence survives createrawtransaction/decoderawtransaction."""
    node0, _node1, _node2 = await _three_funded_nodes(node_factory)

    inputs = [{"txid": NONEXISTENT_TXID, "vout": 1, "sequence": 1000}]
    outputs = {await node0.rpc.getnewaddress(): 1}
    rawtx = await node0.rpc.createrawtransaction(inputs, outputs)
    decoded = await node0.rpc.decoderawtransaction(rawtx)
    assert decoded["vin"][0]["sequence"] == 1000
