"""A confirmed transaction is invalidated by a double-spend on a longer chain.

Reproduces the classic accounting hazard: node0 spends two specific coinbase
utxos to node1 in two ordinary transactions and confirms them in a block, while
an isolated miner (node2) holds a conflicting transaction that spends the very
same utxos. When node2 builds a strictly longer chain that includes its
double-spend and the network re-converges, node0 re-orgs onto node2's chain.

The two originally-confirmed transactions then report confirmations == -1
(wallet-conflicted): their inputs were consumed by the double-spend instead.
Balances follow the double-spend winning -- node1 receives the double-spend
output, and the two original sends are wiped from node0's accounting.
"""

import asyncio
from decimal import Decimal

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode

# A whole coinbase output is spent on, less a normal-sized fee, so the spend is
# never rejected by the absurd-fee check that a small hardcoded output would
# trip on Flux's ~150 FLUX coinbases.
FEE = Decimal("0.0001")


async def _peer_gone(node: FluxNode, p2p_port: int) -> bool:
    target = f":{p2p_port}"
    return not any(target in peer.get("addr", "") for peer in await node.rpc.getpeerinfo())


async def _wait_peer_gone(node: FluxNode, p2p_port: int, timeout: float = 30) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not await _peer_gone(node, p2p_port):
        if loop.time() > deadline:
            raise AssertionError(f"node {node.index} still connected to :{p2p_port}")
        await asyncio.sleep(0.1)


async def _spendable_coinbases(node: FluxNode, count: int) -> list[dict]:
    """Return ``count`` spendable utxos, newest excluded so they stay matured.

    listunspent also surfaces the unsignable P2SH fund outputs (spendable
    False); those are filtered out so a raw spend always signs to completion.
    """
    utxos = [u for u in await node.rpc.listunspent(1) if u["spendable"]]
    assert len(utxos) >= count, f"need {count} spendable utxos, have {len(utxos)}"
    return utxos[:count]


async def _signed_spend(node: FluxNode, utxos: list[dict], to_address: str) -> str:
    """Sign a raw tx spending ``utxos`` wholesale (less one fee) to one address."""
    total = sum((u["amount"] for u in utxos), Decimal(0))
    inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos]
    rawtx = await node.rpc.createrawtransaction(inputs, {to_address: total - FEE})
    signed = await node.rpc.signrawtransaction(rawtx)
    assert signed["complete"] is True
    return signed["hex"]


async def test_confirmed_tx_conflicted_by_doublespend_on_longer_chain(
    node_factory: NodeFactory,
) -> None:
    # node0 is the funded source, node1 the recipient, node2 the isolated
    # double-spend miner. All run in PoW mode so coinbases pay the wallet.
    node0 = await node_factory(0, extra_args=POW_ARGS)
    node1 = await node_factory(1, extra_args=POW_ARGS)
    node2 = await node_factory(2, extra_args=POW_ARGS)
    await connect_nodes_bi(node0, node1)
    await connect_nodes_bi(node0, node2)
    await connect_nodes_bi(node1, node2)

    # node0 mines and matures enough coinbases to spend; everyone syncs so node2
    # shares the same chain/utxos before it is split off.
    await node0.mine(105)
    await sync_blocks([node0, node1, node2])

    node1_address = await node1.rpc.getnewaddress()

    # Two specific mature coinbases that both the double-spend and the two
    # ordinary sends will consume.
    coin_a, coin_b = await _spendable_coinbases(node0, 2)
    doublespend_value = coin_a["amount"] + coin_b["amount"] - FEE

    # Build (but do not broadcast) the double-spend: both coinbases -> node1.
    doublespend_hex = await _signed_spend(node0, [coin_a, coin_b], node1_address)

    # SPLIT: isolate node2 from node0 and node1. node2 keeps the shared chain
    # and utxo set but no longer hears the ordinary sends node0 is about to make.
    await node0.rpc.disconnectnode(f"127.0.0.1:{node2.p2p_port}")
    await node1.rpc.disconnectnode(f"127.0.0.1:{node2.p2p_port}")
    await node2.rpc.disconnectnode(f"127.0.0.1:{node0.p2p_port}")
    await node2.rpc.disconnectnode(f"127.0.0.1:{node1.p2p_port}")
    await _wait_peer_gone(node0, node2.p2p_port)
    await _wait_peer_gone(node1, node2.p2p_port)
    await _wait_peer_gone(node2, node0.p2p_port)
    await _wait_peer_gone(node2, node1.p2p_port)

    # On the node0/node1 side, send two ordinary transactions that spend the
    # SAME two coinbases (one each) to node1, conflicting with the double-spend.
    tx1_hex = await _signed_spend(node0, [coin_a], node1_address)
    tx2_hex = await _signed_spend(node0, [coin_b], node1_address)
    txid1 = await node0.rpc.sendrawtransaction(tx1_hex)
    txid2 = await node0.rpc.sendrawtransaction(tx2_hex)
    tx1_amount = coin_a["amount"] - FEE
    tx2_amount = coin_b["amount"] - FEE

    # Confirm them in a block (the meaningful accounting case): both reach 1
    # confirmation and node1 sees the two sends arrive.
    await node0.mine(1)
    await sync_blocks([node0, node1])

    assert (await node0.rpc.gettransaction(txid1))["confirmations"] == 1
    assert (await node0.rpc.gettransaction(txid2))["confirmations"] == 1
    node1_received_confirmed = await node1.rpc.getreceivedbyaddress(node1_address)
    assert node1_received_confirmed == tx1_amount + tx2_amount

    # Hand the double-spend to the isolated miner and have it bury the spend
    # under a strictly longer chain than the node0/node1 side. node0/node1 are
    # one block past the split; node2 mines three to win the re-org race.
    await node2.rpc.sendrawtransaction(doublespend_hex)
    await node2.mine(3)
    assert await node2.rpc.getblockcount() > await node0.rpc.getblockcount()

    # Reconnect and re-converge: node0 and node1 adopt node2's longer chain.
    await connect_nodes_bi(node0, node2)
    await connect_nodes_bi(node1, node2)
    await sync_blocks([node0, node1, node2])

    # The two originally-confirmed sends are now wallet-conflicted: their inputs
    # were consumed by the double-spend on the winning chain.
    assert (await node0.rpc.gettransaction(txid1))["confirmations"] == -1
    assert (await node0.rpc.gettransaction(txid2))["confirmations"] == -1

    # node1 instead received the single double-spend output, and the two
    # conflicted sends no longer count toward what node1 received.
    node1_received_after = await node1.rpc.getreceivedbyaddress(node1_address)
    assert node1_received_after == doublespend_value

    # node0's wallet no longer credits the conflicted sends: their amounts drop
    # out of the gettransaction accounting (negative = funds left node0).
    assert (await node0.rpc.gettransaction(txid1))["amount"] < 0
    assert (await node0.rpc.gettransaction(txid2))["amount"] < 0

    # The two double-spent coinbases are no longer node0's to spend: the
    # double-spend consumed them on the winning chain.
    spendable_outpoints = {
        (u["txid"], u["vout"]) for u in await node0.rpc.listunspent(1) if u["spendable"]
    }
    assert (coin_a["txid"], coin_a["vout"]) not in spendable_outpoints
    assert (coin_b["txid"], coin_b["vout"]) not in spendable_outpoints
