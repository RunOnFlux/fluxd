"""Exercise the listtransactions API: send and receive categories."""

from decimal import Decimal

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode


def _find(txs: list[dict], txid: str, category: str) -> dict:
    matches = [t for t in txs if t["txid"] == txid and t["category"] == category]
    assert matches, f"no {category} entry for {txid}"
    return matches[0]


async def test_listtransactions(funded_node: FluxNode, node_factory: NodeFactory) -> None:
    sender = funded_node
    receiver = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(sender, receiver)
    await sync_blocks([sender, receiver])

    address = await receiver.rpc.getnewaddress()
    txid = await sender.rpc.sendtoaddress(address, Decimal("0.1"))

    # Unconfirmed: sender records a send, with the negative amount.
    sent = _find(await sender.rpc.listtransactions(), txid, "send")
    assert sent["amount"] == Decimal("-0.1")
    assert sent["confirmations"] == 0

    # After a block, the receiver records a confirmed receive.
    await sender.mine(1)
    await sync_blocks([sender, receiver])
    received = _find(await receiver.rpc.listtransactions(), txid, "receive")
    assert received["amount"] == Decimal("0.1")
    assert received["confirmations"] == 1
