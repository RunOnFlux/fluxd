"""Test listreceivedbyaddress / getreceivedbyaddress."""

from decimal import Decimal

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode


async def test_receivedbyaddress(funded_node: FluxNode, node_factory: NodeFactory) -> None:
    sender = funded_node
    receiver = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(sender, receiver)
    await sync_blocks([sender, receiver])

    address = await receiver.rpc.getnewaddress()
    txid = await sender.rpc.sendtoaddress(address, Decimal("0.1"))
    await sender.mine(1)
    await sync_blocks([sender, receiver])

    entries = [e for e in await receiver.rpc.listreceivedbyaddress() if e["address"] == address]
    assert len(entries) == 1
    assert entries[0]["amount"] == Decimal("0.1")
    assert entries[0]["confirmations"] == 1
    assert txid in entries[0]["txids"]

    assert await receiver.rpc.getreceivedbyaddress(address) == Decimal("0.1")
    # Requiring more confirmations than it has yields nothing.
    assert await receiver.rpc.getreceivedbyaddress(address, 2) == Decimal("0")
