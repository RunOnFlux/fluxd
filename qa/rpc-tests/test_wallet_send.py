"""A funded (PoW-mode) node can send coins to another node."""

from decimal import Decimal

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode


async def test_send_between_nodes(funded_node: FluxNode, node_factory: NodeFactory) -> None:
    sender = funded_node
    receiver = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(sender, receiver)
    await sync_blocks([sender, receiver])

    addr = await receiver.rpc.getnewaddress()
    assert await receiver.rpc.getbalance() == 0

    await sender.rpc.sendtoaddress(addr, 1000)
    await sender.mine(1)
    await sync_blocks([sender, receiver])

    assert await receiver.rpc.getbalance() == Decimal(1000)
