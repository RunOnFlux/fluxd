"""Test that -reindex rebuilds the chain (with CheckBlockIndex)."""

from conftest import NodeFactory


async def test_reindex(node_factory: NodeFactory) -> None:
    node = await node_factory(0)
    await node.mine(3)
    assert await node.rpc.getblockcount() == 3

    await node.restart(extra_args=["-reindex", "-checkblockindex=1"])
    assert await node.rpc.getblockcount() == 3
