"""Test invalidateblock and reorg handling across nodes."""

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks


async def test_invalidateblock_reorg(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0)
    node1 = await node_factory(1)
    node2 = await node_factory(2)

    # Node 0 mines 4 blocks; node 1 mines a competing chain of 6.
    await node0.mine(4)
    assert await node0.rpc.getblockcount() == 4
    besthash = await node0.rpc.getbestblockhash()

    await node1.mine(6)
    assert await node1.rpc.getblockcount() == 6

    # Connecting forces node 0 onto node 1's longer chain.
    await connect_nodes_bi(node0, node1)
    await sync_blocks([node0, node1])
    assert await node0.rpc.getblockcount() == 6
    badhash = await node1.rpc.getblockhash(2)

    # Invalidating block 2 on node 0 repopulates setBlockIndexCandidates and
    # reorgs it back to its original 4-block chain.
    await node0.rpc.invalidateblock(badhash)
    assert await node0.rpc.getblockcount() == 4
    assert await node0.rpc.getbestblockhash() == besthash

    # We must not reorg to a lower-work chain.
    await connect_nodes_bi(node1, node2)
    await sync_blocks([node1, node2])
    assert await node2.rpc.getblockcount() == 6

    await node1.rpc.invalidateblock(await node1.rpc.getblockhash(5))
    assert await node1.rpc.getblockcount() == 4

    await node2.rpc.invalidateblock(await node2.rpc.getblockhash(3))
    assert await node2.rpc.getblockcount() == 2

    await node2.mine(1)
    assert await node2.rpc.getblockcount() == 3
    assert await node0.rpc.getblockcount() == 4
    assert await node1.rpc.getblockcount() >= 4
