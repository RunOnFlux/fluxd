"""Test that invalidateblock repopulates setBlockIndexCandidates and reorgs.

Covers the named purpose of the original invalidateblock test: after a node
reorgs onto a competing chain, invalidating a block on that chain reorgs it
back to its original chain (the candidate set is repopulated correctly).
"""

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks

# Distinct mocktime bases so the two chains genuinely diverge; regtest mining
# is deterministic and would otherwise produce identical chains.
MOCKTIME = 1600000000


async def test_invalidateblock_reorg(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0)
    node1 = await node_factory(1)

    # Node 0 mines 4 blocks; node 1 mines a competing chain of 6.
    await node0.mine(4, mocktime=MOCKTIME)
    assert await node0.rpc.getblockcount() == 4
    besthash = await node0.rpc.getbestblockhash()

    await node1.mine(6, mocktime=MOCKTIME + 150)
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
