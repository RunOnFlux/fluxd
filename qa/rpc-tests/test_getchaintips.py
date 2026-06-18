"""Exercise getchaintips across a fork.

A node that reorgs onto a longer competing chain keeps its abandoned chain as
a valid fork, so getchaintips reports two tips.
"""

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks


async def test_getchaintips_fork(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0)
    node1 = await node_factory(1)

    tips = await node0.rpc.getchaintips()
    assert len(tips) == 1
    assert tips[0]["status"] == "active"

    # Two divergent chains of different lengths.
    await node0.mine(10)
    await node1.mine(20)

    # node0 reorgs onto node1's longer chain; its old chain becomes a valid fork.
    await connect_nodes_bi(node0, node1)
    await sync_blocks([node0, node1])

    tips = await node0.rpc.getchaintips()
    assert len(tips) == 2
    by_status = {tip["status"]: tip for tip in tips}
    assert by_status["active"]["height"] == 20
    fork = by_status["valid-fork"]
    assert fork["height"] == 10
    assert fork["branchlen"] == 10
