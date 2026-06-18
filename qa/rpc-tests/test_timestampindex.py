"""Test the timestamp index: getblockhashes returns blocks within a time range."""

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks

TIMESTAMPINDEX_ARGS = ["-experimentalfeatures", "-insightexplorer", "-txindex"]


async def test_getblockhashes(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=TIMESTAMPINDEX_ARGS)
    reader = await node_factory(1, extra_args=TIMESTAMPINDEX_ARGS)
    await connect_nodes_bi(node, reader)

    hashes = await node.mine(8)
    await sync_blocks([node, reader])
    times = [(await reader.rpc.getblock(h))["time"] for h in hashes]

    # getblockhashes(high, low) returns blocks with low <= time < high.
    assert set(await reader.rpc.getblockhashes(times[7] + 1, times[0])) == set(hashes)
    assert set(await reader.rpc.getblockhashes(times[5] + 1, times[2])) == set(hashes[2:6])
    assert set(await reader.rpc.getblockhashes(times[6] + 1, times[6])) == {hashes[6]}
