"""The daemon accepts a block built and equihash-solved by the mininode."""

from conftest import POW_ARGS, NodeFactory
from fluxtest.blocktools import create_block, create_coinbase


async def test_submit_built_block(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    await node.mine(1)  # leave initial block download
    count = await node.rpc.getblockcount()
    tip = await node.rpc.getbestblockhash()
    tip_time = (await node.rpc.getblock(tip))["time"]
    ntime = tip_time + 1
    await node.set_mocktime_at_least(ntime)

    coinbase = create_coinbase(count + 1)
    block = create_block(int(tip, 16), coinbase, ntime)
    block.solve()

    result = await node.rpc.submitblock(block.serialize().hex())
    assert result is None, f"submitblock rejected the block: {result!r}"
    assert await node.rpc.getblockcount() == count + 1
    assert await node.rpc.getbestblockhash() == block.hash
