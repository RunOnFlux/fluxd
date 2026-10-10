"""Exercise the getblocktemplate API structure."""

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks


async def test_getblocktemplate(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    # getblocktemplate refuses on an unconnected node, so give it a peer.
    peer = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(node, peer)
    await node.mine(1)  # leave initial block download
    await sync_blocks([node, peer])

    tmpl = await node.rpc.getblocktemplate()
    assert "coinbasetxn" in tmpl
    assert "coinbasevalue" not in tmpl
    assert len(tmpl["noncerange"]) == 16
    assert tmpl["coinbasetxn"]["required"] is True
    assert "finalsaplingroothash" in tmpl
