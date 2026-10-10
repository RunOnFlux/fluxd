"""Smoke test for the asyncio mininode: handshake, ping/pong, peer visibility."""

from conftest import POW_ARGS, NodeFactory
from fluxtest.mininode import NodeConn, NodeConnCB


async def test_mininode_handshake(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    cb = NodeConnCB()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb)
    await conn.connect()
    await cb.wait_for_verack()
    assert cb.verack_received

    await cb.sync_with_ping()
    peers = await node.rpc.getpeerinfo()
    assert len(peers) == 1
    # The node sanitizes the reported subversion with SAFE_CHARS_DEFAULT, which
    # on Flux omits "-" (it allows alphanumerics and " .,;_/:?@()"), so the
    # hyphens are dropped from /python-mininode-tester:0.0.1/.
    assert peers[0]["subver"] == "/pythonmininodetester:0.0.1/"

    await conn.disconnect_node()
