"""Flux refuses a chain reorg deeper than MAX_REORG_LENGTH (40) blocks.

A competing chain whose adoption would roll back fewer than 40 of a node's own
blocks is accepted in the usual longest-chain way. A competing chain that would
roll back 40 or more blocks is refused at the block-header acceptance check
(``bad-fork-prior-to-maxreorgdepth`` in ContextualCheckBlockHeader): the too-deep
fork's blocks are never added to the block index, so the node stays on its own
shorter chain and keeps running.

This is Flux's behaviour, which differs from upstream zcash. Upstream stopped
the daemon process on a beyond-limit reorg; Flux instead rejects the fork's
headers and continues serving on its own chain. The intent of the legacy test --
within-limit reorg accepted, beyond-limit reorg refused -- is preserved against
the real Flux behaviour.
"""

import asyncio

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode

# Flux's MAX_REORG_LENGTH (src/main.h). A reorg that would roll back this many
# or more of a node's blocks is refused; rolling back fewer is allowed.
MAX_REORG_LENGTH = 40

# A shared base well clear of genesis so both nodes have a long common history
# to fork from.
BASE_HEIGHT = 105


async def _wait_peer_gone(node: FluxNode, p2p_port: int, timeout: float = 30) -> None:
    target = f":{p2p_port}"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while any(target in peer.get("addr", "") for peer in await node.rpc.getpeerinfo()):
        if loop.time() > deadline:
            raise AssertionError(f"node {node.index} still connected to :{p2p_port}")
        await asyncio.sleep(0.1)


async def _wait_for_log(node: FluxNode, needle: str, timeout: float = 30) -> None:
    """Wait until ``needle`` appears in the node's debug.log."""
    log_path = node.datadir / "regtest" / "debug.log"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            if needle in log_path.read_text():
                return
        except OSError:
            pass
        if loop.time() > deadline:
            raise AssertionError(f"{needle!r} not in node {node.index} debug.log within {timeout}s")
        await asyncio.sleep(0.2)


async def _split(node0: FluxNode, node2: FluxNode) -> None:
    """Disconnect node0 and node2 from each other and wait for the split."""
    await node0.rpc.disconnectnode(f"127.0.0.1:{node2.p2p_port}")
    await node2.rpc.disconnectnode(f"127.0.0.1:{node0.p2p_port}")
    await _wait_peer_gone(node0, node2.p2p_port)
    await _wait_peer_gone(node2, node0.p2p_port)


async def _shared_base(node_factory: NodeFactory) -> tuple[FluxNode, FluxNode]:
    """Two connected PoW nodes that share a common chain, then split apart."""
    node0 = await node_factory(0, extra_args=POW_ARGS)
    node2 = await node_factory(2, extra_args=POW_ARGS)
    await connect_nodes_bi(node0, node2)
    await node0.mine(BASE_HEIGHT)
    await sync_blocks([node0, node2])
    assert await node0.rpc.getblockcount() == BASE_HEIGHT
    assert await node2.rpc.getblockcount() == BASE_HEIGHT
    await _split(node0, node2)
    return node0, node2


async def test_within_limit_reorg_is_adopted(node_factory: NodeFactory) -> None:
    """A reorg rolling back fewer than MAX_REORG_LENGTH blocks is adopted."""
    node0, node2 = await _shared_base(node_factory)

    # Both fork from BASE_HEIGHT. node0 builds a chain node2 will out-mine by one
    # block; the rollback node0 must accept is well under the 40-block limit.
    rollback = MAX_REORG_LENGTH - 1
    await node0.mine(rollback)
    await node2.mine(rollback + 1)
    assert await node0.rpc.getblockcount() == BASE_HEIGHT + rollback
    assert await node2.rpc.getblockcount() == BASE_HEIGHT + rollback + 1

    # Reconnect: node0 rolls back its `rollback` blocks and adopts node2's chain.
    await connect_nodes_bi(node0, node2)
    await sync_blocks([node0, node2])
    assert await node0.rpc.getblockcount() == BASE_HEIGHT + rollback + 1
    assert await node0.rpc.getbestblockhash() == await node2.rpc.getbestblockhash()

    # node0's abandoned chain is retained as a valid fork off the shared base.
    by_status = {tip["status"]: tip for tip in await node0.rpc.getchaintips()}
    assert by_status["active"]["height"] == BASE_HEIGHT + rollback + 1
    assert by_status["valid-fork"]["branchlen"] == rollback


async def test_beyond_limit_reorg_is_refused(node_factory: NodeFactory) -> None:
    """A reorg rolling back MAX_REORG_LENGTH or more blocks is refused.

    The node rejects the too-deep fork's headers and stays on its own shorter
    chain; it does not adopt the longer competing chain and keeps running.
    """
    node0, node2 = await _shared_base(node_factory)

    # node0 builds MAX_REORG_LENGTH blocks past the shared base, so adopting any
    # fork off that base would roll back exactly the limit -- which is refused.
    rollback = MAX_REORG_LENGTH
    await node0.mine(rollback)
    await node2.mine(rollback + 1)
    node0_tip = await node0.rpc.getbestblockhash()
    node2_tip = await node2.rpc.getbestblockhash()
    assert await node0.rpc.getblockcount() == BASE_HEIGHT + rollback
    assert await node2.rpc.getblockcount() == BASE_HEIGHT + rollback + 1

    # Reconnect and wait for positive evidence that node0 actually received and
    # refused node2's competing headers -- the maxreorgdepth rejection in node0's
    # debug.log -- rather than a blind sleep that could pass if the headers never
    # arrived. node0 must NOT follow node2's longer chain: the fork would roll
    # back the limit, so its blocks are refused at the header check.
    await connect_nodes_bi(node0, node2)
    await _wait_for_log(node0, "max reorganization depth")

    # node0 stays on its own chain at its own height -- still running, RPC alive.
    assert await node0.rpc.getblockcount() == BASE_HEIGHT + rollback
    assert await node0.rpc.getbestblockhash() == node0_tip

    # The refused fork's blocks were never added to node0's index, so the longer
    # competing tip does not appear among node0's known chain tips.
    known_tips = {tip["hash"] for tip in await node0.rpc.getchaintips()}
    assert node2_tip not in known_tips

    # node2, having never seen a deeper reorg, stays on its own longer chain.
    assert await node2.rpc.getbestblockhash() == node2_tip
