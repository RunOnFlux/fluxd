"""Block-index rewind on restart when a node's consensus rules change.

Each block index entry caches the consensus branch id it was validated under.
On startup ``RewindBlockIndex`` (src/main.cpp) walks the active chain and, at the
first block whose cached branch id (or upgrade-activation flag) no longer matches
what the *current* consensus rules expect, rewinds the chain back to the last
still-valid block and erases the now-mismatched entries from the index.

The driving consensus change here is the LWMA network upgrade. On regtest every
upgrade is off by default, so ``-nuparams=76b809bb:10`` activates LWMA at height
10: blocks at height 10 and above are then validated under branch id 0x76b809bb,
and block 10 carries the upgrade-activation flag. Restarting the same node
*without* that flag makes those same blocks expect the pre-upgrade Sprout branch
id (0) instead, so the node rewinds to height 9 (the last pre-activation block)
and re-syncs the rest of the chain from a peer under its now-current rules.

This mirrors the legacy three-node fork (Overwinter -> Sprout -> Overwinter) with
the topology that Flux regtest actually supports: blocks do not reject each other
across this boundary at the header level, so the rewound chain is re-supplied by
a peer that stayed up, rather than by a persistently-forked competitor.
"""

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode

# Branch id of the LWMA upgrade (src/consensus/upgrades.cpp), the first upgrade
# past Base. -nuparams matches on branch-id hex and activates the earliest
# upgrade carrying it, so this string turns LWMA on at the given height.
LWMA_BRANCH_ID = "76b809bb"

# LWMA activates at this height; height 9 is the last pre-activation block, which
# is where the node rewinds to once LWMA is switched off again.
ACTIVATION_HEIGHT = 10
LAST_PRE_ACTIVATION = ACTIVATION_HEIGHT - 1

# A handful of blocks past activation so the rewind has real length to undo.
TIP_HEIGHT = 15

# LWMA-on and LWMA-off argument sets. PON is pushed past the test on both so
# regtest mines PoW blocks the wallet can drive.
LWMA_ON = [*POW_ARGS, f"-nuparams={LWMA_BRANCH_ID}:{ACTIVATION_HEIGHT}"]
LWMA_OFF = list(POW_ARGS)


async def _adopt_keeper_chain(node: FluxNode, keeper: FluxNode) -> None:
    """Connect ``node`` to ``keeper`` and let it adopt the full chain.

    ``node`` either starts empty or, after a rewind, sits at the pre-activation
    height with the later blocks erased from its index; the keeper holds the
    whole chain, so ``node`` downloads and validates it under its current rules.
    The follower's clock is pulled up to the keeper's tip first so the later
    blocks are not rejected as timed too far ahead -- the LWMA era tightens the
    future-block window from two hours to a few minutes.
    """
    await node.set_mocktime_at_least(
        (await keeper.rpc.getblock(await keeper.rpc.getbestblockhash()))["time"]
    )
    await connect_nodes_bi(node, keeper)
    await sync_blocks([node, keeper])


async def test_rewind_index_round_trip(node_factory: NodeFactory) -> None:
    """A node rewinds and re-syncs across an upgrade toggled off then on again.

    Built with LWMA on, the node is restarted with LWMA off (rewind to the
    pre-activation block, re-adopt the chain under Sprout rules), then restarted
    with LWMA on again (rewind once more, re-adopt under LWMA rules). The keeper
    node holds the chain throughout so each rewound segment can be re-supplied.
    """
    keeper = await node_factory(0, extra_args=LWMA_ON)
    node = await node_factory(1, extra_args=LWMA_ON)

    # Build the chain on the keeper alone, spanning the activation boundary, then
    # let the node adopt it. Mining in isolation keeps the keeper from announcing
    # future-dated blocks before the follower's clock is brought up to match.
    await keeper.mine(TIP_HEIGHT)
    chain_tip = await keeper.rpc.getbestblockhash()
    await _adopt_keeper_chain(node, keeper)
    assert await keeper.rpc.getblockcount() == TIP_HEIGHT
    assert await node.rpc.getblockcount() == TIP_HEIGHT
    assert await node.rpc.getbestblockhash() == chain_tip

    # Switch the node to LWMA-off. Its blocks 10..15 were validated under the
    # LWMA branch id, which no longer matches the now-Sprout-only rules, so the
    # node rewinds to the last pre-activation block.
    await node.restart(extra_args=LWMA_OFF)
    assert await node.rpc.getblockcount() == LAST_PRE_ACTIVATION

    # The keeper still has the full chain; the node re-adopts it under Sprout
    # rules and returns to the shared tip.
    await _adopt_keeper_chain(node, keeper)
    assert await node.rpc.getblockcount() == TIP_HEIGHT
    assert await node.rpc.getbestblockhash() == chain_tip

    # Switch back to LWMA-on. The blocks the node just re-validated carry the
    # Sprout branch id, which now mismatches the re-enabled LWMA rules at
    # height 10, so it rewinds to the pre-activation block again.
    await node.restart(extra_args=LWMA_ON)
    assert await node.rpc.getblockcount() == LAST_PRE_ACTIVATION

    # And re-adopts the keeper's chain once more, now under LWMA rules.
    await _adopt_keeper_chain(node, keeper)
    assert await node.rpc.getblockcount() == TIP_HEIGHT
    assert await node.rpc.getbestblockhash() == chain_tip
