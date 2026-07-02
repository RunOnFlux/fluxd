"""Mempool behaviour across the ACADIA network-upgrade activation boundary.

Flux has a single upgrade boundary on regtest -- ACADIA activates Sapling and
Overwintered (v4) transactions in one step -- where zcash staged Sprout ->
Overwinter -> Sapling. At the boundary the mempool must drop every transaction
validated under the old branch (removeWithoutBranchId): legacy transactions
that did not fit into the last pre-upgrade block cannot be mined under the new
rules. Transactions created for the first post-upgrade block enter the mempool
under the new branch and survive.

Unlike zcash, no shielded transaction can be created before the boundary at
all: z_sendmany refuses ANY shielded input or output (Sprout included) until
ACADIA is active for the next block, so the shielded mempool entrant here is a
first-possible-moment shield built at the last pre-upgrade tip.

Invalidating the last pre-upgrade block empties the mempool entirely: the
post-upgrade transactions are evicted by the branch check, and the disconnected
block's legacy transactions fail re-acceptance because they are re-validated
for the following (post-upgrade) height -- the same inherited height-off-by-one
zcash documents in the original test.

The `upgrades` map of getblockchaininfo is not asserted on: it is keyed by
branch-id hex, and ACADIA shares 0x76b809bb with PON, so the JSON object
carries duplicate keys and a Python client sees only the last entry. The
consensus.chaintip / consensus.nextblock branch ids are asserted instead.
"""

from decimal import Decimal

import pytest
from conftest import NodeFactory
from fluxtest.network import bump_clocks, connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status

ACADIA_HEIGHT = 210
SPROUT_BRANCH_ID = "00000000"
ACADIA_BRANCH_ID = "76b809bb"
BLOCK_MAX_SIZE = 4000

ARGS = shielded_args(
    ACADIA_HEIGHT, ["-checkmempool", "-debug=mempool", f"-blockmaxsize={BLOCK_MAX_SIZE}"]
)


async def _branch_ids(node: FluxNode) -> tuple[str, str]:
    consensus = (await node.rpc.getblockchaininfo())["consensus"]
    return consensus["chaintip"], consensus["nextblock"]


async def test_mempool_nu_activation(node_factory: NodeFactory) -> None:
    n0 = await node_factory(0, extra_args=ARGS)
    n1 = await node_factory(1, extra_args=ARGS)
    nodes = [n0, n1]
    await connect_nodes_bi(n0, n1)

    # Mature the premine, then give node 1 independent UTXOs to flood from
    # (one sendmany, so the flood transactions never chain on unconfirmed
    # change). The 10-coin output funds the boundary shield.
    await n0.mine(101)
    flood_funding = {}
    for _ in range(60):
        flood_funding[await n1.rpc.getnewaddress()] = Decimal("1")
    await n0.rpc.sendmany("", flood_funding)
    zaddr = await n0.rpc.z_getnewaddress("sprout")
    taddr = await n0.rpc.getnewaddress()
    await n0.rpc.sendtoaddress(taddr, Decimal("10"))
    await n0.mine(1)
    await bump_clocks(nodes)
    await sync_blocks(nodes)

    # Park two blocks below activation: the mempool expects one more
    # pre-ACADIA block.
    await n0.mine(ACADIA_HEIGHT - 2 - await n0.rpc.getblockcount())
    await bump_clocks(nodes)
    await sync_blocks(nodes)
    assert await n0.rpc.getrawmempool() == []
    assert await _branch_ids(n0) == (SPROUT_BRANCH_ID, SPROUT_BRANCH_ID)

    # Two blocks out, even a Sprout-only shield is still refused.
    with pytest.raises(JSONRPCError, match="Cannot create shielded transactions"):
        await n0.rpc.z_sendmany(taddr, [{"address": zaddr, "amount": Decimal("10")}], 1, 0)

    # Fill the mempool with twice as many legacy transactions as fit in a
    # block.
    n0_taddr = await n0.rpc.getnewaddress()
    x_txids = []
    while (await n1.rpc.getmempoolinfo())["bytes"] < 2 * BLOCK_MAX_SIZE:
        x_txids.append(await n1.rpc.sendtoaddress(n0_taddr, Decimal("0.001")))
    await sync_mempools(nodes)
    assert set(await n0.rpc.getrawmempool()) == set(x_txids)

    # Mine the last pre-ACADIA block: it holds only a subset of the flood, and
    # everything else is dropped -- the mempool now expects an ACADIA block, so
    # every remaining legacy-branch transaction is unmineable.
    await n0.mine(1)
    await bump_clocks(nodes)
    await sync_blocks(nodes)
    assert await n0.rpc.getblockcount() == ACADIA_HEIGHT - 1
    assert await _branch_ids(n0) == (SPROUT_BRANCH_ID, ACADIA_BRANCH_ID)
    assert await n0.rpc.getrawmempool() == []
    assert await n1.rpc.getrawmempool() == []
    last_legacy_hash = await n0.rpc.getbestblockhash()
    block_txids = (await n0.rpc.getblock(last_legacy_hash))["tx"]
    assert 1 < len(block_txids) < len(x_txids)
    assert all(txid in x_txids for txid in block_txids[1:])  # skip the coinbase

    # Transactions created now are built for the first ACADIA block and enter
    # the mempool under the new branch -- including the first possible shield.
    y_txids = [await n1.rpc.sendtoaddress(n0_taddr, Decimal("0.001")) for _ in range(10)]
    opid = await n0.rpc.z_sendmany(taddr, [{"address": zaddr, "amount": Decimal("10")}], 1, 0)
    shielded = await wait_and_assert_operationid_status(n0, opid)
    assert shielded is not None
    y_txids.append(shielded)
    await sync_mempools(nodes)
    assert set(await n0.rpc.getrawmempool()) == set(y_txids)

    # Invalidating the boundary block empties the mempool: the new-branch
    # transactions are evicted, and the block's legacy transactions fail
    # re-acceptance (re-validated for the post-upgrade height).
    await n0.rpc.invalidateblock(last_legacy_hash)
    assert await n0.rpc.getblockcount() == ACADIA_HEIGHT - 2
    assert await n0.rpc.getrawmempool() == []
    await n0.rpc.reconsiderblock(last_legacy_hash)
    assert await n0.rpc.getblockcount() == ACADIA_HEIGHT - 1

    # Node 1 still holds the new-branch transactions and mines them once the
    # upgrade is active; node 0 follows the chain across the boundary and its
    # evicted shield confirms.
    await n1.mine(6)
    await bump_clocks(nodes)
    await sync_blocks(nodes)
    assert await n1.rpc.getrawmempool() == []
    assert await _branch_ids(n0) == (ACADIA_BRANCH_ID, ACADIA_BRANCH_ID)
    assert await n0.rpc.z_getbalance(zaddr) == Decimal("10")
