"""A shielded transaction surviving a reorg across an anchor fork.

The same joinsplit is mined into two competing chains formed by partitioning the
network, then the partitions rejoin and the shorter side reorgs onto the longer
one. This guards the historical crash where rebuilding the commitment-tree state
after such a reorg tripped a tree-root assertion, so the nodes are restarted at
each stage to force that state to be reloaded from disk.

Reframed for Flux: -regtestprotectcoinbase forbids change on a coinbase shield,
so each joinsplit shields a whole 150 coinbase; ACADIA is active so the sprout
sends are valid; and the partition is formed by restarting the nodes (which
drops every peer) and reconnecting only one side.
"""

from decimal import Decimal

from conftest import COINBASE_MATURITY, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from zhelpers import shielded_args, wait_and_assert_operationid_status

PROTECT = ["-regtestprotectcoinbase", "-debug=zrpc"]


async def _coinbases(node: FluxNode, count: int) -> list[dict]:
    """The ``count`` smallest spendable coinbase UTXOs (ordinary 150s)."""
    gens = sorted(
        (u for u in await node.rpc.listunspent(1) if u["generated"] and u["spendable"]),
        key=lambda u: u["amount"],
    )
    assert len(gens) >= count, f"need {count} coinbase utxos, have {len(gens)}"
    return gens[:count]


async def _bump_clocks(nodes: list[FluxNode]) -> None:
    """Pull every node's clock up to the latest tip across the set.

    After an independent (partitioned) advance the chains' tips differ, so a node
    must have a clock at least as late as a peer's tip before it will accept that
    peer's longer chain.
    """
    latest = 0
    for node in nodes:
        tip_time = (await node.rpc.getblock(await node.rpc.getbestblockhash()))["time"]
        latest = max(latest, tip_time)
    for node in nodes:
        await node.set_mocktime_at_least(latest)


async def _connect_all(nodes: list[FluxNode]) -> None:
    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            await connect_nodes_bi(nodes[i], nodes[j])


async def test_wallet_anchorfork(node_factory: NodeFactory) -> None:
    args = shielded_args(1, PROTECT)
    nodes = [await node_factory(i, extra_args=args) for i in range(3)]
    n0, n1, n2 = nodes
    await _connect_all(nodes)

    # node0 makes a few coinbases; node1 buries everything past maturity.
    await n0.mine(5)
    await _bump_clocks(nodes)
    await sync_blocks(nodes)
    await n1.mine(COINBASE_MATURITY + 5)
    await _bump_clocks(nodes)
    await sync_blocks(nodes)
    cb1, cb2 = await _coinbases(n0, 2)

    zaddr = await n0.rpc.z_getnewaddress("sprout")
    # Pre-partition joinsplit, mined and synced: every node ends on one anchor.
    opid = await n0.rpc.z_sendmany(
        cb1["address"], [{"address": zaddr, "amount": cb1["amount"] - Decimal("0.0001")}]
    )
    await wait_and_assert_operationid_status(n0, opid)
    await n0.mine(1)
    await _bump_clocks(nodes)
    await sync_blocks(nodes)

    # Partition: restart all (dropping peers), then connect only node1<->node2.
    for node in nodes:
        await node.restart()
    await connect_nodes_bi(n1, n2)

    # Partition B advances by one empty block.
    await n1.mine(1)

    # Partition A: node0 builds the joinsplit against the shared pre-partition
    # anchor (before mining its own block), then mines it.
    opid = await n0.rpc.z_sendmany(
        cb2["address"], [{"address": zaddr, "amount": cb2["amount"] - Decimal("0.0001")}]
    )
    txid = await wait_and_assert_operationid_status(n0, opid)
    rawhex = await n0.rpc.getrawtransaction(txid)
    await n0.mine(1)

    # Partition B mines the very same transaction into its competing chain.
    txid2 = await n1.rpc.sendrawtransaction(rawhex)
    assert txid2 == txid
    await n1.mine(1)

    # B is one block ahead of A, with a different tip.
    assert await n0.rpc.getblockcount() + 1 == await n1.rpc.getblockcount()
    assert await n0.rpc.getbestblockhash() != await n1.rpc.getbestblockhash()

    # Restart so the anchor state is rebuilt from disk, then rejoin the network.
    for node in nodes:
        await node.restart()
    await _connect_all(nodes)

    # A new block propagates; node0 reorgs onto B's longer chain without tripping
    # the commitment-tree assertion, and every node converges on one tip.
    await _bump_clocks(nodes)
    await n1.mine(1)
    await _bump_clocks(nodes)
    await sync_blocks(nodes)
    assert await n0.rpc.getbestblockhash() == await n1.rpc.getbestblockhash()
    assert await n1.rpc.getbestblockhash() == await n2.rpc.getbestblockhash()
