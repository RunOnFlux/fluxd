"""Transaction expiry (nExpiryHeight) behaviour in the mempool.

Flux collapses zcash's Overwinter/Sapling staging into the single ACADIA
upgrade: before it the wallet builds legacy v1 transactions with no expiry;
from activation it builds v4 Sapling transactions that expire -txexpirydelta
blocks after creation. A transaction sitting in (or returned to) the mempool
survives chain advances and reorgs up to and including its expiry height, is
evicted together with its dependents once the chain passes that height --
releasing the wallet funds it spent -- and a transaction within
TX_EXPIRING_SOON_THRESHOLD blocks of expiry is refused mempool entry with
tx-expiring-soon.

The competing chains are mined on a second node while the network is
partitioned; the partition is formed by restarting both nodes (which drops
every peer) and not reconnecting them until the scenario calls for the reorg.
"""

from decimal import Decimal

import pytest
from conftest import NodeFactory
from fluxtest.network import bump_clocks, connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status, z_total

ACADIA_HEIGHT = 110
EXPIRY_DELTA = 10
# main.h TX_EXPIRING_SOON_THRESHOLD: entry to the mempool is refused once the
# next block's height plus this margin exceeds the transaction's expiry.
EXPIRING_SOON_THRESHOLD = 3

ARGS = shielded_args(ACADIA_HEIGHT, [f"-txexpirydelta={EXPIRY_DELTA}", "-debug=mempool"])


async def _partition(nodes: list[FluxNode]) -> None:
    """Isolate the nodes from each other by restarting them (drops all peers)."""
    for node in nodes:
        await node.restart()


async def _rejoin(nodes: list[FluxNode]) -> None:
    """Reconnect the partition and wait for every node to adopt one best chain."""
    await connect_nodes_bi(nodes[0], nodes[1])
    await bump_clocks(nodes)
    await sync_blocks(nodes)


async def _send_expiring_pair(
    n0: FluxNode, z_alice: str, z_bob: str, bob: str
) -> tuple[str, str, int]:
    """A shielded and a transparent wallet send from node 0, plus their expiry.

    Both are built for the next block, so they expire at tip + 1 + the delta.
    """
    tip = await n0.rpc.getblockcount()
    opid = await n0.rpc.z_sendmany(
        z_alice, [{"address": z_bob, "amount": Decimal("0.9999")}]
    )
    shielded = await wait_and_assert_operationid_status(n0, opid)
    assert shielded is not None
    transparent = await n0.rpc.sendtoaddress(bob, Decimal("0.01"))
    expiry = tip + 1 + EXPIRY_DELTA
    for txid in (shielded, transparent):
        raw = await n0.rpc.getrawtransaction(txid, 1)
        assert raw["version"] == 4
        assert raw["overwintered"] is True
        assert raw["expiryheight"] == expiry
    return shielded, transparent, expiry


async def test_mempool_tx_expiry(node_factory: NodeFactory) -> None:
    n0 = await node_factory(0, extra_args=ARGS)
    n1 = await node_factory(1, extra_args=ARGS)
    nodes = [n0, n1]
    await connect_nodes_bi(n0, n1)

    bob = await n1.rpc.getnewaddress()

    # Mature the premine so node 0 can spend, staying below ACADIA activation.
    await n0.mine(105)
    await bump_clocks(nodes)
    await sync_blocks(nodes)

    # Before ACADIA the wallet builds legacy transactions with no expiry.
    txid = await n0.rpc.sendtoaddress(bob, Decimal("0.01"))
    raw = await n0.rpc.getrawtransaction(txid, 1)
    assert raw["version"] == 1
    assert raw["overwintered"] is False
    assert "expiryheight" not in raw

    # Cross the activation boundary (the legacy send is mined along the way).
    await n0.mine(ACADIA_HEIGHT - await n0.rpc.getblockcount())
    await bump_clocks(nodes)
    await sync_blocks(nodes)

    # Fund z_alice with a known private balance. A coinbase input forbids
    # change in z_sendmany, so fund an ordinary output first and shield all of
    # it (10 = 9.9999 + the default 0.0001 fee).
    z_alice = await n0.rpc.z_getnewaddress("sapling")
    z_bob = await n1.rpc.z_getnewaddress("sapling")
    taddr = await n0.rpc.getnewaddress()
    await n0.rpc.sendtoaddress(taddr, Decimal("10"))
    await n0.mine(1)
    opid = await n0.rpc.z_sendmany(taddr, [{"address": z_alice, "amount": Decimal("9.9999")}])
    await wait_and_assert_operationid_status(n0, opid)
    await n0.mine(1)
    await bump_clocks(nodes)
    await sync_blocks(nodes)
    assert (await z_total(n0))["private"] == Decimal("9.9999")

    # --- A reorg past the expiry height evicts a mined transaction AND its
    # mined dependent when they are returned to the mempool.
    await _partition(nodes)
    alice = await n0.rpc.getnewaddress()
    tip = await n0.rpc.getblockcount()
    first = await n0.rpc.sendtoaddress(alice, Decimal("0.1"))
    info = await n0.rpc.getrawtransaction(first, 1)
    assert info["version"] == 4
    assert info["overwintered"] is True
    assert info["versiongroupid"] == "892f2085"
    assert info["expiryheight"] == tip + 1 + EXPIRY_DELTA
    await n0.mine(1)
    # Second transaction spends the first one's 0.1 output (fee-less, like the
    # original test: inputs == outputs).
    vout = next(o for o in info["vout"] if o["value"] == Decimal("0.1"))
    rawtx = await n0.rpc.createrawtransaction(
        [{"txid": first, "vout": vout["n"]}], {alice: Decimal("0.1")}
    )
    signed = await n0.rpc.signrawtransaction(rawtx)
    assert signed["complete"] is True
    second = await n0.rpc.sendrawtransaction(signed["hex"])
    assert second in await n0.rpc.getrawmempool()
    await n0.mine(1)
    # The competing chain overtakes node 0 and ends past both expiry heights.
    await n1.mine(2 + EXPIRY_DELTA)
    await _rejoin(nodes)
    assert await n0.rpc.getrawmempool() == []
    assert await n1.rpc.getrawmempool() == []
    # Sanity: node 0 really reorged onto the competing chain.
    assert await n0.rpc.getblockcount() == tip + 2 + EXPIRY_DELTA
    assert await n0.rpc.getbestblockhash() == await n1.rpc.getbestblockhash()

    # --- A reorg that stays below the expiry height returns the transactions
    # to the mempool and keeps them there.
    await _partition(nodes)
    persist_sh, persist_tr, _ = await _send_expiring_pair(n0, z_alice, z_bob, bob)
    await n0.mine(1)
    assert await n0.rpc.getrawmempool() == []
    await n1.mine(2)
    await _rejoin(nodes)
    mempool = await n0.rpc.getrawmempool()
    assert persist_tr in mempool
    assert persist_sh in mempool
    # Mine them for real to clear the mempool for the next scenario.
    await n0.mine(1)
    await bump_clocks(nodes)
    await sync_blocks(nodes)
    assert await n0.rpc.getrawmempool() == []

    # --- Unmined transactions persist while the chain advances up to exactly
    # their expiry height, and are evicted one block past it, releasing the
    # note they spent back to the wallet.
    await _partition(nodes)
    expire_sh, expire_tr, expiry = await _send_expiring_pair(n0, z_alice, z_bob, bob)
    await n1.mine(EXPIRY_DELTA + 1)
    await _rejoin(nodes)
    assert await n0.rpc.getblockcount() == expiry
    mempool = await n0.rpc.getrawmempool()
    assert expire_tr in mempool
    assert expire_sh in mempool
    await n1.mine(1)
    await bump_clocks(nodes)
    await sync_blocks(nodes)
    assert await n0.rpc.getrawmempool() == []
    # One 1.0 send was mined (scenario above); the expired one is released.
    assert (await z_total(n0))["private"] == Decimal("8.9999")

    # --- A transaction close to expiry is refused entry to a fresh mempool
    # with tx-expiring-soon; entry is allowed right up to that margin.
    await _partition(nodes)
    soon_sh, soon_tr, expiry = await _send_expiring_pair(n0, z_alice, z_bob, bob)
    await n1.mine(1 + EXPIRY_DELTA - EXPIRING_SOON_THRESHOLD - 1)
    await _rejoin(nodes)
    mempool = await n0.rpc.getrawmempool()
    assert soon_tr in mempool
    assert soon_sh in mempool
    # Mempool transactions are not re-announced after a reconnect, so node 1
    # never saw them.
    n1_mempool = await n1.rpc.getrawmempool()
    assert soon_tr not in n1_mempool
    assert soon_sh not in n1_mempool
    # At this height the next block plus the margin lands exactly on the expiry
    # height, which is still allowed.
    await n1.rpc.sendrawtransaction(await n0.rpc.getrawtransaction(soon_tr))
    # One block later the margin crosses the expiry height and entry is refused.
    await n1.mine(1)
    raw_sh = await n0.rpc.getrawtransaction(soon_sh)
    with pytest.raises(JSONRPCError, match="tx-expiring-soon"):
        await n1.rpc.sendrawtransaction(raw_sh)
