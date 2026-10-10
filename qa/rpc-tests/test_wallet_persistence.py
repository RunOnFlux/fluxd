"""Wallet shielded state survives daemon restarts.

A Sapling address created before the ACADIA (Sapling) activation persists across
a restart; shielded balances and the on-chain shielded value pools survive
restarts; and -- the original regression -- an imported spending key's spend
nullifiers and note witnesses persist, so a spent note is not later double
counted and the recovered notes remain spendable.
"""

from decimal import Decimal

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from zhelpers import shielded_args, wait_and_assert_operationid_status

ACADIA_HEIGHT = 10


async def _sync_all(nodes: list[FluxNode]) -> None:
    """Bring the non-mining nodes' clocks up to the tip before syncing blocks."""
    tip = await nodes[0].rpc.getbestblockhash()
    tip_time = (await nodes[0].rpc.getblock(tip))["time"]
    for node in nodes[1:]:
        await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def _restart_all(nodes: list[FluxNode]) -> None:
    for node in nodes:
        await node.restart()
    await connect_nodes_bi(nodes[0], nodes[1])
    await connect_nodes_bi(nodes[1], nodes[2])
    await _sync_all(nodes)


def _sapling_pool_value(info: dict) -> Decimal:
    return next(p["chainValue"] for p in info["valuePools"] if p["id"] == "sapling")


async def test_wallet_persists_across_restart(node_factory: NodeFactory) -> None:
    nodes = [await node_factory(i, extra_args=shielded_args(ACADIA_HEIGHT)) for i in range(3)]
    await connect_nodes_bi(nodes[0], nodes[1])
    await connect_nodes_bi(nodes[1], nodes[2])

    # A Sapling address created before ACADIA activates must persist.
    await nodes[0].mine(5)  # below ACADIA_HEIGHT
    await _sync_all(nodes)
    sapling_addr = await nodes[0].rpc.z_getnewaddress("sapling")
    assert sapling_addr in await nodes[0].rpc.z_listaddresses()

    await _restart_all(nodes)
    assert sapling_addr in await nodes[0].rpc.z_listaddresses(), "address lost on restart"

    # Mature the premine and cross ACADIA, then shield 20 from a fresh t-address.
    await nodes[0].mine(101)
    await _sync_all(nodes)
    taddr = await nodes[0].rpc.getnewaddress()
    await nodes[0].rpc.sendtoaddress(taddr, Decimal("20"))
    await nodes[0].mine(1)
    opid = await nodes[0].rpc.z_sendmany(
        taddr, [{"address": sapling_addr, "amount": Decimal("20")}], 1, 0
    )
    await wait_and_assert_operationid_status(nodes[0], opid)
    await nodes[0].mine(1)
    await _sync_all(nodes)

    assert await nodes[0].rpc.z_getbalance(sapling_addr) == Decimal("20")
    assert _sapling_pool_value(await nodes[0].rpc.getblockchaininfo()) == Decimal("20")

    await _restart_all(nodes)
    assert _sapling_pool_value(await nodes[0].rpc.getblockchaininfo()) == Decimal("20"), (
        "shielded pool value lost on restart"
    )

    # Sapling -> Sapling send to node 1, balances persist across a restart.
    dest = await nodes[1].rpc.z_getnewaddress("sapling")
    opid = await nodes[0].rpc.z_sendmany(
        sapling_addr, [{"address": dest, "amount": Decimal("15")}], 1, 0
    )
    await wait_and_assert_operationid_status(nodes[0], opid)
    await nodes[0].mine(1)
    await _sync_all(nodes)
    assert await nodes[0].rpc.z_getbalance(sapling_addr) == Decimal("5")
    assert await nodes[1].rpc.z_getbalance(dest) == Decimal("15")

    await _restart_all(nodes)
    assert await nodes[0].rpc.z_getbalance(sapling_addr) == Decimal("5")
    assert await nodes[1].rpc.z_getbalance(dest) == Decimal("15")

    # Importing the spending key recovers the balance; after a restart the spend
    # nullifiers must persist so the spent note is not counted as unspent.
    sk = await nodes[0].rpc.z_exportkey(sapling_addr)
    await nodes[2].rpc.z_importkey(sk, "yes")
    assert await nodes[2].rpc.z_getbalance(sapling_addr) == Decimal("5")

    await _restart_all(nodes)
    assert await nodes[2].rpc.z_getbalance(sapling_addr) == Decimal("5"), "nullifiers not persisted"

    # Witnesses persisted -> node 2 can still spend the recovered notes. The
    # spend originates on node 2 but node 0 mines, so the transaction must reach
    # node 0's mempool before it mines or the block excludes it.
    opid = await nodes[2].rpc.z_sendmany(
        sapling_addr, [{"address": dest, "amount": Decimal("1")}], 1, 0
    )
    await wait_and_assert_operationid_status(nodes[2], opid)
    await sync_mempools(nodes)
    await nodes[0].mine(1)
    await _sync_all(nodes)
    assert await nodes[2].rpc.z_getbalance(sapling_addr) == Decimal("4")
    assert await nodes[1].rpc.z_getbalance(dest) == Decimal("16")
