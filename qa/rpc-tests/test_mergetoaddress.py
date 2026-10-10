"""z_mergetoaddress consolidates UTXOs and notes into one address.

Reframed for Flux and split into focused cases. The miner holds the premine and
funds the owner with ordinary (non-coinbase) UTXOs; the owner never matures any
coinbase of its own, so the ANY_TADDR wildcard sees only those funds. ACADIA
gates every shielded send and is active here, which makes the upstream
-mempooltxinputlimit bound (honored only before Overwinter) and the pre-Sapling
transaction-size UTXO split unreachable, so the UTXO limit is exercised through
the explicit limit parameter and those two cases are dropped. The out-of-range
fee probe uses a value above Flux's 440M MAX_MONEY. z_mergetoaddress is
experimental, so it is enabled with -experimentalfeatures -zmergetoaddress.
"""

from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status

DEFAULT_FEE = Decimal("0.0001")
MERGE_DEFAULT_LIMIT = 50
ARGS = ["-experimentalfeatures", "-zmergetoaddress", "-debug=zrpcunsafe"]
ANY = {"sprout": "ANY_SPROUT", "sapling": "ANY_SAPLING"}


async def _sync_to(nodes: list[FluxNode], tip_node: FluxNode) -> None:
    tip = await tip_node.rpc.getbestblockhash()
    tip_time = (await tip_node.rpc.getblock(tip))["time"]
    for node in nodes:
        if node is not tip_node:
            await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def _utxo_count(node: FluxNode, addr: str) -> int:
    return sum(1 for u in await node.rpc.listunspent(1) if u["address"] == addr)


async def _fund(miner: FluxNode, owner: FluxNode, addr: str, count: int, amount: Decimal) -> None:
    """Give ``owner`` ``count`` separate UTXOs of ``amount`` at ``addr``."""
    for _ in range(count):
        await miner.rpc.sendtoaddress(addr, amount)
    await miner.mine(1)
    await _sync_to([miner, owner], miner)


async def _setup(node_factory: NodeFactory, watcher: bool = False) -> tuple[FluxNode, ...]:
    """A funded miner and an owner that never matures its own coinbase."""
    miner = await node_factory(0, extra_args=shielded_args(1, ARGS))
    owner = await node_factory(1, extra_args=shielded_args(1, ARGS))
    nodes = [miner, owner]
    await connect_nodes_bi(miner, owner)
    if watcher:
        w = await node_factory(2, extra_args=shielded_args(1, ARGS))
        await connect_nodes_bi(miner, w)
        await connect_nodes_bi(owner, w)
        nodes.append(w)
    await miner.mine(COINBASE_MATURITY + 1)  # mature the premine for funding
    await _sync_to(nodes, miner)
    return tuple(nodes)


async def _mine_owner(miner: FluxNode, owner: FluxNode) -> None:
    """Confirm the owner's transactions by mining on the owner.

    The owner mines its own sends so they are in the mining node's mempool; its
    coinbase stays immature (far fewer than COINBASE_MATURITY blocks), so it is
    never selectable by a later merge.
    """
    await owner.mine(1)
    await _sync_to([miner, owner], owner)


@pytest.mark.parametrize("addr_type", ["sprout", "sapling"])
async def test_mergetoaddress_errors(node_factory: NodeFactory, addr_type: str) -> None:
    miner, owner, watcher = await _setup(node_factory, watcher=True)
    zaddr = await owner.rpc.z_getnewaddress(addr_type)
    any_z = ANY[addr_type]

    # Fund the owner with a handful of UTXOs (well under the 999 fee probed below)
    # and shield one into a note so both source kinds exist.
    taddr = await owner.rpc.getnewaddress()
    await _fund(miner, owner, taddr, 4, Decimal("10"))
    opid = await owner.rpc.z_sendmany(taddr, [{"address": zaddr, "amount": Decimal("10")}], 1, 0)
    await wait_and_assert_operationid_status(owner, opid)
    await _mine_owner(miner, owner)

    src = [any_z, "ANY_TADDR"]
    with pytest.raises(JSONRPCError) as e:  # sources must be an array
        await owner.rpc.z_mergetoaddress("notanarray", zaddr)
    assert "JSON value is not an array as expected" in e.value.error["message"]

    await watcher.rpc.importaddress(taddr)  # watch-only: no spending key
    with pytest.raises(JSONRPCError) as e:
        await watcher.rpc.z_mergetoaddress([taddr], zaddr)
    assert "Could not find any funds to merge" in e.value.error["message"]

    for bad_fee in (Decimal("-1"), Decimal("450000000")):  # negative, then above MAX_MONEY
        with pytest.raises(JSONRPCError) as e:
            await owner.rpc.z_mergetoaddress(src, zaddr, bad_fee)
        assert "Amount out of range" in e.value.error["message"]

    with pytest.raises(JSONRPCError) as e:  # fee exceeds the funds being merged
        await owner.rpc.z_mergetoaddress(src, zaddr, Decimal("999"))
    assert "less than miners fee 999.00" in e.value.error["message"]

    with pytest.raises(JSONRPCError) as e:
        await owner.rpc.z_mergetoaddress(src, zaddr, Decimal("0.001"), -1)
    assert "Limit on maximum number of UTXOs cannot be negative" in e.value.error["message"]
    with pytest.raises(JSONRPCError) as e:
        await owner.rpc.z_mergetoaddress(src, zaddr, Decimal("0.001"), 99999999999999)
    assert "JSON integer out of range" in e.value.error["message"]
    with pytest.raises(JSONRPCError) as e:
        await owner.rpc.z_mergetoaddress(src, zaddr, Decimal("0.001"), 50, -1)
    assert "Limit on maximum number of notes cannot be negative" in e.value.error["message"]
    with pytest.raises(JSONRPCError) as e:
        await owner.rpc.z_mergetoaddress(src, zaddr, Decimal("0.001"), 50, 99999999999999)
    assert "JSON integer out of range" in e.value.error["message"]

    # A single UTXO whose only source is also the destination has nothing to do.
    solo = await owner.rpc.getnewaddress()
    await _fund(miner, owner, solo, 1, Decimal("1"))
    with pytest.raises(JSONRPCError) as e:
        await owner.rpc.z_mergetoaddress([solo], solo)
    assert "Destination address is also the only source address" in e.value.error["message"]

    with pytest.raises(JSONRPCError) as e:  # the two note pools cannot be mixed
        await owner.rpc.z_mergetoaddress(["ANY_SPROUT", "ANY_SAPLING"], taddr)
    assert "Cannot send from both Sprout and Sapling addresses" in e.value.error["message"]


@pytest.mark.parametrize("addr_type", ["sprout", "sapling"])
async def test_mergetoaddress_merge(node_factory: NodeFactory, addr_type: str) -> None:
    miner, owner = await _setup(node_factory)
    any_z = ANY[addr_type]

    # Three separate UTXOs merge into one note.
    addrs = [await owner.rpc.getnewaddress() for _ in range(3)]
    for addr in addrs:
        await _fund(miner, owner, addr, 1, Decimal("10"))
    zaddr = await owner.rpc.z_getnewaddress(addr_type)
    result = await owner.rpc.z_mergetoaddress(addrs, zaddr)
    assert result["mergingUTXOs"] == 3
    assert result["mergingNotes"] == 0
    await wait_and_assert_operationid_status(owner, result["opid"])
    await _mine_owner(miner, owner)
    assert Decimal(await owner.rpc.z_getbalance(zaddr)) == Decimal("30") - DEFAULT_FEE

    # A second note, then both notes merge into one.
    taddr = await owner.rpc.getnewaddress()
    await _fund(miner, owner, taddr, 1, Decimal("10"))
    opid = await owner.rpc.z_sendmany(taddr, [{"address": zaddr, "amount": Decimal("5")}], 1, 0)
    await wait_and_assert_operationid_status(owner, opid)
    await _mine_owner(miner, owner)

    merged_z = await owner.rpc.z_getnewaddress(addr_type)
    result = await owner.rpc.z_mergetoaddress([any_z], merged_z, 0)
    assert result["mergingUTXOs"] == 0
    assert result["mergingNotes"] == 2
    assert result["remainingNotes"] == 0
    await wait_and_assert_operationid_status(owner, result["opid"])
    await _mine_owner(miner, owner)
    assert Decimal(await owner.rpc.z_getbalance(zaddr)) == 0
    assert Decimal(await owner.rpc.z_getbalance(merged_z)) == Decimal("34.9999")

    # All transparent funds (the new UTXOs plus any change left above) merge
    # into one taddr.
    dest_t = await owner.rpc.getnewaddress()
    await _fund(miner, owner, await owner.rpc.getnewaddress(), 2, Decimal("4"))
    utxos = await owner.rpc.listunspent(1)
    total = sum((u["amount"] for u in utxos), Decimal(0))
    result = await owner.rpc.z_mergetoaddress(["ANY_TADDR"], dest_t, 0)
    assert result["mergingUTXOs"] == len(utxos)
    assert result["mergingNotes"] == 0
    await wait_and_assert_operationid_status(owner, result["opid"])
    await _mine_owner(miner, owner)
    assert await owner.rpc.getreceivedbyaddress(dest_t) == total


@pytest.mark.parametrize("addr_type", ["sprout", "sapling"])
async def test_mergetoaddress_limits(node_factory: NodeFactory, addr_type: str) -> None:
    miner, owner = await _setup(node_factory)
    zaddr = await owner.rpc.z_getnewaddress(addr_type)
    taddr = await owner.rpc.getnewaddress()
    await _fund(miner, owner, taddr, 90, Decimal("1"))

    # The default limit merges at most 50 UTXOs.
    n = await _utxo_count(owner, taddr)
    assert n > MERGE_DEFAULT_LIMIT
    result = await owner.rpc.z_mergetoaddress([taddr], zaddr, DEFAULT_FEE)
    assert result["mergingUTXOs"] == MERGE_DEFAULT_LIMIT
    assert result["remainingUTXOs"] == n - MERGE_DEFAULT_LIMIT
    await wait_and_assert_operationid_status(owner, result["opid"])
    await _mine_owner(miner, owner)

    # An explicit limit overrides the default.
    n = await _utxo_count(owner, taddr)
    result = await owner.rpc.z_mergetoaddress([taddr], zaddr, DEFAULT_FEE, 33)
    assert result["mergingUTXOs"] == 33
    assert result["remainingUTXOs"] == n - 33
    await wait_and_assert_operationid_status(owner, result["opid"])
    await _mine_owner(miner, owner)

    # A second operation cannot reselect the first's locked UTXOs.
    n = await _utxo_count(owner, taddr)
    assert n > 2
    op1 = await owner.rpc.z_mergetoaddress([taddr], zaddr, Decimal("0"), 2)
    assert op1["mergingUTXOs"] == 2
    op2 = await owner.rpc.z_mergetoaddress([taddr], zaddr, Decimal("0"), 0)
    assert op2["mergingUTXOs"] == n - 2
    assert op2["remainingUTXOs"] == 0
    await wait_and_assert_operationid_status(owner, op1["opid"])
    await wait_and_assert_operationid_status(owner, op2["opid"])
    await _mine_owner(miner, owner)

    # The note limit and locking behave the same for the shielded side. Build a
    # few notes, then queue two merges that each take two and lock them.
    any_z = ANY[addr_type]
    fund_t = await owner.rpc.getnewaddress()
    await _fund(miner, owner, fund_t, 5, Decimal("2"))
    notes_z = await owner.rpc.z_getnewaddress(addr_type)
    for _ in range(5):
        opid = await owner.rpc.z_sendmany(
            fund_t, [{"address": notes_z, "amount": Decimal("1")}], 1, 0
        )
        await wait_and_assert_operationid_status(owner, opid)
        await _mine_owner(miner, owner)

    num_notes = len(await owner.rpc.z_listunspent(0))
    assert num_notes >= 4
    res1 = await owner.rpc.z_mergetoaddress([any_z], notes_z, Decimal("0.0001"), 50, 2)
    res2 = await owner.rpc.z_mergetoaddress([any_z], notes_z, Decimal("0.0001"), 50, 2)
    assert res1["mergingNotes"] == 2
    assert res1["remainingNotes"] == num_notes - 2
    assert res2["mergingNotes"] == 2
    assert res2["remainingNotes"] == num_notes - 4
    await wait_and_assert_operationid_status(owner, res1["opid"])
    await wait_and_assert_operationid_status(owner, res2["opid"])


async def test_mergetoaddress_mixednotes(node_factory: NodeFactory) -> None:
    miner, owner = await _setup(node_factory)
    t_addr = await miner.rpc.getnewaddress()
    sprout_z = await owner.rpc.z_getnewaddress("sprout")
    sapling_z = await owner.rpc.z_getnewaddress("sapling")

    # Fund a sprout and a sapling note from ordinary transparent funds.
    fund_t = await owner.rpc.getnewaddress()
    await _fund(miner, owner, fund_t, 2, Decimal("10"))
    for target in (sprout_z, sapling_z):
        opid = await owner.rpc.z_sendmany(
            fund_t, [{"address": target, "amount": Decimal("10")}], 1, 0
        )
        await wait_and_assert_operationid_status(owner, opid)
        await _mine_owner(miner, owner)
    assert Decimal(await owner.rpc.z_getbalance(sprout_z)) == Decimal("10")
    assert Decimal(await owner.rpc.z_getbalance(sapling_z)) == Decimal("10")

    # The two note pools can never be merged in one operation.
    with pytest.raises(JSONRPCError) as e:
        await owner.rpc.z_mergetoaddress(["ANY_SPROUT", "ANY_SAPLING"], t_addr)
    assert "Cannot send from both Sprout and Sapling addresses" in e.value.error["message"]

    # Each pool merges to the transparent address on its own.
    result = await owner.rpc.z_mergetoaddress(["ANY_SPROUT"], t_addr, 0)
    await wait_and_assert_operationid_status(owner, result["opid"])
    await _mine_owner(miner, owner)
    assert Decimal(await owner.rpc.z_getbalance(sprout_z)) == 0
    assert await miner.rpc.getreceivedbyaddress(t_addr) == Decimal("10")

    result = await owner.rpc.z_mergetoaddress(["ANY_SAPLING"], t_addr, 0)
    await wait_and_assert_operationid_status(owner, result["opid"])
    await _mine_owner(miner, owner)
    assert Decimal(await owner.rpc.z_getbalance(sapling_z)) == 0
    assert await miner.rpc.getreceivedbyaddress(t_addr) == Decimal("20")
