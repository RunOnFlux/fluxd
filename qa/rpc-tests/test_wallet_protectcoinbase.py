"""Shielding coinbase funds under -regtestprotectcoinbase.

With coinbase protection enabled a coinbase UTXO can only be spent by shielding
it to a zaddr, and the wallet refuses any change on such a shield (there is no
way to name a change address in z_sendmany). This drives that path end to end:
the failing transparent spend, the watch-only / missing-spending-key errors, the
no-change rule and its operation-result params, viewing-key import, value-pool
accounting, chained joinsplits, and the insufficient-shielded-funds / fee-range
guards.

Flux diverges from upstream Zcash here. The block-1 premine is a spendable
transparent balance, so the wallet is never at zero transparent funds and the
upstream "balance == 0" / transparent-scarcity assertions do not translate -- the
shielded side is asserted instead, which is deterministic. The transparent
coinbase spend is rejected at consensus (a generic commit failure) because the
FLUX network upgrade, which retires the wallet's pre-check, never activates on
regtest, so the wallet selects the premine and the tx dies in CheckInputs.
Coinbase is 150/block, so every amount is computed from the live UTXO value.
"""

import asyncio
from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import (
    shielded_args,
    wait_and_assert_operationid_status,
    wait_and_assert_operationid_status_result,
)

COIN = 100000000
DEFAULT_FEE = Decimal("0.0001")
PROTECT_ARGS = ["-regtestprotectcoinbase", "-debug=zrpcunsafe"]


async def _smallest_coinbase(node: FluxNode) -> tuple[str, Decimal]:
    """A (address, value) for the smallest spendable coinbase UTXO.

    The smallest generated output is an ordinary 150 coinbase, never the much
    larger block-1 premine; picking it keeps the shield amounts deterministic.
    Each coinbase pays a fresh address holding exactly one UTXO.
    """
    gens = sorted(
        (u for u in await node.rpc.listunspent() if u["generated"] and u["spendable"]),
        key=lambda u: u["amount"],
    )
    assert gens, "node has no spendable coinbase outputs"
    return gens[0]["address"], gens[0]["amount"]


async def _wait_zunspent(
    node: FluxNode,
    count: int,
    minconf: int = 0,
    watchonly: bool = False,
    timeout: float = 30,
) -> list[dict]:
    """Poll z_listunspent until at least ``count`` notes are visible.

    A note reaches the wallet a moment after the operation reports success
    (ThreadNotifyRecentlyAdded batches mempool notifications once a second; a
    freshly synced block is scanned shortly after arrival)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        notes = await node.rpc.z_listunspent(minconf, 9999, watchonly)
        if len(notes) >= count:
            return notes
        if loop.time() > deadline:
            raise AssertionError(f"expected >= {count} notes, got {len(notes)}")
        await asyncio.sleep(0.25)


async def _sprout_pool(node: FluxNode) -> Decimal:
    for pool in (await node.rpc.getblockchaininfo())["valuePools"]:
        if pool["id"] == "sprout":
            assert pool["monitored"] is True
            assert pool["chainValueZat"] == pool["chainValue"] * COIN
            return Decimal(pool["chainValue"])
    raise AssertionError("no sprout value pool")


async def test_wallet_protectcoinbase(node_factory: NodeFactory) -> None:
    owner = await node_factory(0, extra_args=shielded_args(1, PROTECT_ARGS))
    watcher = await node_factory(1, extra_args=shielded_args(1, PROTECT_ARGS))
    await connect_nodes_bi(owner, watcher)

    await owner.mine(COINBASE_MATURITY + 10)
    await watcher.set_mocktime_at_least(
        (await owner.rpc.getblock(await owner.rpc.getbestblockhash()))["time"]
    )
    await sync_blocks([owner, watcher])
    assert await _sprout_pool(owner) == 0

    cb_addr, cb_value = await _smallest_coinbase(owner)
    zaddr = await owner.rpc.z_getnewaddress("sprout")
    assert (await owner.rpc.z_validateaddress(zaddr))["type"] == "sprout"

    # Spending a coinbase to a transparent output is rejected. Flux retires the
    # wallet's friendly pre-check at the FLUX upgrade (never active on regtest),
    # so the wallet selects the premine and the tx is rejected at consensus.
    with pytest.raises(JSONRPCError) as excinfo:
        await owner.rpc.sendtoaddress(await watcher.rpc.getnewaddress(), Decimal("1"))
    assert "rejected" in excinfo.value.error["message"]

    # A watch-only sender has no spending key, so no UTXOs are selectable.
    await watcher.rpc.importaddress(cb_addr)
    opid = await watcher.rpc.z_sendmany(cb_addr, [{"address": zaddr, "amount": Decimal("1")}])
    await wait_and_assert_operationid_status(
        watcher, opid, "failed", "Insufficient funds, no UTXOs found for taddr from address."
    )

    # Import the viewing key before the note exists so the watcher detects it
    # without a rescan (z_importviewingkey "no" only scans future blocks).
    await watcher.rpc.z_importviewingkey(await owner.rpc.z_exportviewingkey(zaddr), "no")

    # Shielding a coinbase with change left over is refused: the wallet cannot
    # name a change address. Change == value - fee - amount.
    change_amount = Decimal("1.23456789")
    expected_change = cb_value - DEFAULT_FEE - change_amount
    opid = await owner.rpc.z_sendmany(cb_addr, [{"address": zaddr, "amount": change_amount}])
    result = await wait_and_assert_operationid_status_result(
        owner,
        opid,
        "failed",
        f"Change {expected_change:.8f} not allowed. When shielding coinbase funds, the "
        "wallet does not allow any change as there is currently no way to specify a "
        "change address in z_sendmany.",
    )
    assert result["method"] == "z_sendmany"
    params = result["params"]
    assert params["fee"] == DEFAULT_FEE
    assert params["minconf"] == Decimal(1)
    assert params["fromaddress"] == cb_addr
    assert params["amounts"][0]["address"] == zaddr
    assert params["amounts"][0]["amount"] == change_amount

    # Shielding the whole UTXO (no change) succeeds.
    shield_value = cb_value - DEFAULT_FEE
    opid = await owner.rpc.z_sendmany(cb_addr, [{"address": zaddr, "amount": shield_value}])
    txid = await wait_and_assert_operationid_status(owner, opid)
    assert txid is not None

    # Unconfirmed: hidden at minconf 1, one note at minconf 0.
    assert await owner.rpc.z_listunspent() == []
    note = (await _wait_zunspent(owner, 1))[0]
    assert note["address"] == zaddr
    assert note["amount"] == shield_value
    assert note["confirmations"] == 0

    await owner.mine(1)
    await watcher.set_mocktime_at_least(
        (await owner.rpc.getblock(await owner.rpc.getbestblockhash()))["time"]
    )
    await sync_blocks([owner, watcher])

    note = (await owner.rpc.z_listunspent())[0]
    assert note["amount"] == shield_value
    assert note["confirmations"] == 1
    assert note["spendable"] is True

    # The watcher sees the same note via its viewing key, but cannot spend it.
    watched = await _wait_zunspent(watcher, 1, minconf=1, watchonly=True)
    assert watched[0]["address"] == zaddr
    assert watched[0]["amount"] == shield_value
    assert watched[0]["spendable"] is False
    with pytest.raises(JSONRPCError) as excinfo:
        await watcher.rpc.z_listunspent(1, 999, False, [zaddr])
    assert "spending key for address does not belong to wallet" in excinfo.value.error["message"]

    # -debug=zrpcunsafe logs the operation's params and final txid, in order.
    log = (owner.datadir / "regtest" / "debug.log").read_text().splitlines()
    seen = 0
    for line in log:
        if f"{opid}: z_sendmany initialized" in line and cb_addr in line and zaddr in line:
            assert seen == 0
            seen = 1
        if f"{opid}: z_sendmany finished" in line and txid in line:
            assert seen == 1
            seen = 2
    assert seen == 2

    # Value-pool and balance accounting reflect the shielded amount.
    assert await _sprout_pool(owner) == shield_value
    total = await owner.rpc.z_gettotalbalance()
    assert Decimal(total["private"]) == shield_value

    # A custom fee of 0 sending the note back to itself leaves balances unchanged.
    opid = await owner.rpc.z_sendmany(
        zaddr, [{"address": zaddr, "amount": shield_value}], 1, Decimal("0.0")
    )
    await wait_and_assert_operationid_status(owner, opid)
    await owner.mine(1)
    assert await _sprout_pool(owner) == shield_value
    assert Decimal((await owner.rpc.z_gettotalbalance())["private"]) == shield_value

    # Chained joinsplits: one tx fanning the note out to three zaddrs. Its
    # priority (spending a shielded note) is well above zero.
    recipients = []
    for _ in range(3):
        addr = await watcher.rpc.z_getnewaddress("sprout")
        recipients.append({"address": addr, "amount": Decimal("0.002")})
    send_amount = Decimal("0.006")
    custom_fee = Decimal("0.00012345")
    z_before = Decimal(await owner.rpc.z_getbalance(zaddr))
    opid = await owner.rpc.z_sendmany(zaddr, recipients, 1, custom_fee)
    txid = await wait_and_assert_operationid_status(owner, opid)
    mempool = await owner.rpc.getrawmempool(True)
    assert Decimal(mempool[txid]["startingpriority"]) >= Decimal("1000000000000")
    await owner.mine(1)
    await watcher.set_mocktime_at_least(
        (await owner.rpc.getblock(await owner.rpc.getbestblockhash()))["time"]
    )
    await sync_blocks([owner, watcher])

    assert Decimal((await watcher.rpc.z_gettotalbalance())["private"]) == send_amount
    assert Decimal(await owner.rpc.z_getbalance(zaddr)) == z_before - custom_fee - send_amount

    # Insufficient shielded funds reports the shortfall.
    have = Decimal(await owner.rpc.z_getbalance(zaddr))
    opid = await owner.rpc.z_sendmany(
        zaddr, [{"address": await owner.rpc.getnewaddress(), "amount": Decimal("10000.0")}]
    )
    await wait_and_assert_operationid_status(
        owner, opid, "failed", f"Insufficient shielded funds, have {have}, need 10000.0001"
    )

    # Fee out of range / larger than the outputs is rejected synchronously. The
    # over-MAX_MONEY value is a whole number of FLUX: a sub-satoshi excess at
    # this magnitude is lost in the JSON float encoding and would land back in
    # range (MAX_MONEY is 440000000).
    one = [{"address": await owner.rpc.getnewaddress(), "amount": Decimal("0.001")}]
    for bad_fee in (Decimal("-1"), Decimal("450000000")):  # > MAX_MONEY
        with pytest.raises(JSONRPCError) as excinfo:
            await owner.rpc.z_sendmany(zaddr, one, 1, bad_fee)
        assert "Amount out of range" in excinfo.value.error["message"]
    with pytest.raises(JSONRPCError) as excinfo:
        await owner.rpc.z_sendmany(zaddr, one, 1, Decimal("0.002"))
    assert "is greater than the sum of outputs" in excinfo.value.error["message"]


@pytest.mark.slow
async def test_wallet_protectcoinbase_many_recipients(node_factory: NodeFactory) -> None:
    """A single shielded send to 2500 transparent recipients clears the mempool.

    Confirms a joinsplit tx with many small outputs is accepted: a regression
    where the default fee was judged too low for the tx size (zcash #1851).
    """
    owner = await node_factory(0, extra_args=shielded_args(1, PROTECT_ARGS))
    receiver = await node_factory(1, extra_args=shielded_args(1, PROTECT_ARGS))
    await connect_nodes_bi(owner, receiver)
    await owner.mine(COINBASE_MATURITY + 5)
    await receiver.set_mocktime_at_least(
        (await owner.rpc.getblock(await owner.rpc.getbestblockhash()))["time"]
    )
    await sync_blocks([owner, receiver])

    cb_addr, cb_value = await _smallest_coinbase(owner)
    zaddr = await owner.rpc.z_getnewaddress("sprout")
    opid = await owner.rpc.z_sendmany(
        cb_addr, [{"address": zaddr, "amount": cb_value - DEFAULT_FEE}]
    )
    await wait_and_assert_operationid_status(owner, opid)
    await owner.mine(1)

    amount = Decimal("0.00000546")  # dust threshold
    recipients = []
    for _ in range(2500):
        recipients.append({"address": await receiver.rpc.getnewaddress(), "amount": amount})
    opid = await owner.rpc.z_sendmany(zaddr, recipients)
    await wait_and_assert_operationid_status(owner, opid, timeout=600)
    await owner.mine(1)
    await receiver.set_mocktime_at_least(
        (await owner.rpc.getblock(await owner.rpc.getbestblockhash()))["time"]
    )
    await sync_blocks([owner, receiver])
    assert await receiver.rpc.getbalance() == amount * 2500
