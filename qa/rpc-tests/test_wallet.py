"""Transparent and shielded wallet bookkeeping, split into focused cases.

The upstream Bitcoin Core wallet omnibus tracks exact balances through a long
chain of sends, assuming a 50-coin coinbase and no premine. Flux mines 150 per
block and block 1 is the 13.02M premine, so the mining node's total balance is
dominated by the premine and the upstream absolute numbers do not translate. The
reframe funds a clean second node and asserts that node's exact balance deltas,
and asserts receipts on the mining node by address rather than its (polluted)
total. Coinbase can be spent to transparent outputs here because coinbase
protection is left off (it requires -regtestprotectcoinbase); the upstream
transaction-size and zaddr-output limits are pre-Sapling guards, so that case
runs on a node with ACADIA inactive.
"""

import asyncio
from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status


async def _smallest_coinbase(node: FluxNode) -> dict:
    """The smallest spendable coinbase UTXO (an ordinary 150, never the premine).

    Each coinbase pays a fresh address holding one UTXO, so the smallest
    generated output is a regular block reward rather than the much larger
    block-1 premine.
    """
    gens = sorted(
        (u for u in await node.rpc.listunspent(1) if u["generated"] and u["spendable"]),
        key=lambda u: u["amount"],
    )
    assert gens, "node has no spendable coinbase outputs"
    return gens[0]


async def _sync_to(nodes: list[FluxNode], tip_node: FluxNode) -> None:
    """Pull every other node's clock up to ``tip_node``'s tip, then sync blocks."""
    tip = await tip_node.rpc.getbestblockhash()
    tip_time = (await tip_node.rpc.getblock(tip))["time"]
    for node in nodes:
        if node is not tip_node:
            await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def test_wallet_transparent_bookkeeping(node_factory: NodeFactory) -> None:
    funder = await node_factory(0, extra_args=shielded_args(1))
    spender = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(funder, spender)

    await funder.mine(COINBASE_MATURITY + 1)  # mature the premine to spend it
    await _sync_to([funder, spender], funder)

    # The spender starts with a clean, known balance: it mines no coinbase and
    # holds no premine, so its balance tracks exactly through the sends below.
    spender_addr = await spender.rpc.getnewaddress()
    await funder.rpc.sendtoaddress(spender_addr, Decimal("50"))
    await funder.mine(1)
    await _sync_to([funder, spender], funder)
    assert await spender.rpc.getbalance() == Decimal("50")

    # Receipts are tracked by address on the funder, whose total is dominated by
    # the premine. The spender mines its own sends, so the fee returns to the
    # spender as an immature coinbase (excluded from getbalance).
    dest = await funder.rpc.getnewaddress()
    fee = Decimal("0.001")
    await spender.rpc.settxfee(fee)

    # Plain send: the spender debits amount + fee.
    await spender.rpc.sendtoaddress(dest, Decimal("10"))
    await spender.mine(1)
    await _sync_to([funder, spender], spender)
    assert await spender.rpc.getbalance() == Decimal("39.999")
    assert await spender.rpc.getbalance("*") == Decimal("39.999")
    assert await funder.rpc.getreceivedbyaddress(dest) == Decimal("10")

    # Subtract fee from amount: the spender debits exactly the amount, and the
    # recipient receives amount - fee.
    await spender.rpc.sendtoaddress(dest, Decimal("10"), "", "", True)
    await spender.mine(1)
    await _sync_to([funder, spender], spender)
    assert await spender.rpc.getbalance() == Decimal("29.999")
    assert await spender.rpc.getbalance("*") == Decimal("29.999")
    assert await funder.rpc.getreceivedbyaddress(dest) == Decimal("19.999")  # 10 + 9.999

    # sendmany: the spender debits amount + fee.
    await spender.rpc.sendmany("", {dest: Decimal("10")}, 0, "", [])
    await spender.mine(1)
    await _sync_to([funder, spender], spender)
    assert await spender.rpc.getbalance() == Decimal("19.998")
    assert await spender.rpc.getbalance("*") == Decimal("19.998")
    assert await funder.rpc.getreceivedbyaddress(dest) == Decimal("29.999")

    # sendmany with subtract-fee: the spender debits exactly the amount.
    await spender.rpc.sendmany("", {dest: Decimal("10")}, 0, "", [dest])
    await spender.mine(1)
    await _sync_to([funder, spender], spender)
    assert await spender.rpc.getbalance() == Decimal("9.998")
    assert await spender.rpc.getbalance("*") == Decimal("9.998")
    assert await funder.rpc.getreceivedbyaddress(dest) == Decimal("39.998")  # 29.999 + 9.999


async def test_wallet_listunspent_generated(node_factory: NodeFactory) -> None:
    miner = await node_factory(0, extra_args=shielded_args(1))
    receiver = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(miner, receiver)
    await miner.mine(COINBASE_MATURITY + 5)
    await _sync_to([miner, receiver], miner)

    # Mined outputs report generated=true.
    coinbase = [u for u in await miner.rpc.listunspent(1) if u["generated"]]
    assert coinbase, "miner should hold matured coinbase outputs"
    assert all(u["generated"] is True for u in coinbase)

    # Two ordinary sends give the receiver two non-coinbase outputs.
    for _ in range(2):
        await miner.rpc.sendtoaddress(await receiver.rpc.getnewaddress(), Decimal("1"))
    await miner.mine(1)
    await _sync_to([miner, receiver], miner)
    recv_utxos = await receiver.rpc.listunspent(1)
    assert len(recv_utxos) == 2
    assert all(u["generated"] is False for u in recv_utxos)


async def test_wallet_absurd_fee_guard(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=shielded_args(1))
    await node.mine(COINBASE_MATURITY + 5)

    # Spend a whole 150 coinbase to a single 1.0 output: the ~149 left over
    # becomes the fee, far above the relay threshold, so the raw send is rejected.
    utxo = await _smallest_coinbase(node)
    raw = await node.rpc.createrawtransaction(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        {await node.rpc.getnewaddress(): Decimal("1.0")},
    )
    signed = await node.rpc.signrawtransaction(raw)
    assert signed["complete"] is True
    with pytest.raises(JSONRPCError) as excinfo:
        await node.rpc.sendrawtransaction(signed["hex"])
    assert "absurdly high fees" in excinfo.value.error["message"]


async def test_wallet_resend_transactions(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0, extra_args=shielded_args(1))
    node1 = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(node0, node1)
    await node0.mine(COINBASE_MATURITY + 1)
    await _sync_to([node0, node1], node0)

    # Fund node1 so it, too, can originate a transaction.
    await node0.rpc.sendtoaddress(await node1.rpc.getnewaddress(), Decimal("10"))
    await node0.mine(1)
    await _sync_to([node0, node1], node0)

    txid1 = await node0.rpc.sendtoaddress(await node1.rpc.getnewaddress(), Decimal("1"))
    txid2 = await node1.rpc.sendtoaddress(await node0.rpc.getnewaddress(), Decimal("1"))
    await sync_mempools([node0, node1])

    # A fresh node joins after the transactions were created and only syncs
    # blocks, so it does not learn the still-unconfirmed transactions until
    # node0 rebroadcasts its wallet transactions.
    node3 = await node_factory(3, extra_args=shielded_args(1))
    await connect_nodes_bi(node0, node3)
    await _sync_to([node0, node1, node3], node0)
    assert txid1 not in await node3.rpc.getrawmempool()

    relayed = await node0.rpc.resendwallettransactions()
    assert set(relayed) == {txid1, txid2}
    await sync_mempools([node0, node3])
    assert txid1 in await node3.rpc.getrawmempool()


async def test_wallet_zero_value_output(node_factory: NodeFactory) -> None:
    builder = await node_factory(0, extra_args=shielded_args(1))
    receiver = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(builder, receiver)
    await builder.mine(COINBASE_MATURITY + 5)
    await _sync_to([builder, receiver], builder)

    # Build a transaction with one ordinary output and one zero-value output
    # directly (regtest does not enforce dust limits), and confirm the recipient
    # lists the zero-value output as a spendable coin.
    utxo = await _smallest_coinbase(builder)
    recv_addr = await receiver.rpc.getnewaddress()
    raw = await builder.rpc.createrawtransaction(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        {
            await builder.rpc.getnewaddress(): utxo["amount"] - Decimal("0.001"),
            recv_addr: Decimal("0"),
        },
    )
    signed = await builder.rpc.signrawtransaction(raw)
    assert signed["complete"] is True
    zero_txid = (await builder.rpc.decoderawtransaction(signed["hex"]))["txid"]
    await builder.rpc.sendrawtransaction(signed["hex"])
    await builder.mine(1)
    await _sync_to([builder, receiver], builder)

    found = [u for u in await receiver.rpc.listunspent(1) if u["txid"] == zero_txid]
    assert len(found) == 1
    assert found[0]["amount"] == Decimal("0")


async def test_wallet_broadcast_disabled(node_factory: NodeFactory) -> None:
    base = shielded_args(1)
    nobroadcast = shielded_args(1, ["-walletbroadcast=0"])
    sender = await node_factory(0, extra_args=base)
    miner = await node_factory(1, extra_args=base)
    receiver = await node_factory(2, extra_args=base)
    nodes = [sender, miner, receiver]

    async def wire() -> None:
        await connect_nodes_bi(sender, miner)
        await connect_nodes_bi(miner, receiver)
        await connect_nodes_bi(sender, receiver)

    await wire()
    await sender.mine(COINBASE_MATURITY + 1)
    await _sync_to(nodes, sender)

    # Give the receiver a known starting balance to track across the scenarios.
    await sender.rpc.sendtoaddress(await receiver.rpc.getnewaddress(), Decimal("10"))
    await sender.mine(1)
    await _sync_to(nodes, sender)
    assert await receiver.rpc.getbalance() == Decimal("10")
    balance = Decimal("10")

    # Restart all three with broadcasting disabled.
    for node in nodes:
        await node.restart(extra_args=nobroadcast)
    await wire()
    await _sync_to(nodes, sender)

    # A transaction created now is not relayed, so the miner never sees it:
    # mining a block does not confirm it and the receiver's balance is unchanged.
    txid = await sender.rpc.sendtoaddress(await receiver.rpc.getnewaddress(), Decimal("2"))
    txhex = (await sender.rpc.gettransaction(txid))["hex"]
    await miner.mine(1)
    await _sync_to(nodes, miner)
    assert await receiver.rpc.getbalance() == balance

    # Broadcasting the same raw transaction by hand from another node confirms it.
    await miner.rpc.sendrawtransaction(txhex)
    await miner.mine(1)
    await _sync_to(nodes, miner)
    balance += Decimal("2")
    assert await receiver.rpc.getbalance() == balance

    # Create another unbroadcast transaction, then restart with broadcasting
    # enabled: the wallet re-accepts its unconfirmed transactions on startup, so
    # the sender's next block confirms it.
    await sender.rpc.sendtoaddress(await receiver.rpc.getnewaddress(), Decimal("2"))
    for node in nodes:
        await node.restart(extra_args=base)
    await wire()
    await _sync_to(nodes, sender)
    await sender.mine(1)
    await _sync_to(nodes, sender)
    balance += Decimal("2")
    assert await receiver.rpc.getbalance() == balance


async def test_wallet_vjoinsplit_and_shield(node_factory: NodeFactory) -> None:
    funder = await node_factory(0, extra_args=shielded_args(1))
    owner = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(funder, owner)
    await funder.mine(COINBASE_MATURITY + 1)
    await _sync_to([funder, owner], funder)

    # A plain transparent send carries no joinsplit.
    mytaddr = await owner.rpc.getnewaddress()
    txid = await funder.rpc.sendtoaddress(mytaddr, Decimal("10"))
    await funder.mine(1)
    await _sync_to([funder, owner], funder)
    assert Decimal(await owner.rpc.z_getbalance(mytaddr)) == Decimal("10")
    assert (await owner.rpc.gettransaction(txid))["vJoinSplit"] == []

    # Shield 7 from the funded (non-coinbase) taddr: a non-coinbase input allows
    # change, so 2.9999 returns transparently and the 7 lands in the zaddr.
    myzaddr = await owner.rpc.z_getnewaddress("sprout")
    note_value = Decimal("7")
    opid = await owner.rpc.z_sendmany(mytaddr, [{"address": myzaddr, "amount": note_value}])
    shield_txid = await wait_and_assert_operationid_status(owner, opid)
    await owner.mine(1)
    await _sync_to([funder, owner], owner)

    assert Decimal(await owner.rpc.z_getbalance(myzaddr)) == note_value
    total = await owner.rpc.z_gettotalbalance()
    assert Decimal(total["private"]) == note_value
    assert Decimal(total["transparent"]) == Decimal("2.9999")

    # The joinsplit takes the public value in (vpub_old) and emits none (vpub_new).
    joinsplit = (await owner.rpc.getrawtransaction(shield_txid, 1))["vJoinSplit"][0]
    assert joinsplit["vpub_old"] == note_value
    assert joinsplit["vpub_new"] == Decimal("0")
    for field in ("onetimePubKey", "randomSeed", "ciphertexts"):
        assert field in joinsplit

    # Spend the note to two transparent recipients; receipts are tracked by
    # address since the funder's total is dominated by the premine.
    funder_recv = await funder.rpc.getnewaddress()
    owner_recv = await owner.rpc.getnewaddress()
    opid = await owner.rpc.z_sendmany(
        myzaddr,
        [
            {"address": funder_recv, "amount": Decimal("1")},
            {"address": owner_recv, "amount": Decimal("1")},
        ],
    )
    await wait_and_assert_operationid_status(owner, opid)
    await owner.mine(1)
    await _sync_to([funder, owner], owner)
    assert await funder.rpc.getreceivedbyaddress(funder_recv) == Decimal("1")
    assert await owner.rpc.getreceivedbyaddress(owner_recv) == Decimal("1")
    assert Decimal(await owner.rpc.z_getbalance(myzaddr)) == note_value - Decimal("2") - Decimal(
        "0.0001"
    )


async def test_wallet_amount_parsing(node_factory: NodeFactory) -> None:
    funder = await node_factory(0, extra_args=shielded_args(1))
    other = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(funder, other)
    await funder.mine(COINBASE_MATURITY + 1)
    await _sync_to([funder, other], funder)

    # String and scientific-notation amounts parse to exact values.
    for amount, expected in (
        ("2", Decimal("-2")),
        ("0.0001", Decimal("-0.0001")),
        ("1e-4", Decimal("-0.0001")),
    ):
        txid = await funder.rpc.sendtoaddress(await other.rpc.getnewaddress(), amount)
        assert (await funder.rpc.gettransaction(txid))["amount"] == expected

    # A malformed amount and a non-integer block count are rejected.
    with pytest.raises(JSONRPCError) as excinfo:
        await funder.rpc.sendtoaddress(await other.rpc.getnewaddress(), "1f-4")
    assert "Invalid amount" in excinfo.value.error["message"]

    with pytest.raises(JSONRPCError) as excinfo:
        await funder.rpc.generate("2")
    assert "not an integer" in excinfo.value.error["message"]


async def test_wallet_zsendmany_fee_edge_cases(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=shielded_args(1))
    await node.mine(2)  # ACADIA active so z_sendmany validates rather than rejecting
    myzaddr = await node.rpc.z_getnewaddress("sprout")

    # amount=0 with the default fee is accepted (an operation id is returned).
    opid = await node.rpc.z_sendmany(myzaddr, [{"address": myzaddr, "amount": Decimal("0")}])
    assert opid

    # amount=0 with a fee above the default is rejected synchronously.
    with pytest.raises(JSONRPCError) as excinfo:
        await node.rpc.z_sendmany(
            myzaddr, [{"address": myzaddr, "amount": Decimal("0")}], 1, Decimal("0.1")
        )
    assert "Small transaction amount" in excinfo.value.error["message"]

    # A fee below the default with a tiny amount is accepted.
    opid = await node.rpc.z_sendmany(
        myzaddr, [{"address": myzaddr, "amount": Decimal("0.00000001")}], 1, Decimal("0.0000001")
    )
    assert opid

    # amount=0, fee=0 is accepted.
    opid = await node.rpc.z_sendmany(
        myzaddr, [{"address": myzaddr, "amount": Decimal("0")}], 1, Decimal("0")
    )
    assert opid


@pytest.mark.slow
async def test_wallet_zsendmany_output_limits(node_factory: NodeFactory) -> None:
    """z_sendmany rejects oversized output sets, before Sapling activates.

    The transaction-size limit (100000 bytes pre-Sapling, the full block size
    after) and the zaddr-output cap are only reachable while Sapling is inactive,
    so this runs on a node with ACADIA left off; Flux requires ACADIA for any
    active shielded send.
    """
    node = await node_factory(0, extra_args=[*POW_ARGS, "-acadiaactivation=1000000"])
    await node.mine(COINBASE_MATURITY + 1)
    cb_addr = (await _smallest_coinbase(node))["address"]

    # The daemon's RPC work queue is shallow, so the thousands of addresses below
    # are created with bounded concurrency; firing them all at once overflows it.
    gate = asyncio.Semaphore(8)

    async def _new_taddr() -> str:
        async with gate:
            return await node.rpc.getnewaddress()

    async def _new_zaddr() -> str:
        async with gate:
            return await node.rpc.z_getnewaddress("sprout")

    async def taddrs(count: int) -> list[str]:
        return await asyncio.gather(*(_new_taddr() for _ in range(count)))

    async def zaddrs(count: int) -> list[str]:
        return await asyncio.gather(*(_new_zaddr() for _ in range(count)))

    dust = Decimal("0.00000001")

    # Too many transparent outputs exceed the pre-Sapling size limit.
    recipients = [{"address": a, "amount": dust} for a in await taddrs(3000)]
    with pytest.raises(JSONRPCError) as excinfo:
        await node.rpc.z_sendmany(cb_addr, recipients)
    assert "size of raw transaction would be larger than limit" in excinfo.value.error["message"]

    # A mix of transparent and shielded outputs also exceeds it.
    recipients = [{"address": a, "amount": dust} for a in await taddrs(2000)]
    recipients += [{"address": a, "amount": dust} for a in await zaddrs(50)]
    with pytest.raises(JSONRPCError) as excinfo:
        await node.rpc.z_sendmany(cb_addr, recipients)
    assert "size of raw transaction would be larger than limit" in excinfo.value.error["message"]

    # More shielded outputs than the cap are rejected outright.
    recipients = [{"address": a, "amount": dust} for a in await zaddrs(100)]
    with pytest.raises(JSONRPCError) as excinfo:
        await node.rpc.z_sendmany(cb_addr, recipients)
    assert "too many zaddr outputs" in excinfo.value.error["message"]
