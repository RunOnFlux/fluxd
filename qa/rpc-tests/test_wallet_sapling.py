"""Wallet behaviour with Sapling addresses.

Before ACADIA (Flux's Sapling gate) activates, every shielded value transfer is
rejected. Once active: a Sapling address can be created, funded by shielding
coinbase, and spent Sapling->Sapling (with change) and Sapling->transparent
(unshielding); the raw transaction exposes the Sapling spend/output fields;
importing a spending key recovers the balance; and a single z_sendmany cannot
target both a Sprout and a Sapling recipient.

Flux jumps Sprout -> Sapling directly with no Overwinter epoch, so the upstream
test's staged activation collapses to a single -acadiaactivation gate.
"""

from decimal import Decimal
from typing import Any

import pytest
from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status

ACADIA_HEIGHT = 105
# z_sendmany and z_shieldcoinbase reject shielded transfers before ACADIA with
# their own distinct messages.
SENDMANY_NOT_ACTIVE = (
    "Invalid parameter, Acadia(Sapling) has not activated. "
    f"Will be activated on block {ACADIA_HEIGHT}."
)
SHIELD_NOT_ACTIVE = "Cannot create shielded transactions before Acadia (Sapling) has activated"
MIXED_POOLS = "Cannot send to both Sprout and Sapling addresses using z_sendmany"
MAX_PRIORITY = Decimal("1E+16")


async def _sync_all(nodes: list[FluxNode]) -> None:
    tip = await nodes[0].rpc.getbestblockhash()
    tip_time = (await nodes[0].rpc.getblock(tip))["time"]
    for node in nodes[1:]:
        await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def _mine(nodes: list[FluxNode]) -> None:
    """Confirm pending transactions: propagate every node's mempool to the
    miner (node 0) first, or a transaction sent on another node is excluded."""
    await sync_mempools(nodes)
    await nodes[0].mine(1)
    await _sync_all(nodes)


async def _spendable_coinbase(node: FluxNode, amount: Decimal) -> str:
    """A coinbase address with a single spendable UTXO of at least ``amount``.

    listunspent also surfaces the unspendable foundation P2SH coinbase outputs,
    so filter on ``spendable`` -- a plain ``generated`` filter can hand back an
    address z_sendmany then rejects as having no usable UTXOs.
    """
    utxos = [
        u
        for u in await node.rpc.listunspent(1)
        if u["generated"] and u["spendable"] and u["amount"] >= amount
    ]
    assert utxos, f"no spendable coinbase UTXO of at least {amount}"
    return utxos[0]["address"]


async def _send(node: FluxNode, frm: str, recipients: list[dict[str, Any]]) -> str:
    """z_sendmany (fee 0), wait for the op, assert MAX_PRIORITY, return the txid."""
    opid = await node.rpc.z_sendmany(frm, recipients, 1, 0)
    txid = await wait_and_assert_operationid_status(node, opid)
    assert txid is not None
    mempool = await node.rpc.getrawmempool(True)
    assert mempool[txid]["startingpriority"] == MAX_PRIORITY
    return txid


async def test_wallet_sapling(node_factory: NodeFactory) -> None:
    nodes = [await node_factory(i, extra_args=shielded_args(ACADIA_HEIGHT)) for i in range(3)]
    await connect_nodes_bi(nodes[0], nodes[1])
    await connect_nodes_bi(nodes[1], nodes[2])

    # Before ACADIA, shielded value transfer is rejected (no funds needed -- the
    # gate is checked before input selection).
    pre_taddr = await nodes[0].rpc.getnewaddress()
    pre_zaddr = await nodes[0].rpc.z_getnewaddress("sapling")
    for frm, to in ((pre_taddr, pre_zaddr), (pre_zaddr, pre_taddr)):
        with pytest.raises(JSONRPCError) as exc:
            await nodes[0].rpc.z_sendmany(frm, [{"address": to, "amount": Decimal("10")}], 1, 0)
        assert exc.value.error["message"] == SENDMANY_NOT_ACTIVE
    with pytest.raises(JSONRPCError) as exc:
        await nodes[0].rpc.z_shieldcoinbase(pre_taddr, pre_zaddr)
    assert exc.value.error["message"] == SHIELD_NOT_ACTIVE

    # Cross ACADIA and mature coinbase.
    await nodes[0].mine(110)
    await _sync_all(nodes)

    taddr1 = await nodes[1].rpc.getnewaddress()
    sapling0 = await nodes[0].rpc.z_getnewaddress("sapling")
    sapling1 = await nodes[1].rpc.z_getnewaddress("sapling")
    assert sapling0 in await nodes[0].rpc.z_listaddresses()
    assert sapling1 in await nodes[1].rpc.z_listaddresses()
    assert (await nodes[0].rpc.z_validateaddress(sapling0))["type"] == "sapling"
    assert await nodes[0].rpc.z_getbalance(sapling0) == Decimal("0")
    assert await nodes[1].rpc.z_getbalance(sapling1) == Decimal("0")

    # Shield two coinbase UTXOs into sapling0 -> 20.
    for _ in range(2):
        coinbase = await _spendable_coinbase(nodes[0], Decimal("10"))
        await _send(nodes[0], coinbase, [{"address": sapling0, "amount": Decimal("10")}])
        await _mine(nodes)
    assert await nodes[0].rpc.z_getbalance(sapling0) == Decimal("20")
    assert await nodes[1].rpc.z_getbalance(sapling1) == Decimal("0")

    # Sapling -> Sapling (15) with 5 change back to sapling0.
    await _send(nodes[0], sapling0, [{"address": sapling1, "amount": Decimal("15")}])
    await _mine(nodes)
    assert await nodes[0].rpc.z_getbalance(sapling0) == Decimal("5")
    assert await nodes[1].rpc.z_getbalance(sapling1) == Decimal("15")

    # Node 1: Sapling -> Sapling (5) + unshield to taddr (5), 5 change back.
    txid = await _send(
        nodes[1],
        sapling1,
        [
            {"address": sapling0, "amount": Decimal("5")},
            {"address": taddr1, "amount": Decimal("5")},
        ],
    )
    await _mine(nodes)
    assert await nodes[0].rpc.z_getbalance(sapling0) == Decimal("10")
    assert await nodes[1].rpc.z_getbalance(sapling1) == Decimal("5")
    assert await nodes[1].rpc.z_getbalance(taddr1) == Decimal("5")

    # The unshielding transaction carries the Sapling spend/output fields.
    resp = await nodes[0].rpc.getrawtransaction(txid, 1)
    assert resp["valueBalance"] == Decimal("5")
    assert len(resp["vShieldedSpend"]) == 1
    assert len(resp["vShieldedOutput"]) == 2
    assert "bindingSig" in resp
    spend = resp["vShieldedSpend"][0]
    assert all(k in spend for k in ("cv", "anchor", "nullifier", "rk", "proof", "spendAuthSig"))
    output = resp["vShieldedOutput"][0]
    output_keys = ("cv", "cmu", "ephemeralKey", "encCiphertext", "outCiphertext", "proof")
    assert all(k in output for k in output_keys)

    # Importing the spending keys recovers the witnesses and nullifiers.
    await nodes[2].rpc.z_importkey(await nodes[0].rpc.z_exportkey(sapling0), "yes")
    assert await nodes[2].rpc.z_getbalance(sapling0) == Decimal("10")
    await nodes[2].rpc.z_importkey(await nodes[1].rpc.z_exportkey(sapling1), "yes")
    assert await nodes[2].rpc.z_getbalance(sapling1) == Decimal("5")

    # A single z_sendmany cannot target both a Sprout and a Sapling recipient.
    sprout_dest = await nodes[2].rpc.z_getnewaddress("sprout")
    sapling_dest = await nodes[2].rpc.z_getnewaddress("sapling")
    with pytest.raises(JSONRPCError) as exc:
        await nodes[1].rpc.z_sendmany(
            taddr1,
            [
                {"address": sprout_dest, "amount": Decimal("2.5")},
                {"address": sapling_dest, "amount": Decimal("2.4999")},
            ],
            1,
            Decimal("0.0001"),
        )
    assert exc.value.error["message"] == MIXED_POOLS
