"""z_listunspent reports each note's pool, change flag, spendability and address.

After shielding and a partial spend, z_listunspent lists every note with its
txid / amount / address, marks the residual change note change=True, hides
still-unconfirmed notes under the default one-confirmation filter, and filters by
address across both the Sprout and Sapling pools in a single call.
"""

import asyncio
from decimal import Decimal

from conftest import NodeFactory
from fluxtest.node import FluxNode
from zhelpers import shielded_args, wait_and_assert_operationid_status


async def _wait_unspent(node: FluxNode, count: int, timeout: float = 30) -> list[dict]:
    """Poll z_listunspent(0) until at least ``count`` notes are visible. A note
    in the mempool reaches the sending wallet ~1s after the operation reports
    success (ThreadNotifyRecentlyAdded batches mempool notifications)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        unspent = await node.rpc.z_listunspent(0)
        if len(unspent) >= count:
            return unspent
        if loop.time() > deadline:
            raise AssertionError(f"expected >= {count} unspent notes, got {len(unspent)}")
        await asyncio.sleep(0.25)


async def _funded_taddr(node: FluxNode, amount: Decimal) -> str:
    """A fresh t-address holding ``amount`` in a non-coinbase UTXO (coinbase
    inputs forbid change, so an ordinary output lets us shield a fixed amount)."""
    taddr = await node.rpc.getnewaddress()
    await node.rpc.sendtoaddress(taddr, amount)
    await node.mine(1)
    return taddr


async def _shield(node: FluxNode, frm: str, to: str, amount: Decimal) -> str:
    opid = await node.rpc.z_sendmany(frm, [{"address": to, "amount": amount}], 1, 0)
    txid = await wait_and_assert_operationid_status(node, opid)
    assert txid is not None
    return txid


def _by_amount(notes: list[dict]) -> list[dict]:
    return sorted(notes, key=lambda n: n["amount"])


async def test_wallet_listnotes(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=shielded_args(1))
    await node.mine(110)

    sprout = await node.rpc.z_getnewaddress("sprout")
    sapling = await node.rpc.z_getnewaddress("sapling")
    assert Decimal((await node.rpc.z_gettotalbalance())["private"]) == 0

    # Shield 10 into the Sprout address.
    taddr = await _funded_taddr(node, Decimal("10"))
    shield_txid = await _shield(node, taddr, sprout, Decimal("10"))

    # Unconfirmed: hidden at minconf>=1, visible at minconf 0.
    assert await node.rpc.z_listunspent() == []
    assert await node.rpc.z_listunspent(1) == []
    unspent = await _wait_unspent(node, 1)
    assert len(unspent) == 1
    note = unspent[0]
    assert note["change"] is False
    assert note["txid"] == shield_txid
    assert note["spendable"] is True
    assert note["address"] == sprout
    assert note["amount"] == Decimal("10")
    assert await node.rpc.z_listunspent(0, 9999, False, [sprout]) == unspent
    await node.mine(1)

    # Spend 1 Sprout -> Sprout, leaving a 9 change note flagged change=True.
    sprout2 = await node.rpc.z_getnewaddress("sprout")
    assert (await node.rpc.z_validateaddress(sprout2))["type"] == "sprout"
    send_txid = await _shield(node, sprout, sprout2, Decimal("1"))
    unspent = _by_amount(await _wait_unspent(node, 2))
    assert len(unspent) == 2
    assert unspent[0]["change"] is False
    assert unspent[0]["address"] == sprout2
    assert unspent[0]["amount"] == Decimal("1")
    assert unspent[0]["txid"] == send_txid
    assert unspent[1]["change"] is True
    assert unspent[1]["address"] == sprout
    assert unspent[1]["amount"] == Decimal("9")
    assert await node.rpc.z_listunspent(0, 9999, False, [sprout2]) == [unspent[0]]
    assert await node.rpc.z_listunspent(0, 9999, False, [sprout]) == [unspent[1]]
    await node.mine(1)

    # Shield 2 into the Sapling address; all three notes are now listed.
    assert await node.rpc.z_listunspent(0, 9999, False, [sapling]) == []
    taddr2 = await _funded_taddr(node, Decimal("2"))
    await _shield(node, taddr2, sapling, Decimal("2"))
    unspent = _by_amount(await _wait_unspent(node, 3))
    assert len(unspent) == 3
    assert [n["amount"] for n in unspent] == [Decimal("1"), Decimal("2"), Decimal("9")]
    assert unspent[1]["address"] == sapling
    assert unspent[1]["change"] is False

    # Filter by one address, then across both pools in a single call.
    assert await node.rpc.z_listunspent(0, 9999, False, [sapling]) == [unspent[1]]
    cross_pool = _by_amount(await node.rpc.z_listunspent(0, 9999, False, [sprout, sapling]))
    assert cross_pool == [unspent[1], unspent[2]]

    # No watch-only addresses, so requesting them changes nothing.
    assert _by_amount(await node.rpc.z_listunspent(0, 9999, True)) == unspent
