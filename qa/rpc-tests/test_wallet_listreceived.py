"""z_listreceivedbyaddress reports notes, memos, change and confirmation depth.

Exercised for both the Sprout and Sapling pools: a received note carries the
right txid/amount/memo and change=false; the default one-confirmation filter
hides a still-unconfirmed note and reveals it once mined; and a partial spend
yields a change note (change=true, default empty memo) alongside the immutable
original note.
"""

from decimal import Decimal

import pytest
from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from zhelpers import (
    shielded_args,
    wait_and_assert_operationid_status,
    wait_for_received_notes,
)

MY_MEMO = "c0ffee" + "0" * (1024 - len("c0ffee"))
NO_MEMO = "f6" + "0" * 1022  # the protocol's empty-memo sentinel
FEE = Decimal("0.0001")


@pytest.mark.parametrize("pool", ["sprout", "sapling"])
async def test_list_received(node_factory: NodeFactory, pool: str) -> None:
    node0 = await node_factory(0, extra_args=shielded_args(1))
    await node0.mine(101)
    node1 = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(node0, node1)
    await sync_blocks([node0, node1])

    taddr = await node1.rpc.getnewaddress()
    zaddr1 = await node1.rpc.z_getnewaddress(pool)
    await node0.rpc.sendtoaddress(taddr, Decimal("2.0"))
    await node0.mine(1)
    await sync_blocks([node0, node1])

    # 1 FLUX t -> z carrying a memo (default fee).
    opid = await node1.rpc.z_sendmany(
        taddr, [{"address": zaddr1, "amount": Decimal("1"), "memo": MY_MEMO}]
    )
    txid = await wait_and_assert_operationid_status(node1, opid)

    # The note is unconfirmed: visible at minconf=0, hidden by the default minconf=1.
    received = await wait_for_received_notes(node1, zaddr1, 1)
    assert await node1.rpc.z_listreceivedbyaddress(zaddr1) == []
    assert received[0]["txid"] == txid
    assert received[0]["amount"] == Decimal("1")
    assert received[0]["change"] is False
    assert received[0]["memo"] == MY_MEMO

    # Node 0 mines node 1's transaction: it must have relayed first.
    await sync_mempools([node0, node1])
    await node0.mine(1)
    await sync_blocks([node0, node1])
    # Once confirmed the same note shows under the default one-confirmation filter.
    confirmed = await node1.rpc.z_listreceivedbyaddress(zaddr1)
    assert len(confirmed) == 1
    assert confirmed[0]["txid"] == txid
    assert confirmed[0]["amount"] == Decimal("1")
    assert confirmed[0]["change"] is False
    assert confirmed[0]["memo"] == MY_MEMO

    # Partial spend of zaddr1 -> zaddr2 leaves a change note on zaddr1.
    zaddr2 = await node1.rpc.z_getnewaddress(pool)
    opid = await node1.rpc.z_sendmany(zaddr1, [{"address": zaddr2, "amount": Decimal("0.6")}])
    txid = await wait_and_assert_operationid_status(node1, opid)
    await sync_mempools([node0, node1])
    await node0.mine(1)
    await sync_blocks([node0, node1])

    received1 = sorted(
        await node1.rpc.z_listreceivedbyaddress(zaddr1, 0), key=lambda r: r["amount"]
    )
    assert len(received1) == 2
    assert received1[0]["txid"] == txid
    assert received1[0]["amount"] == Decimal("0.4") - FEE
    assert received1[0]["change"] is True
    assert received1[0]["memo"] == NO_MEMO
    assert received1[1]["amount"] == Decimal("1.0")
    assert received1[1]["change"] is False
    assert received1[1]["memo"] == MY_MEMO

    received2 = sorted(
        await node1.rpc.z_listreceivedbyaddress(zaddr2, 0), key=lambda r: r["amount"]
    )
    assert len(received2) == 1
    assert received2[0]["txid"] == txid
    assert received2[0]["amount"] == Decimal("0.6")
    assert received2[0]["change"] is False
    assert received2[0]["memo"] == NO_MEMO
