"""z_listreceivedbyaddress / z_listunspent flag change notes correctly (Sprout).

A received note is reported change=false; a partial spend produces a change note
flagged change=true carrying the residual amount, while the immutable original
note remains. A viewing-key-only node sees the received notes but cannot tell
which are spent or which are change (both require the spending key), so it
over-reports unspent notes and omits the change field.
"""

from decimal import Decimal

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from zhelpers import shielded_args, wait_and_assert_operationid_status


async def test_change_indicator(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0, extra_args=shielded_args(1))
    await node0.mine(101)
    node1 = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(node0, node1)
    await sync_blocks([node0, node1])

    taddr = await node1.rpc.getnewaddress()
    zaddr1 = await node1.rpc.z_getnewaddress("sprout")
    zaddr2 = await node1.rpc.z_getnewaddress("sprout")

    await node0.rpc.sendtoaddress(taddr, Decimal("1.0"))
    await node0.mine(1)
    await sync_blocks([node0, node1])

    # 1.0 t -> z with a zero fee, so the note is exactly 1.0 and not change.
    opid = await node1.rpc.z_sendmany(
        taddr, [{"address": zaddr1, "amount": Decimal("1.0"), "memo": "c0ffee01"}], 1, 0
    )
    await wait_and_assert_operationid_status(node1, opid)
    await node0.mine(1)
    await sync_blocks([node0, node1])

    received = await node1.rpc.z_listreceivedbyaddress(zaddr1, 0)
    unspent = await node1.rpc.z_listunspent()
    assert len(received) == 1
    assert received[0]["change"] is False
    assert len(unspent) == 1
    assert unspent[0]["change"] is False

    # Spend 0.6 of the 1.0 note; the 0.4 remainder returns to zaddr1 as change.
    opid = await node1.rpc.z_sendmany(
        zaddr1, [{"address": zaddr2, "amount": Decimal("0.6"), "memo": "c0ffee02"}], 1, 0
    )
    await wait_and_assert_operationid_status(node1, opid)
    await node0.mine(1)
    await sync_blocks([node0, node1])

    received1 = sorted(
        await node1.rpc.z_listreceivedbyaddress(zaddr1, 0), key=lambda r: r["amount"]
    )
    assert len(received1) == 2
    assert received1[0]["amount"] == Decimal("0.4")
    assert received1[0]["change"] is True
    assert received1[1]["amount"] == Decimal("1.0")
    assert received1[1]["change"] is False

    received2 = sorted(
        await node1.rpc.z_listreceivedbyaddress(zaddr2, 0), key=lambda r: r["amount"]
    )
    assert len(received2) == 1
    assert received2[0]["amount"] == Decimal("0.6")
    assert received2[0]["change"] is False

    unspent = sorted(await node1.rpc.z_listunspent(), key=lambda u: u["amount"])
    assert len(unspent) == 2
    assert unspent[0]["amount"] == Decimal("0.4")
    assert unspent[0]["change"] is True
    assert unspent[1]["amount"] == Decimal("0.6")
    assert unspent[1]["change"] is False

    # A viewing-key-only node sees both notes but not the change field, and
    # cannot detect that the 1.0 note was spent, so it lists 2 unspent.
    viewing_key = await node1.rpc.z_exportviewingkey(zaddr1)
    await node0.rpc.z_importviewingkey(viewing_key)
    received_node0 = await node0.rpc.z_listreceivedbyaddress(zaddr1, 0)
    unspent_node0 = await node0.rpc.z_listunspent(1, 9999999, True)
    assert len(received_node0) == 2
    assert len(unspent_node0) == 2
    for entry in received_node0 + unspent_node0:
        assert "change" not in entry
