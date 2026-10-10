"""Payment disclosure: prove the recipient of a shielded output.

A node with payment disclosure enabled can, for a confirmed shielded
transaction it sent, emit a "zpd:"-prefixed proof for a chosen JoinSplit output
that any node can validate (recovering the value and the attached message). The
RPC rejects: a node without the feature, unknown/unconfirmed transactions,
transactions outside the wallet, out-of-range indices, malformed proofs, and
transparent (non-shielded) transactions.
"""

from collections.abc import Awaitable
from decimal import Decimal

import pytest
from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status

DISCLOSURE = ["-experimentalfeatures", "-paymentdisclosure", "-txindex"]
NO_DISCLOSURE = ["-experimentalfeatures", "-txindex"]


async def _sync_all(nodes: list[FluxNode]) -> None:
    tip = await nodes[0].rpc.getbestblockhash()
    tip_time = (await nodes[0].rpc.getblock(tip))["time"]
    for node in nodes[1:]:
        await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def _expect_error(coro: Awaitable, substring: str) -> None:
    with pytest.raises(JSONRPCError) as exc:
        await coro
    assert substring in exc.value.error["message"]


async def test_paymentdisclosure(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0, extra_args=shielded_args(1, extra=DISCLOSURE))
    node1 = await node_factory(1, extra_args=shielded_args(1, extra=DISCLOSURE))
    node2 = await node_factory(2, extra_args=shielded_args(1, extra=NO_DISCLOSURE))
    nodes = [node0, node1, node2]
    await connect_nodes_bi(node0, node1)
    await connect_nodes_bi(node1, node2)
    await connect_nodes_bi(node0, node2)
    await node0.mine(110)
    await _sync_all(nodes)

    # node2 has the feature disabled; node0 rejects an unknown txid.
    bad = "00" * 32
    await _expect_error(
        node2.rpc.z_getpaymentdisclosure(bad, 0, 0), "payment disclosure is disabled"
    )
    await _expect_error(
        node0.rpc.z_getpaymentdisclosure(bad, 0, 0), "No information available about transaction"
    )

    # Shield a controlled 39.9999 (40 funded, default 0.0001 fee) into a Sprout zaddr.
    taddr = await node0.rpc.getnewaddress()
    await node0.rpc.sendtoaddress(taddr, Decimal("40"))
    await node0.mine(1)
    await _sync_all(nodes)
    zaddr = await node0.rpc.z_getnewaddress("sprout")
    opid = await node0.rpc.z_sendmany(taddr, [{"address": zaddr, "amount": Decimal("39.9999")}])
    txid = await wait_and_assert_operationid_status(node0, opid)
    assert txid is not None
    assert len((await node0.rpc.getrawtransaction(txid, 1))["vJoinSplit"]) > 0

    # A disclosure cannot be made for an unconfirmed transaction.
    await sync_mempools(nodes)
    not_confirmed = "Transaction has not been confirmed yet"
    await _expect_error(node0.rpc.z_getpaymentdisclosure(txid, 0, 0), not_confirmed)
    await _expect_error(node1.rpc.z_getpaymentdisclosure(txid, 0, 0), not_confirmed)

    await node0.mine(1)
    await _sync_all(nodes)

    # node1 holds the block but the transaction is not in its wallet.
    await _expect_error(
        node1.rpc.z_getpaymentdisclosure(txid, 0, 0), "Transaction does not belong to the wallet"
    )
    # Out-of-range JoinSplit / output indices are rejected.
    await _expect_error(node0.rpc.z_getpaymentdisclosure(txid, 1, 0), "Invalid js_index")
    await _expect_error(node0.rpc.z_getpaymentdisclosure(txid, -1, 0), "Invalid js_index")
    await _expect_error(node0.rpc.z_getpaymentdisclosure(txid, 0, 2), "Invalid output_index")
    await _expect_error(node0.rpc.z_getpaymentdisclosure(txid, 0, -1), "Invalid output_index")

    # A valid disclosure validates on the sender and any other enabled node.
    message = "Here is proof of my payment!"
    pd = await node0.rpc.z_getpaymentdisclosure(txid, 0, 0, message)
    assert pd.startswith("zpd:")
    result = await node0.rpc.z_validatepaymentdisclosure(pd)
    assert result["valid"]
    value_sum = Decimal(result["value"])

    result = await node1.rpc.z_validatepaymentdisclosure(pd)
    assert result["valid"]
    assert result["message"] == message
    assert Decimal(result["value"]) == value_sum

    # A proof without its zpd: prefix is rejected.
    await _expect_error(
        node1.rpc.z_validatepaymentdisclosure(pd[4:]), "payment disclosure prefix not found"
    )

    # The two JoinSplit outputs together account for the shielded amount.
    pd1 = await node0.rpc.z_getpaymentdisclosure(txid, 0, 1)
    value_sum += Decimal((await node0.rpc.z_validatepaymentdisclosure(pd1))["value"])
    assert value_sum == Decimal("39.99990000")

    # A z->z send: the sender can disclose, the recipient cannot.
    node1zaddr = await node1.rpc.z_getnewaddress("sprout")
    opid = await node0.rpc.z_sendmany(zaddr, [{"address": node1zaddr, "amount": Decimal("1")}])
    txid = await wait_and_assert_operationid_status(node0, opid)
    assert txid is not None
    await node0.mine(1)
    await _sync_all(nodes)
    pd = await node0.rpc.z_getpaymentdisclosure(txid, 0, 0, "a message of your choice")
    assert (await node0.rpc.z_validatepaymentdisclosure(pd))["valid"]
    await _expect_error(
        node1.rpc.z_getpaymentdisclosure(txid, 0, 0),
        "Could not find payment disclosure info for the given joinsplit output",
    )

    # A transparent transaction has no shielded output to disclose.
    txid = await node0.rpc.sendtoaddress(await node1.rpc.getnewaddress(), Decimal("1"))
    await sync_mempools(nodes)
    await _expect_error(node0.rpc.z_getpaymentdisclosure(txid, 0, 0), not_confirmed)
    await node0.mine(1)
    await _sync_all(nodes)
    await _expect_error(
        node0.rpc.z_getpaymentdisclosure(txid, 0, 0), "Transaction is not a shielded transaction"
    )
