"""z_sendmany uses a fresh transparent change address for every transaction.

Whatever the recipient pool -- Sapling, Sprout, or transparent -- two successive
sends from the same source t-address must not reuse a change address.
"""

from decimal import Decimal

from conftest import NodeFactory
from fluxtest.node import FluxNode
from zhelpers import (
    get_coinbase_address,
    shielded_args,
    wait_and_assert_operationid_status,
)


async def _assert_change_addresses_differ(node: FluxNode, source: str, target: str) -> None:
    """Send 1 from ``source`` to ``target`` twice; the two transactions must use
    different transparent change addresses (the non-``target`` vout)."""
    recipients = [{"address": target, "amount": Decimal("1")}]
    txids = []
    for _ in range(2):
        opid = await node.rpc.z_sendmany(source, recipients, 1, 0)
        txid = await wait_and_assert_operationid_status(node, opid)
        assert txid is not None
        await node.mine(1)
        txids.append(txid)

    changes = []
    for txid in txids:
        tx = await node.rpc.getrawtransaction(txid, 1)
        for vout in tx["vout"]:
            addresses = vout["scriptPubKey"]["addresses"]
            if addresses != [target]:  # the change output, not the recipient
                changes.append(addresses)
    assert changes[0] != changes[1], f"change address reused: {changes}"


async def test_change_addresses_not_reused(node_factory: NodeFactory) -> None:
    # -txindex so getrawtransaction can resolve the spends by id; ACADIA from
    # height 1 so Sapling/Sprout sends are valid throughout.
    node = await node_factory(0, extra_args=shielded_args(1, extra=["-txindex"]))
    await node.mine(110)

    # Shield a coinbase UTXO, then peel off six 2-coin transparent UTXOs to spend.
    mid = await node.rpc.z_getnewaddress("sapling")
    shield = await node.rpc.z_shieldcoinbase(await get_coinbase_address(node), mid, 0)
    await wait_and_assert_operationid_status(node, shield["opid"])
    await node.mine(1)
    source = await node.rpc.getnewaddress()
    for _ in range(6):
        opid = await node.rpc.z_sendmany(mid, [{"address": source, "amount": Decimal("2")}], 1, 0)
        await wait_and_assert_operationid_status(node, opid)
        await node.mine(1)

    await _assert_change_addresses_differ(node, source, await node.rpc.z_getnewaddress("sapling"))
    await _assert_change_addresses_differ(node, source, await node.rpc.z_getnewaddress("sprout"))
    await _assert_change_addresses_differ(node, source, await node.rpc.getnewaddress())
