"""Signing a shielded (Overwintered) transaction selects the right branch id.

A z_sendmany from a transparent address to a Sprout zaddr builds and signs an
Overwintered Sapling-v4 transaction; if the wrong consensus branch id were
chosen the signature would not verify and the async operation would fail. ACADIA
must be active for any shielded send, so the test activates it from genesis.
"""

from decimal import Decimal

from conftest import NodeFactory
from zhelpers import shielded_args, wait_and_assert_operationid_status


async def test_sign_shielded_transaction(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=shielded_args(1))
    await node.mine(101)  # mature the premine so a t-address can be funded

    taddr = await node.rpc.getnewaddress()
    await node.rpc.sendtoaddress(taddr, Decimal("2.0"))
    await node.mine(1)

    zaddr = await node.rpc.z_getnewaddress("sprout")
    opid = await node.rpc.z_sendmany(taddr, [{"address": zaddr, "amount": Decimal("1.0")}])
    await wait_and_assert_operationid_status(node, opid)
