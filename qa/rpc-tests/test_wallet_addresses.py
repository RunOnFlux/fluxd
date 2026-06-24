"""z_getnewaddress creates valid, owned addresses of each shielded pool type.

The default new shielded address is always Sapling and both Sprout and Sapling
addresses can be generated regardless of activation height -- address creation
is unconditional. (Spending from or to a shielded address is separately gated on
the ACADIA upgrade and exercised by the send tests.) The default pool must not
change across the ACADIA boundary.
"""

from conftest import NodeFactory
from fluxtest.node import FluxNode


async def _check_address_types(node: FluxNode) -> None:
    default_addr = await node.rpc.z_getnewaddress()
    sprout_addr = await node.rpc.z_getnewaddress("sprout")
    sapling_addr = await node.rpc.z_getnewaddress("sapling")

    all_addresses = await node.rpc.z_listaddresses()

    for expected_type, addr in (
        ("sapling", default_addr),  # the default pool is always Sapling
        ("sprout", sprout_addr),
        ("sapling", sapling_addr),
    ):
        res = await node.rpc.z_validateaddress(addr)
        assert res["isvalid"]
        assert res["ismine"]
        assert res["type"] == expected_type
        assert addr in all_addresses


async def test_z_address_types_across_acadia(node_factory: NodeFactory) -> None:
    # ACADIA (Sapling) activates at height 6; check address creation below the
    # boundary and again above it.
    node = await node_factory(0, extra_args=["-acadiaactivation=6"])

    await _check_address_types(node)  # pre-ACADIA
    await node.mine(8)  # cross the boundary
    await _check_address_types(node)  # post-ACADIA
