"""z_importkey honours its rescan start height (#1941 regression).

Importing a shielded spending key with a start height above the block that
funded the note must not rescan that note (balance stays zero); re-importing the
same key from a height below the note must rescan it and recover the balance.
"""

from decimal import Decimal

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from zhelpers import shielded_args, wait_and_assert_operationid_status

FEE = Decimal("0.0001")


async def test_importkey_rescan_start_height(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0, extra_args=shielded_args(1))
    await node0.mine(101)

    # Fund a fresh t-address with exactly 10, then shield it into a Sprout note.
    taddr = await node0.rpc.getnewaddress()
    await node0.rpc.sendtoaddress(taddr, Decimal("10.0"))
    await node0.mine(1)

    zaddr = await node0.rpc.z_getnewaddress("sprout")
    opid = await node0.rpc.z_sendmany(taddr, [{"address": zaddr, "amount": Decimal("10.0") - FEE}])
    await wait_and_assert_operationid_status(node0, opid)
    await node0.mine(1)
    note_height = await node0.rpc.getblockcount()  # block containing the note

    assert await node0.rpc.z_getbalance(zaddr) == Decimal("10.0") - FEE
    key = await node0.rpc.z_exportkey(zaddr)

    # A second node syncs the chain but does not hold the key.
    await node0.mine(10)  # blocks after the note, so a start height can sit past it
    node1 = await node_factory(1, extra_args=shielded_args(1))
    await connect_nodes_bi(node0, node1)
    await sync_blocks([node0, node1])

    # Import scanning only from after the note: it is not seen.
    await node1.rpc.z_importkey(key, "true", note_height + 5)
    assert await node1.rpc.z_getbalance(zaddr) == 0

    # Re-import scanning from before the note: it is recovered.
    await node1.rpc.z_importkey(key, "yes", note_height - 5)
    assert await node1.rpc.z_getbalance(zaddr) == Decimal("10.0") - FEE
