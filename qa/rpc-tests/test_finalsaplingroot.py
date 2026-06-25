"""The block header's finalsaplingroot tracks the Sapling commitment tree.

The field is null in the genesis block and the empty-tree root in every block
until a Sapling output (commitment) is mined; it then advances only for blocks
that add a Sapling commitment -- a transparent or Sprout transaction, or an
unshielding Sapling spend with no shielded output, leaves it unchanged.
"""

from decimal import Decimal

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from zhelpers import shielded_args, wait_and_assert_operationid_status

SAPLING_TREE_EMPTY_ROOT = "3e49b5f954aa9d3545bc6c37744661eea48d7c34e3000d82b7f0010c30f4c2fb"
NULL_FIELD = "00" * 32


async def _sync_all(nodes: list[FluxNode]) -> None:
    tip = await nodes[0].rpc.getbestblockhash()
    tip_time = (await nodes[0].rpc.getblock(tip))["time"]
    for node in nodes[1:]:
        await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def _mine(nodes: list[FluxNode]) -> None:
    await sync_mempools(nodes)
    await nodes[0].mine(1)
    await _sync_all(nodes)


async def _tip_block(node: FluxNode) -> dict:
    return await node.rpc.getblock(await node.rpc.getbestblockhash())


async def _root_at(node: FluxNode, height: int) -> str:
    blockhash = await node.rpc.getblockhash(height)
    return (await node.rpc.getblock(blockhash))["finalsaplingroot"]


async def _shield_send(node: FluxNode, frm: str, recipients: list[dict]) -> str:
    opid = await node.rpc.z_sendmany(frm, recipients, 1, 0)
    txid = await wait_and_assert_operationid_status(node, opid)
    assert txid is not None
    return txid


async def _funded_taddr(nodes: list[FluxNode], amount: Decimal) -> str:
    """A fresh t-address holding ``amount`` in a non-coinbase UTXO. z_sendmany
    forbids change when shielding a coinbase input, so fund an ordinary output
    first to be able to shield a fixed amount."""
    taddr = await nodes[0].rpc.getnewaddress()
    await nodes[0].rpc.sendtoaddress(taddr, amount)
    await _mine(nodes)
    return taddr


async def test_finalsaplingroot(node_factory: NodeFactory) -> None:
    # -txindex so getrawtransaction resolves the spends; ACADIA from height 1.
    args = shielded_args(1, extra=["-txindex"])
    nodes = [await node_factory(i, extra_args=args) for i in range(2)]
    await connect_nodes_bi(nodes[0], nodes[1])
    await nodes[0].mine(110)
    await _sync_all(nodes)

    # Genesis is null; every block before a Sapling commitment is the empty root.
    assert await _root_at(nodes[0], 0) == NULL_FIELD
    for height in range(1, await nodes[0].rpc.getblockcount() + 1):
        assert await _root_at(nodes[0], height) == SAPLING_TREE_EMPTY_ROOT

    # Shielding to Sapling adds a commitment, so the root advances.
    sapling0 = await nodes[0].rpc.z_getnewaddress("sapling")
    taddr0 = await _funded_taddr(nodes, Decimal("20"))
    txid = await _shield_send(nodes[0], taddr0, [{"address": sapling0, "amount": Decimal("20")}])
    await _mine(nodes)
    root = await _root_at(nodes[0], await nodes[0].rpc.getblockcount())
    assert root not in (SAPLING_TREE_EMPTY_ROOT, NULL_FIELD)
    assert len((await nodes[0].rpc.getrawtransaction(txid, 1))["vShieldedOutput"]) == 1

    # An empty block does not change the root.
    await _mine(nodes)
    assert (await _tip_block(nodes[0]))["finalsaplingroot"] == root

    # A transparent transaction does not change the root.
    taddr1 = await nodes[1].rpc.getnewaddress()
    await nodes[0].rpc.sendtoaddress(taddr1, Decimal("1.23"))
    await _mine(nodes)
    tip = await _tip_block(nodes[0])
    assert len(tip["tx"]) == 2
    assert await nodes[1].rpc.z_getbalance(taddr1) == Decimal("1.23")
    assert tip["finalsaplingroot"] == root

    # A Sprout shielded transaction does not change the Sapling root.
    zaddr1 = await nodes[1].rpc.z_getnewaddress("sprout")
    taddr_src = await _funded_taddr(nodes, Decimal("10"))
    await _shield_send(nodes[0], taddr_src, [{"address": zaddr1, "amount": Decimal("10")}])
    await _mine(nodes)
    tip = await _tip_block(nodes[0])
    assert len(tip["tx"]) == 2
    assert await nodes[1].rpc.z_getbalance(zaddr1) == Decimal("10")
    assert tip["finalsaplingroot"] == root

    # A Sapling recipient adds a commitment, so the root advances again.
    sapling1 = await nodes[1].rpc.z_getnewaddress("sapling")
    recipients = [{"address": sapling1, "amount": Decimal("12.34")}]
    txid = await _shield_send(nodes[0], sapling0, recipients)
    await _mine(nodes)
    tip = await _tip_block(nodes[0])
    assert len(tip["tx"]) == 2
    assert await nodes[1].rpc.z_getbalance(sapling1) == Decimal("12.34")
    assert tip["finalsaplingroot"] != root
    root = tip["finalsaplingroot"]
    # The output plus the Sapling change make two shielded outputs.
    assert len((await nodes[0].rpc.getrawtransaction(txid, 1))["vShieldedOutput"]) == 2

    # A Sapling spend with only a transparent recipient adds no commitment.
    taddr2 = await nodes[0].rpc.getnewaddress()
    await _shield_send(nodes[1], sapling1, [{"address": taddr2, "amount": Decimal("12.34")}])
    await _mine(nodes)
    tip = await _tip_block(nodes[0])
    assert len(tip["tx"]) == 2
    assert await nodes[0].rpc.z_getbalance(taddr2) == Decimal("12.34")
    assert tip["finalsaplingroot"] == root
