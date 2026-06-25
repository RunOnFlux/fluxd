"""Importing a Sprout spending key rescans and recovers all of its notes.

A key exported from one wallet and imported (with rescan) into others recovers
the full set of received notes -- amounts and JoinSplit indices -- and keeps
tracking spends afterwards, so an imported address never reports a stale
("zombie") balance (#1936). Re-importing the same key is idempotent.
"""

from decimal import Decimal

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from zhelpers import shielded_args, wait_and_assert_operationid_status

FEE = Decimal("0.0001")
AMOUNTS = [Decimal(a) for a in ("2.3", "3.7", "0.1", "0.5", "1.0", "0.19")]


async def _sync(nodes: list[FluxNode], tip_node: FluxNode) -> None:
    """Sync every node to ``tip_node``'s chain (it, not node 0, holds the tip)."""
    tip = await tip_node.rpc.getbestblockhash()
    tip_time = (await tip_node.rpc.getblock(tip))["time"]
    for node in nodes:
        if node is not tip_node:
            await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def _assert_received(node: FluxNode, zaddr: str, amounts: list[Decimal]) -> None:
    received = await node.rpc.z_listreceivedbyaddress(zaddr)
    assert sorted((r["amount"] for r in received), reverse=True) == sorted(amounts, reverse=True)
    for r in received:
        assert r["jsindex"] >= 0  # Sprout JoinSplit indices
        assert r["jsoutindex"] >= 0


async def test_zkey_import_export(node_factory: NodeFactory) -> None:
    nodes = [await node_factory(i, extra_args=shielded_args(1)) for i in range(5)]
    alice, bob, charlie, david, miner = nodes
    await connect_nodes_bi(alice, bob)
    await connect_nodes_bi(bob, charlie)
    await connect_nodes_bi(alice, charlie)
    await connect_nodes_bi(alice, david)
    await connect_nodes_bi(alice, miner)

    async def z_send(from_node: FluxNode, from_addr: str, to_addr: str, amount: Decimal) -> None:
        recipients = [{"address": to_addr, "amount": amount}]
        opid = await from_node.rpc.z_sendmany(from_addr, recipients, 1, FEE)
        await wait_and_assert_operationid_status(from_node, opid)
        await sync_mempools(nodes)
        await miner.mine(1)
        await _sync(nodes, miner)

    # Seed alice, mature the coinbase on the miner, then shield all of alice's
    # coinbase into a Sprout zaddr (z_shieldcoinbase takes the whole UTXO).
    await alice.mine(10)
    await _sync(nodes, alice)
    await miner.mine(100)
    await _sync(nodes, miner)
    alice_zaddr = await alice.rpc.z_getnewaddress("sprout")
    shield = await alice.rpc.z_shieldcoinbase("*", alice_zaddr)
    await wait_and_assert_operationid_status(alice, shield["opid"])
    await sync_mempools(nodes)
    await miner.mine(1)
    await _sync(nodes, miner)
    assert await alice.rpc.z_getbalance(alice_zaddr) > sum(AMOUNTS)

    bob_zaddr = await bob.rpc.z_getnewaddress("sprout")
    await _assert_received(bob, bob_zaddr, [])

    # Send two notes, export bob's key, send two more.
    for amount in AMOUNTS[0:2]:
        await z_send(alice, alice_zaddr, bob_zaddr, amount)
    bob_privkey = await bob.rpc.z_exportkey(bob_zaddr)
    for amount in AMOUNTS[2:4]:
        await z_send(alice, alice_zaddr, bob_zaddr, amount)
    await _assert_received(bob, bob_zaddr, AMOUNTS[:4])

    # Import into charlie (default rescan) recovers the four notes; idempotent.
    await charlie.rpc.z_importkey(bob_privkey)
    assert bob_zaddr in await charlie.rpc.z_listaddresses()
    await _assert_received(charlie, bob_zaddr, AMOUNTS[:4])
    await charlie.rpc.z_importkey(bob_privkey)
    await _assert_received(charlie, bob_zaddr, AMOUNTS[:4])

    # Notes sent after the import are seen by both the original and imported wallet.
    for amount in AMOUNTS[4:]:
        await z_send(alice, alice_zaddr, bob_zaddr, amount)
    await _assert_received(bob, bob_zaddr, AMOUNTS)
    await _assert_received(charlie, bob_zaddr, AMOUNTS)

    # bob spends back to alice; the imported wallets track the spend rather than
    # reporting a stale balance.
    for amount in AMOUNTS[:2]:
        await z_send(bob, bob_zaddr, alice_zaddr, amount)
    bob_balance = sum(AMOUNTS[2:]) - 2 * FEE
    assert await bob.rpc.z_getbalance(bob_zaddr) == bob_balance

    await david.rpc.z_importkey(bob_privkey)
    assert bob_zaddr in await david.rpc.z_listaddresses()
    assert await charlie.rpc.z_getbalance(bob_zaddr) == bob_balance
    assert await david.rpc.z_getbalance(bob_zaddr) == bob_balance
