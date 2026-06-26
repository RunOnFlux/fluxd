"""Spent-note detection depends on cached nullifiers.

A wallet computes a note's nullifier only when it holds the spending key and is
unlocked. An encrypted-and-locked wallet, or one holding only a viewing key,
receives notes but cannot derive their nullifiers, so it cannot tell when those
notes are spent and over-reports the address balance. This drives both cases:
node1's wallet is encrypted while holding a spending key (balance is wrong while
locked, corrects itself once unlocked and the nullifiers are cached), and node3
imports only a viewing key (balance over-reports until watch-only totals expose
why).

Funding shields a whole coinbase (Flux coinbase is 150, and a coinbase shield
forbids change), so the first note is 149.9999; the chained 7 / 2 / 1 sends that
follow are ordinary shielded spends and translate unchanged.
"""

from decimal import Decimal

import aiohttp
from conftest import COINBASE_MATURITY, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status

DEFAULT_FEE = Decimal("0.0001")
ENCRYPT_ARGS = ["-experimentalfeatures", "-developerencryptwallet"]


async def _smallest_coinbase(node: FluxNode) -> str:
    gens = sorted(
        (u for u in await node.rpc.listunspent() if u["generated"] and u["spendable"]),
        key=lambda u: u["amount"],
    )
    assert gens, "node has no spendable coinbase outputs"
    return gens[0]["address"]


async def _sync_to(nodes: list[FluxNode], tip_node: FluxNode) -> None:
    tip = await tip_node.rpc.getbestblockhash()
    tip_time = (await tip_node.rpc.getblock(tip))["time"]
    for node in nodes:
        if node is not tip_node:
            await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def test_wallet_nullifiers(node_factory: NodeFactory) -> None:
    nodes = [await node_factory(i, extra_args=shielded_args(1, ENCRYPT_ARGS)) for i in range(4)]
    node0, node1, node2, node3 = nodes
    for i in range(4):
        for j in range(i + 1, 4):
            await connect_nodes_bi(nodes[i], nodes[j])

    # node0 mines the premine and the coinbase it will shield; node3 mines two
    # blocks for a known transparent balance; bury everything past maturity.
    await node0.mine(1)
    await _sync_to(nodes, node0)
    await node3.mine(2)
    await _sync_to(nodes, node3)
    await node0.mine(COINBASE_MATURITY + 10)
    await _sync_to(nodes, node0)
    node3_mined = Decimal("300")  # two matured 150 coinbases
    assert Decimal((await node3.rpc.z_gettotalbalance())["transparent"]) == node3_mined

    # Shield a whole coinbase into node0's zaddr (coinbase shield forbids change).
    zaddr0 = await node0.rpc.z_getnewaddress("sprout")
    coinbase = await _smallest_coinbase(node0)
    opid = await node0.rpc.z_sendmany(
        coinbase, [{"address": zaddr0, "amount": Decimal("149.9999")}]
    )
    await wait_and_assert_operationid_status(node0, opid)
    await node0.mine(1)
    await _sync_to(nodes, node0)

    # node2 owns the zaddr; node1 imports its spending key, then encrypts.
    zaddr = await node2.rpc.z_getnewaddress("sprout")
    await node1.rpc.z_importkey(await node2.rpc.z_exportkey(zaddr))
    try:
        await node1.rpc.encryptwallet("test")
    except (JSONRPCError, aiohttp.ClientError):
        pass  # encryptwallet shuts the daemon down; the reply may be cut off
    await node1.restart()
    for other in (node0, node2, node3):
        await connect_nodes_bi(node1, other)
    await _sync_to(nodes, node0)

    # node0 -> zaddr (7), seen identically by note owner (node2) and the
    # encrypted holder (node1).
    note_value = Decimal("7.0")
    opid = await node0.rpc.z_sendmany(zaddr0, [{"address": zaddr, "amount": note_value}])
    await wait_and_assert_operationid_status(node0, opid)
    await node0.mine(1)
    await _sync_to(nodes, node0)
    assert Decimal(await node2.rpc.z_getbalance(zaddr)) == note_value
    assert Decimal(await node1.rpc.z_getbalance(zaddr)) == note_value

    # node2 spends 2 of the 7 to node3, keeping 4.9999 as change.
    zaddr3 = await node3.rpc.z_getnewaddress("sprout")
    spend2 = Decimal("2.0")
    opid = await node2.rpc.z_sendmany(zaddr, [{"address": zaddr3, "amount": spend2}])
    await wait_and_assert_operationid_status(node2, opid)
    await node2.mine(1)
    await _sync_to(nodes, node2)
    remaining = note_value - spend2 - DEFAULT_FEE  # 4.9999
    assert Decimal(await node3.rpc.z_getbalance(zaddr3)) == spend2
    assert Decimal(await node2.rpc.z_getbalance(zaddr)) == remaining

    # The locked wallet cannot cache nullifiers, so it misses the spend and
    # over-reports: it counts both notes it received (the 7 and the 4.9999 change).
    assert Decimal(await node1.rpc.z_getbalance(zaddr)) == note_value + remaining

    # Unlocking caches the nullifiers; spending 1 to a taddr now reconciles both
    # wallets to the same balance.
    await node1.rpc.walletpassphrase("test", 600)
    taddr1 = await node1.rpc.getnewaddress()
    spend3 = Decimal("1.0")
    opid = await node1.rpc.z_sendmany(zaddr, [{"address": taddr1, "amount": spend3}])
    await wait_and_assert_operationid_status(node1, opid)
    await node1.mine(1)
    await _sync_to(nodes, node1)
    remaining2 = remaining - spend3 - DEFAULT_FEE  # 3.9998
    assert Decimal(await node1.rpc.z_getbalance(zaddr)) == remaining2
    assert Decimal(await node2.rpc.z_getbalance(zaddr)) == remaining2

    # node3 owns only its own received note; its totals reflect mined coinbase
    # plus the single 2.0 note.
    def totals(balance: dict) -> dict:
        return {k: Decimal(v) for k, v in balance.items()}

    assert totals(await node3.rpc.z_gettotalbalance()) == {
        "transparent": node3_mined,
        "private": spend2,
        "total": node3_mined + spend2,
    }

    # Import node1's taddr and node2's viewing key into node3.
    await node3.rpc.importaddress(taddr1)
    await node3.rpc.z_importviewingkey(await node2.rpc.z_exportviewingkey(zaddr), "whenkeyisnew", 1)
    assert zaddr not in await node3.rpc.z_listaddresses()
    assert zaddr in await node3.rpc.z_listaddresses(True)

    # node3 sees the same notes node2 received. The change flag (needs the
    # spending key) and time (each wallet's own record of when it saw the tx,
    # which diverges with per-node mocktime) are node-local, so skip both.
    node2_received = {r["txid"]: r for r in await node2.rpc.z_listreceivedbyaddress(zaddr)}
    node3_received = {r["txid"]: r for r in await node3.rpc.z_listreceivedbyaddress(zaddr)}
    for txid, r2 in node2_received.items():
        r3 = node3_received[txid]
        for key, value in r2.items():
            if key not in ("change", "time"):
                assert r3[key] == value

    # Default totals ignore watch-only, so node3's own balances are unchanged.
    assert totals(await node3.rpc.z_gettotalbalance()) == {
        "transparent": node3_mined,
        "private": spend2,
        "total": node3_mined + spend2,
    }

    # With watch-only included, the viewing key (no nullifiers) over-reports: it
    # sums every note the address received, blind to the spends.
    watch_private = spend2 + note_value + remaining + remaining2
    assert totals(await node3.rpc.z_gettotalbalance(1, True)) == {
        "transparent": node3_mined + spend3,
        "private": watch_private,
        "total": node3_mined + spend3 + watch_private,
    }
    assert Decimal(await node3.rpc.z_getbalance(taddr1)) == spend3
    assert Decimal(await node3.rpc.z_getbalance(zaddr)) == note_value + remaining + remaining2
