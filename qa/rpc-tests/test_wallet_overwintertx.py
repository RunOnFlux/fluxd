"""Wallet transaction versions and expiry across the ACADIA boundary.

Flux has no Overwinter stage: the wallet jumps from legacy v1 transactions
(no version group, no expiry) straight to v4 Sapling transactions (version
group 0x892f2085, nExpiryHeight = next block + -txexpirydelta) when ACADIA
becomes active for the next block. The upstream test's v3/0x03c48270 Overwinter
assertions have no Flux equivalent -- that branch of the transaction builder is
unreachable -- and neither does its pre-upgrade v2 Sprout shield, because
z_sendmany refuses any shielded output until ACADIA is active for the next
block (covered by test_mempool_nu_activation).

createrawtransaction's expiryheight parameter is gated the same way: refused
outright before the boundary, and once usable it must be inside
[0, 500000000) and past the expiring-soon margin of the next block.

The getblockchaininfo upgrades map is not asserted on (ACADIA and PON share
branch id 0x76b809bb, so the JSON object has duplicate keys); the branch
transition is asserted via consensus.chaintip/nextblock.
"""

import asyncio
from decimal import Decimal

import pytest
from conftest import NodeFactory
from fluxtest.network import bump_clocks, connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status

ACADIA_HEIGHT = 110
SPROUT_BRANCH_ID = "00000000"
ACADIA_BRANCH_ID = "76b809bb"
SAPLING_VERSION_GROUP_ID = "892f2085"
# main.h DEFAULT_TX_EXPIRY_DELTA / TX_EXPIRING_SOON_THRESHOLD.
DEFAULT_EXPIRY_DELTA = 20
EXPIRING_SOON_THRESHOLD = 3

ARGS = shielded_args(ACADIA_HEIGHT, ["-txindex", "-debug=zrpcunsafe"])


async def _sync_all(nodes: list[FluxNode]) -> None:
    await bump_clocks(nodes)
    await sync_blocks(nodes)


async def _branch_ids(node: FluxNode) -> tuple[str, str]:
    consensus = (await node.rpc.getblockchaininfo())["consensus"]
    return consensus["chaintip"], consensus["nextblock"]


async def _wait_unconfirmed_funds(
    node: FluxNode, taddr: str, amount: Decimal, timeout: float = 30
) -> None:
    """Poll until the wallet registers the unconfirmed funds on ``taddr``.

    A mempool transaction only reaches the wallet through the once-per-second
    recently-added notifier, so a 0-conf balance is not visible immediately
    after the mempools sync.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while await node.rpc.z_getbalance(taddr, 0) < amount:
        if loop.time() > deadline:
            raise AssertionError(f"{taddr} never saw {amount} unconfirmed")
        await asyncio.sleep(0.25)


async def _send_pair(
    n0: FluxNode, n2: FluxNode, receiver: str, via: str
) -> tuple[str, str]:
    """Node 0 funds ``via`` (node 2's) with 1.0; node 2 forwards 0.5 of it,
    still unconfirmed, to ``receiver`` through z_sendmany."""
    funded = await n0.rpc.sendtoaddress(via, Decimal("1.0"))
    await sync_mempools([n0, n2])
    await _wait_unconfirmed_funds(n2, via, Decimal("1.0"))
    opid = await n2.rpc.z_sendmany(via, [{"address": receiver, "amount": Decimal("0.5")}], 0)
    forwarded = await wait_and_assert_operationid_status(n2, opid)
    assert forwarded is not None
    return funded, forwarded


async def test_wallet_overwintertx(node_factory: NodeFactory) -> None:
    n0 = await node_factory(0, extra_args=ARGS)
    n1 = await node_factory(1, extra_args=ARGS)
    n2 = await node_factory(2, extra_args=ARGS)
    nodes = [n0, n1, n2]
    await connect_nodes_bi(n0, n1)
    await connect_nodes_bi(n1, n2)
    await connect_nodes_bi(n0, n2)

    await n0.mine(105)
    await _sync_all(nodes)
    assert await _branch_ids(n0) == (SPROUT_BRANCH_ID, SPROUT_BRANCH_ID)

    # Before the boundary the expiryheight parameter is refused outright.
    with pytest.raises(JSONRPCError, match="can only be used if Overwinter is active"):
        await n0.rpc.createrawtransaction([], {}, 0, 99)

    # Pre-ACADIA wallet transactions are legacy v1 with no expiry -- both a
    # plain send and a z_sendmany between transparent addresses.
    taddr1 = await n1.rpc.getnewaddress()
    taddr2 = await n2.rpc.getnewaddress()
    funded_a, forwarded_a = await _send_pair(n0, n2, taddr1, taddr2)
    # Fund the shield input for the post-boundary phase while still here.
    shield_from = await n0.rpc.getnewaddress()
    await n0.rpc.sendtoaddress(shield_from, Decimal("10"))
    await sync_mempools(nodes)
    await n0.mine(1)
    await _sync_all(nodes)

    for txid in (funded_a, forwarded_a):
        raw = await n0.rpc.getrawtransaction(txid, 1)
        assert raw["version"] == 1
        assert raw["overwintered"] is False
        assert "expiryheight" not in raw
        assert "versiongroupid" not in raw
    assert await n1.rpc.z_getbalance(taddr1) == Decimal("0.5")
    assert await n2.rpc.getbalance() == Decimal("0.4999")

    # Park at the last pre-ACADIA tip: the next block activates the upgrade,
    # so everything built from here on follows the v4 Sapling rules.
    await n0.mine(ACADIA_HEIGHT - 1 - await n0.rpc.getblockcount())
    await _sync_all(nodes)
    assert await _branch_ids(n0) == (SPROUT_BRANCH_ID, ACADIA_BRANCH_ID)

    # expiryheight is accepted now, within [0, 500000000) and past the
    # expiring-soon margin of the next block.
    raw_hex = await n0.rpc.createrawtransaction([], {}, 0, 499999999)
    assert raw_hex
    for bad_expiry in (-1, 500000000):
        with pytest.raises(JSONRPCError, match="must be nonnegative and less than"):
            await n0.rpc.createrawtransaction([], {}, 0, bad_expiry)
    min_allowed = ACADIA_HEIGHT + EXPIRING_SOON_THRESHOLD
    with pytest.raises(JSONRPCError, match=f"at least {min_allowed} to avoid"):
        await n0.rpc.createrawtransaction([], {}, 0, ACADIA_HEIGHT)

    # The same wallet flows now produce v4 transactions, plus the first
    # possible Sprout shield.
    taddr1b = await n1.rpc.getnewaddress()
    taddr3 = await n2.rpc.getnewaddress()
    zaddr3 = await n2.rpc.z_getnewaddress("sprout")
    n2_balance_before = await n2.rpc.getbalance()
    # Shield first: a later sendtoaddress is free to pick the 10-coin UTXO
    # sitting on shield_from as its input and would leave the shield unfunded.
    opid = await n0.rpc.z_sendmany(
        shield_from, [{"address": zaddr3, "amount": Decimal("9.9999")}]
    )
    shielded_b = await wait_and_assert_operationid_status(n0, opid)
    assert shielded_b is not None
    funded_b, forwarded_b = await _send_pair(n0, n2, taddr1b, taddr3)
    await sync_mempools(nodes)
    await n0.mine(1)
    await _sync_all(nodes)

    info = await n0.rpc.getblockchaininfo()
    assert await _branch_ids(n0) == (ACADIA_BRANCH_ID, ACADIA_BRANCH_ID)
    assert info["size_on_disk"] > 0

    for txid in (funded_b, forwarded_b, shielded_b):
        raw = await n0.rpc.getrawtransaction(txid, 1)
        assert raw["version"] == 4
        assert raw["overwintered"] is True
        assert raw["versiongroupid"] == SAPLING_VERSION_GROUP_ID
        assert raw["expiryheight"] == ACADIA_HEIGHT + DEFAULT_EXPIRY_DELTA
    assert await n1.rpc.z_getbalance(taddr1b) == Decimal("0.5")
    assert await n2.rpc.getbalance() == n2_balance_before + Decimal("0.4999")
    assert await n2.rpc.z_getbalance(zaddr3) == Decimal("9.9999")
