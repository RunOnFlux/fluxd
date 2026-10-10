"""z_shieldcoinbase sweeps coinbase utxos into a shielded address.

Reframed for Flux. Each PoW block pays a fresh single-utxo coinbase address
(upstream regtest reuses one coinbase address), so the limit and locking cases
sweep all coinbase with the "*" wildcard and assert the operation's reported
utxo counts rather than draining one accumulating address. ACADIA gates every
shielded send and is active here, which has two consequences the upstream test
predates: -mempooltxinputlimit (honored only before Overwinter) never applies
while shielding works, and the post-Sapling transaction-size limit is the whole
block, so the upstream pre-Sapling utxo-count split does not happen -- the utxo
limit is exercised through the explicit limit parameter instead. Coinbase is 150
and MAX_MONEY is 440M, so the out-of-range fee probe uses a value above that.
"""

from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args, wait_and_assert_operationid_status

DEFAULT_FEE = Decimal("0.0001")
SHIELD_DEFAULT_LIMIT = 50


async def _smallest_coinbase(node: FluxNode) -> dict:
    """The smallest spendable coinbase UTXO (an ordinary 150, never the premine)."""
    gens = sorted(
        (u for u in await node.rpc.listunspent(1) if u["generated"] and u["spendable"]),
        key=lambda u: u["amount"],
    )
    assert gens, "node has no spendable coinbase outputs"
    return gens[0]


async def _coinbase_count(node: FluxNode) -> int:
    """Number of spendable (matured, unlocked) coinbase UTXOs the wallet holds."""
    return sum(1 for u in await node.rpc.listunspent(1) if u["generated"] and u["spendable"])


async def _sync_to(nodes: list[FluxNode], tip_node: FluxNode) -> None:
    tip = await tip_node.rpc.getbestblockhash()
    tip_time = (await tip_node.rpc.getblock(tip))["time"]
    for node in nodes:
        if node is not tip_node:
            await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


@pytest.mark.parametrize("addr_type", ["sprout", "sapling"])
async def test_wallet_shieldcoinbase(node_factory: NodeFactory, addr_type: str) -> None:
    args = shielded_args(1, ["-debug=zrpcunsafe"])
    owner = await node_factory(0, extra_args=args)
    watcher = await node_factory(1, extra_args=args)
    await connect_nodes_bi(owner, watcher)

    # Enough coinbase to exceed the default 50-utxo shield limit after maturity.
    await owner.mine(COINBASE_MATURITY + 60)
    await _sync_to([owner, watcher], owner)
    zaddr = await owner.rpc.z_getnewaddress(addr_type)

    # Argument validation (each rejected synchronously, before any operation runs).
    cb = await _smallest_coinbase(owner)
    await watcher.rpc.importaddress(cb["address"])
    with pytest.raises(JSONRPCError) as excinfo:  # watch-only: no spending key
        await watcher.rpc.z_shieldcoinbase(cb["address"], zaddr)
    assert "Could not find any coinbase funds to shield" in excinfo.value.error["message"]

    for bad_fee in (Decimal("-1"), Decimal("450000000")):  # negative, then above MAX_MONEY
        with pytest.raises(JSONRPCError) as excinfo:
            await owner.rpc.z_shieldcoinbase("*", zaddr, bad_fee)
        assert "Amount out of range" in excinfo.value.error["message"]

    with pytest.raises(JSONRPCError) as excinfo:  # fee exceeds a single coinbase's value
        await owner.rpc.z_shieldcoinbase(cb["address"], zaddr, Decimal("999"))
    assert "Insufficient coinbase funds" in excinfo.value.error["message"]

    with pytest.raises(JSONRPCError) as excinfo:
        await owner.rpc.z_shieldcoinbase("*", zaddr, Decimal("0.001"), -1)
    assert "Limit on maximum number of utxos cannot be negative" in excinfo.value.error["message"]
    with pytest.raises(JSONRPCError) as excinfo:
        await owner.rpc.z_shieldcoinbase("*", zaddr, Decimal("0.001"), 99999999999999)
    assert "JSON integer out of range" in excinfo.value.error["message"]

    # Shield one coinbase: the whole 150 utxo lands in the zaddr, less the fee.
    one_z = await owner.rpc.z_getnewaddress(addr_type)
    cb = await _smallest_coinbase(owner)
    result = await owner.rpc.z_shieldcoinbase(cb["address"], one_z)
    assert result["shieldingUTXOs"] == 1
    await wait_and_assert_operationid_status(owner, result["opid"])
    await owner.mine(1)
    assert Decimal(await owner.rpc.z_getbalance(one_z)) == cb["amount"] - DEFAULT_FEE

    # The default limit shields at most 50 utxos; the rest are reported remaining.
    n = await _coinbase_count(owner)
    assert n > SHIELD_DEFAULT_LIMIT
    result = await owner.rpc.z_shieldcoinbase("*", zaddr, DEFAULT_FEE)
    assert result["shieldingUTXOs"] == SHIELD_DEFAULT_LIMIT
    assert result["remainingUTXOs"] == n - SHIELD_DEFAULT_LIMIT
    await wait_and_assert_operationid_status(owner, result["opid"])
    await owner.mine(1)

    # An explicit limit overrides the default.
    n = await _coinbase_count(owner)
    limit = 5
    assert n > limit
    result = await owner.rpc.z_shieldcoinbase("*", zaddr, DEFAULT_FEE, limit)
    assert result["shieldingUTXOs"] == limit
    assert result["remainingUTXOs"] == n - limit
    await wait_and_assert_operationid_status(owner, result["opid"])
    await owner.mine(1)

    # A second operation queued behind the first cannot reselect its locked
    # utxos: it sees only what the first left, and reports nothing remaining.
    n = await _coinbase_count(owner)
    assert n > 1
    op1 = await owner.rpc.z_shieldcoinbase("*", zaddr, Decimal("0"), 1)
    assert op1["shieldingUTXOs"] == 1
    op2 = await owner.rpc.z_shieldcoinbase("*", zaddr, Decimal("0"), 0)
    assert op2["shieldingUTXOs"] == n - 1
    assert op2["remainingUTXOs"] == 0
    await wait_and_assert_operationid_status(owner, op1["opid"])
    await wait_and_assert_operationid_status(owner, op2["opid"])
