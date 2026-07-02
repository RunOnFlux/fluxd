"""Sprout and Sapling value-pool turnstile violations (ZIP 209).

The experimental -developersetpoolsizezero flag zeroes the node's in-memory
shielded pool sizes at launch (and enables ZIP209 monitoring on regtest), so an
unshielding transaction then drives the pool negative from that node's point of
view. Such a transaction must be excluded from the node's own block templates
(CreateNewBlock logs the violation and skips it), and a block another node
mines containing it must be rejected (ConnectBlock turnstile DoS) -- the node
holds its old tip while the rest of the network moves on. Relaunched without
the override, the node loads the real pool sizes from disk and accepts the
same block.

The node's debug.log is read while its daemon is stopped, mirroring the
original test, so buffered log lines are flushed before the check.
"""

import asyncio
from decimal import Decimal

import pytest
from conftest import NodeFactory
from fluxtest.network import bump_clocks, connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from zhelpers import shielded_args, wait_and_assert_operationid_status

BASE_ARGS = shielded_args(1)
TURNSTILE_ARGS = [*BASE_ARGS, "-experimentalfeatures", "-developersetpoolsizezero"]


async def _pool_balance(node: FluxNode, name: str) -> Decimal:
    pools = (await node.rpc.getblockchaininfo())["valuePools"]
    matching = [pool for pool in pools if pool["id"] == name]
    assert matching, f"pool {name!r} not found"
    return matching[0]["chainValue"]


async def _relaunch(n0: FluxNode, others: list[FluxNode], args: list[str]) -> None:
    """Restart node 0 with new args and rewire it into the network."""
    await n0.restart(args)
    for peer in others:
        await connect_nodes_bi(n0, peer)
    await bump_clocks([n0, *others])


async def _wait_invalid_tip(node: FluxNode, blockhash: str, timeout: float = 30) -> None:
    """Wait until ``node`` has seen ``blockhash`` and judged it invalid."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        tips = await node.rpc.getchaintips()
        if any(tip["hash"] == blockhash and tip["status"] == "invalid" for tip in tips):
            return
        if loop.time() > deadline:
            raise AssertionError(f"{blockhash} never showed up as an invalid tip: {tips}")
        await asyncio.sleep(0.25)


def _log_text(node: FluxNode) -> str:
    return (node.datadir / "regtest" / "debug.log").read_text()


@pytest.mark.parametrize("pool", ["sprout", "sapling"])
async def test_turnstile(node_factory: NodeFactory, pool: str) -> None:
    n0 = await node_factory(0, extra_args=BASE_ARGS)
    n1 = await node_factory(1, extra_args=BASE_ARGS)
    n2 = await node_factory(2, extra_args=BASE_ARGS)
    nodes = [n0, n1, n2]
    await connect_nodes_bi(n0, n1)
    await connect_nodes_bi(n1, n2)
    await connect_nodes_bi(n0, n2)

    await n0.mine(101)
    await bump_clocks(nodes)
    await sync_blocks(nodes)

    # Node 0 shields 10 into the pool under test (fund an ordinary output
    # first -- a coinbase input forbids change -- and use a zero fee so the
    # pool value is exact).
    dest_addr = await n0.rpc.z_getnewaddress(pool)
    taddr0 = await n0.rpc.getnewaddress()
    await n0.rpc.sendtoaddress(taddr0, Decimal("10"))
    await n0.mine(1)
    opid = await n0.rpc.z_sendmany(taddr0, [{"address": dest_addr, "amount": Decimal("10")}], 1, 0)
    await wait_and_assert_operationid_status(n0, opid)
    await sync_mempools(nodes)
    await n0.mine(1)
    await bump_clocks(nodes)
    await sync_blocks(nodes)
    assert await n0.rpc.z_getbalance(dest_addr) == Decimal("10")
    for node in nodes:
        assert await _pool_balance(node, pool) == Decimal("10")

    # Relaunch node 0 with the pool sizes overridden to zero: any unshielding
    # is now a turnstile violation from its point of view.
    await _relaunch(n0, [n1, n2], TURNSTILE_ARGS)
    assert await _pool_balance(n0, pool) == Decimal("0")
    assert await _pool_balance(n1, pool) == Decimal("10")
    assert await _pool_balance(n2, pool) == Decimal("10")

    # Node 0 creates the unshielding transaction; it relays everywhere.
    opid = await n0.rpc.z_sendmany(dest_addr, [{"address": taddr0, "amount": Decimal("1")}], 1, 0)
    mytxid = await wait_and_assert_operationid_status(n0, opid)
    assert mytxid is not None
    await sync_mempools(nodes)
    for node in nodes:
        assert mytxid in await node.rpc.getrawmempool()

    # Node 0's own miner must exclude it from the block template.
    count = await n0.rpc.getblockcount()
    await n0.mine(1)
    await bump_clocks(nodes)
    await sync_blocks(nodes)
    block = await n0.rpc.getblock(await n0.rpc.getbestblockhash())
    assert len(block["tx"]) == 1
    assert block["height"] == count + 1

    # Stop the daemon to flush the log and verify the miner-side exclusion.
    await n0.stop_daemon()
    exclusion = f"CreateNewBlock(): tx {mytxid} appears to violate {pool.capitalize()} turnstile"
    assert exclusion in _log_text(n0)
    await _relaunch(n0, [n1, n2], TURNSTILE_ARGS)
    await sync_blocks(nodes)

    # Node 1 mines the unshielding transaction; nodes 1 and 2 accept the
    # block, node 0 must reject it and hold its tip.
    oldhash = await n0.rpc.getbestblockhash()
    await n1.mine(1)
    newhash = await n1.rpc.getbestblockhash()
    assert mytxid in (await n1.rpc.getblock(newhash))["tx"]
    await bump_clocks(nodes)
    await sync_blocks([n1, n2])
    assert await n1.rpc.getrawmempool() == []
    assert await n2.rpc.getrawmempool() == []

    await _wait_invalid_tip(n0, newhash)
    assert await n0.rpc.getbestblockhash() == oldhash
    # The wallet re-accepted its own transaction on the relaunch.
    assert mytxid in await n0.rpc.getrawmempool()
    assert await _pool_balance(n0, pool) == Decimal("0")
    assert await _pool_balance(n1, pool) == Decimal("9")
    assert await _pool_balance(n2, pool) == Decimal("9")

    # Verify the rejection in the stopped node's log.
    await n0.stop_daemon()
    log = _log_text(n0)
    assert f"ConnectBlock(): turnstile violation in {pool.capitalize()} shielded value pool" in log
    assert f"InvalidChainFound: invalid block={newhash}" in log
    assert f"ConnectTip(): ConnectBlock {newhash} failed" in log

    # Relaunched without the override, the node reads the real pool sizes from
    # disk and accepts the block it previously rejected.
    await _relaunch(n0, [n1, n2], BASE_ARGS)
    await sync_blocks(nodes)
    assert await n0.rpc.getbestblockhash() == newhash
