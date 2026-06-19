"""getblocktemplate long-polling wakes on tip and mempool changes.

A client calls ``getblocktemplate({"longpollid": <id>})``; the RPC blocks until
the watched chain tip changes (woken immediately by ``cvBlockChange``) or, after
a one-minute timeout that then re-checks every ten seconds, the mempool's
transaction counter advances. It then returns a fresh template carrying a new
longpollid (``<tipHash><nTransactionsUpdatedLast>``).

Each legacy scenario is preserved: the longpollid is stable while nothing
happens; a long-poll keeps blocking when idle; it wakes when a peer mines a
block, when this node mines a block itself, and when a new transaction enters
the mempool. getblocktemplate refuses on an unconnected node, so two connected
PoW-mode nodes are used throughout.
"""

import asyncio
from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode

# A whole coinbase output is spent less a normal-sized fee, so the spend is never
# rejected by the absurd-fee check that a small hardcoded output would trip on
# Flux's ~150 FLUX coinbases.
FEE = Decimal("0.0001")

# The longpoll re-checks the mempool only after a one-minute timeout and then
# every ten seconds, so a transaction-driven wake can take well over a minute.
TX_WAKE_TIMEOUT = 90.0
# A block change wakes the longpoll immediately; this is only a generous ceiling.
BLOCK_WAKE_TIMEOUT = 30.0


async def _longpoll(node: FluxNode, longpollid: str) -> dict:
    """Issue the blocking long-poll call and return its fresh template."""
    return await node.rpc.getblocktemplate({"longpollid": longpollid})


async def _assert_still_blocking(task: asyncio.Task, seconds: float) -> None:
    """Assert the long-poll task is still pending after a short wait."""
    done, _ = await asyncio.wait({task}, timeout=seconds)
    assert not done, "long-poll returned while the chain and mempool were idle"


async def _await_wake(task: asyncio.Task, timeout: float) -> dict:
    """Wait for the long-poll task to return, failing if it stays blocked."""
    return await asyncio.wait_for(task, timeout)


async def _spend_a_coinbase(node: FluxNode) -> str:
    """Broadcast a raw spend of one spendable coinbase, returning its txid.

    Broadcasting bumps the mempool's transaction-updated counter, which is what
    a long-poll wakes on. listunspent also surfaces the unsignable P2SH fund
    outputs (spendable False); those are filtered out so the spend always signs.
    """
    utxo = next(u for u in await node.rpc.listunspent(1) if u["spendable"])
    address = await node.rpc.getnewaddress()
    rawtx = await node.rpc.createrawtransaction(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        {address: utxo["amount"] - FEE},
    )
    signed = await node.rpc.signrawtransaction(rawtx)
    assert signed["complete"] is True
    return await node.rpc.sendrawtransaction(signed["hex"])


async def test_longpoll_wakes_on_tip_and_mempool_changes(node_factory: NodeFactory) -> None:
    # getblocktemplate refuses on an unconnected node, so two peers are wired up;
    # both run in PoW mode so node0's coinbases fund its wallet for the tx test.
    node0 = await node_factory(0, extra_args=POW_ARGS)
    node1 = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(node0, node1)
    await node0.mine(COINBASE_MATURITY + 1)  # leave IBD and mature block 1's coinbase
    await sync_blocks([node0, node1])

    template = await node0.rpc.getblocktemplate()
    longpollid = template["longpollid"]
    assert longpollid

    # The longpollid is stable across successive calls while nothing changes.
    again = await node0.rpc.getblocktemplate()
    assert again["longpollid"] == longpollid

    # A long-poll on the current id keeps blocking while the chain and mempool
    # are idle.
    idle_task = asyncio.create_task(_longpoll(node0, longpollid))
    await _assert_still_blocking(idle_task, seconds=5.0)

    # It wakes once a peer mines a block (the watched tip changes).
    await node1.mine(1)
    await sync_blocks([node0, node1])
    woken = await _await_wake(idle_task, BLOCK_WAKE_TIMEOUT)
    assert woken["longpollid"] != longpollid

    # It wakes when this node mines a block itself.
    longpollid = woken["longpollid"]
    self_task = asyncio.create_task(_longpoll(node0, longpollid))
    await _assert_still_blocking(self_task, seconds=2.0)
    await node0.mine(1)
    await sync_blocks([node0, node1])
    woken = await _await_wake(self_task, BLOCK_WAKE_TIMEOUT)
    assert woken["longpollid"] != longpollid

    # It wakes when a new transaction enters the mempool. The tip never changes
    # here, so the wake comes only from the post-timeout mempool re-check. The
    # node's clock is frozen, and the template is only rebuilt for a mempool
    # change once more than five seconds have elapsed since the prior build
    # (GetTime() reads the frozen mocktime); advancing the clock past that guard
    # lets the wake return a freshly built template with a new longpollid.
    longpollid = woken["longpollid"]
    await node0.advance_mocktime(60)
    tx_task = asyncio.create_task(_longpoll(node0, longpollid))
    txid = await _spend_a_coinbase(node0)
    assert txid in set(await node0.rpc.getrawmempool())
    woken = await _await_wake(tx_task, TX_WAKE_TIMEOUT)
    assert woken["longpollid"] != longpollid

    # A long-poll on the now-current id again blocks, confirming the returned id
    # is a fresh, not-yet-satisfied watch point.
    blocking_task = asyncio.create_task(_longpoll(node0, woken["longpollid"]))
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(blocking_task), timeout=5.0)
    blocking_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await blocking_task
