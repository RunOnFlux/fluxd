"""prioritisetransaction promotes a low-priority tx into the block template.

Two nodes run with a tiny 11 kB block size and a 7 kB priority area so that an
11 kB block holds only ~50 transactions. node0 mines a long chain, then floods
its mempool with hundreds of small sends so the mempool holds far more
transactions than one block can mine. A newer, low-value transaction
(``priority_tx_0``) is therefore crowded out of the block template by the older
queued sends.

``prioritisetransaction`` then raises that transaction's mining priority and fee
delta. The template does not refresh immediately -- ``getblocktemplate`` only
rebuilds when the tip changes, or when the mempool's transaction-update counter
moves and more than five seconds have elapsed since the last build (see
``rpc/mining.cpp`` line 652-653, where the staleness check uses ``GetTime()``,
which honours mocktime). After a fresh mempool entry and a >5 s mocktime
advance, the prioritised transaction appears in the template, and a block mined
on node0 includes it.

A transaction prioritised only on node1 is *not* mined into node0's block: the
fee/priority delta is local mempool state, so node0's template never sees it.
Mining a block on node1 then confirms that transaction there.
"""

from decimal import Decimal

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes, sync_blocks, sync_mempools
from fluxtest.node import FluxNode

# satoshis per FLUX; prioritisetransaction's fee delta is an integer satoshi amount.
COIN = 100000000

# Tiny blocks (~50 txs each) over a flooded mempool are what crowd a newer,
# low-value send out of the template; -relaypriority/-printpriority mirror the
# legacy mining configuration that exercises the priority code path.
NODE_ARGS = [
    *POW_ARGS,
    "-blockprioritysize=7000",
    "-blockmaxsize=11000",
    "-maxorphantx=1000",
    "-relaypriority=true",
    "-printpriority=1",
]

# Enough matured coinbases to fund the mempool flood; well past the 101-block
# maturity floor and large enough that one 11 kB block cannot drain the backlog.
CHAIN_HEIGHT = 501

# Small sends queued ahead of the prioritised tx; an 11 kB block mines only ~50,
# so a few hundred queued transactions guarantee the newer low-value tx is
# crowded out until it is prioritised.
FLOOD_COUNT = 900
SEND_AMOUNT = Decimal("0.1")

# getblocktemplate's staleness window: a rebuild needs the mempool-update counter
# to move AND more than five seconds (mocktime) since the last build.
TEMPLATE_STALE_SECONDS = 5


def _in_template(template: dict, txid: str) -> bool:
    return any(tx["hash"] == txid for tx in template["transactions"])


async def _catch_up_clock(follower: FluxNode, miner: FluxNode) -> None:
    """Advance a non-mining node's frozen clock to the miner's tip time.

    A miner's long chain advances its mocktime far past a peer's frozen clock;
    fluxd rejects any block timed more than two hours past the receiver's clock
    (main.cpp line 5400, "time-too-new"), so a frozen follower stalls partway
    through the chain. Pulling its clock up to the miner's tip lets it accept the
    whole chain. Both clocks are then kept in step for later mining."""
    tip_time = (await miner.rpc.getblock(await miner.rpc.getbestblockhash()))["time"]
    await follower.set_mocktime_at_least(tip_time)


async def _wait_for_template(node: FluxNode, txid: str, recipient: str) -> dict:
    """Poll getblocktemplate until ``txid`` appears, driving the daemon's
    refresh by adding a fresh mempool entry and advancing mocktime past the
    five-second staleness window. Mirrors the legacy 30 s poll loop, but the
    clock is frozen so the window is crossed by advancing mocktime instead."""
    for _ in range(30):
        template = await node.rpc.getblocktemplate()
        if _in_template(template, txid):
            return template
        # A new mempool entry bumps the transaction-update counter; the mocktime
        # advance then satisfies the >5 s staleness check on the next call.
        await node.rpc.sendtoaddress(recipient, SEND_AMOUNT)
        await node.advance_mocktime(TEMPLATE_STALE_SECONDS + 1)
    raise AssertionError("prioritised transaction did not appear in getblocktemplate after polling")


async def test_prioritisetransaction(node_factory: NodeFactory) -> None:
    node0 = await node_factory(0, extra_args=NODE_ARGS)
    node1 = await node_factory(1, extra_args=NODE_ARGS)

    # tx priority = sum(input_value_in_satoshis * input_age) / size_in_bytes,
    # so a long chain of matured coinbases gives the flood high priority while a
    # freshly funded, low-value send stays at the back of the queue.
    #
    # node1 is connected only after the long chain exists: a peer relays each
    # block as it is mined, and node1's frozen clock would reject every block
    # timed more than two hours ahead (main.cpp line 5400, "time-too-new"),
    # permanently stalling its tip partway up the chain. Catching node1's clock
    # up first, then connecting, lets it download the whole chain in one pass.
    await node0.mine(CHAIN_HEIGHT)
    await _catch_up_clock(node1, node0)
    await connect_nodes(node1, node0)
    await sync_blocks([node0, node1])

    relayfee = (await node0.rpc.getnetworkinfo())["relayfee"]
    fee_delta = int(3 * relayfee * COIN)

    # Flood node0's mempool with small sends; an 11 kB block mines only ~50, so
    # the backlog dwarfs one block's capacity.
    flood_addr = await node1.rpc.getnewaddress()
    for _ in range(FLOOD_COUNT):
        await node0.rpc.sendtoaddress(flood_addr, SEND_AMOUNT)
    await node0.mine(1)
    await sync_blocks([node0, node1])

    # A newer, low-value send: older queued sends mine first, so this one is
    # unlikely to be templated without prioritisation.
    priority_tx_0 = await node0.rpc.sendtoaddress(await node1.rpc.getnewaddress(), SEND_AMOUNT)
    assert not _in_template(await node0.rpc.getblocktemplate(), priority_tx_0)

    priority_success = await node0.rpc.prioritisetransaction(priority_tx_0, 1000, fee_delta)
    assert priority_success

    # The cached template has not refreshed (no new mempool entry yet), so the
    # prioritised tx is still absent.
    assert not _in_template(await node0.rpc.getblocktemplate(), priority_tx_0)

    # A fresh send bumps the update counter, but the staleness window has not
    # elapsed, so the template is still stale on the immediate next call.
    await node0.rpc.sendtoaddress(await node1.rpc.getnewaddress(), SEND_AMOUNT)
    assert not _in_template(await node0.rpc.getblocktemplate(), priority_tx_0)

    # After advancing the frozen clock past the staleness window, the rebuilt
    # template promotes the prioritised tx.
    await _wait_for_template(node0, priority_tx_0, await node1.rpc.getnewaddress())

    # A transaction prioritised only on node1 is local mempool state; node0's
    # template never sees the delta, so it should not be mined in node0's block.
    priority_tx_1 = await node1.rpc.sendtoaddress(await node0.rpc.getnewaddress(), SEND_AMOUNT)
    await node1.rpc.prioritisetransaction(priority_tx_1, 1000, fee_delta)
    await sync_mempools([node0, node1])

    # Mine on node0: the prioritised-on-node0 tx is included; the
    # prioritised-only-on-node1 tx is not.
    blk_hash = (await node0.mine(1))[0]
    block = await node0.rpc.getblock(blk_hash)
    await sync_blocks([node0, node1])

    assert priority_tx_0 in block["tx"]
    assert priority_tx_0 not in await node0.rpc.getrawmempool()

    assert priority_tx_1 in await node0.rpc.getrawmempool()
    assert priority_tx_1 not in block["tx"]

    # node1 mines its own block; its locally prioritised tx is confirmed there.
    # generate builds a fresh block from node1's mempool (it does not reuse the
    # cached getblocktemplate), so the locally prioritised tx is selectable.
    blk_hash_1 = (await node1.mine(1))[0]
    block_1 = await node1.rpc.getblock(blk_hash_1)
    await sync_blocks([node0, node1])

    assert priority_tx_1 not in await node1.rpc.getrawmempool()
    assert priority_tx_1 in block_1["tx"]
