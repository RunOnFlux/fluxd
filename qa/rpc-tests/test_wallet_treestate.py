"""A chained-joinsplit send survives the treestate changing mid-build.

z_sendmany consuming three notes needs two joinsplits (two inputs each). If a
block carrying another joinsplit is mined while the second joinsplit is still
being assembled, the global treestate -- and therefore the anchor the change
note is witnessed against -- moves underneath it. This drives exactly that race
(mine Tx1 once Tx2 reaches "executing") and asserts Tx2 still completes, guarding
the historical "Witness for spendable note does not have same anchor as change
input" regression.

Funding uses -regtestprotectcoinbase, so coinbase can only be shielded; a
coinbase shield forbids change, so each note is the whole 150 UTXO less the fee
(not upstream Zcash's 9.9999), and all amounts are computed from that.
"""

import asyncio
from decimal import Decimal

from conftest import COINBASE_MATURITY, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from zhelpers import shielded_args, wait_and_assert_operationid_status

DEFAULT_FEE = Decimal("0.0001")
PROTECT_ARGS = ["-regtestprotectcoinbase", "-debug=zrpc"]


async def _coinbase_addrs(node: FluxNode, count: int) -> list[tuple[str, Decimal]]:
    """The ``count`` smallest spendable coinbase UTXOs as (address, value).

    The smallest generated outputs are ordinary 150 coinbases (never the larger
    block-1 premine); each pays a fresh address holding one UTXO."""
    gens = sorted(
        (u for u in await node.rpc.listunspent() if u["generated"] and u["spendable"]),
        key=lambda u: u["amount"],
    )
    assert len(gens) >= count, f"need {count} coinbase utxos, have {len(gens)}"
    return [(u["address"], u["amount"]) for u in gens[:count]]


async def _sync_to(nodes: list[FluxNode], tip_node: FluxNode) -> None:
    """Pull every other node's clock up to ``tip_node``'s tip, then sync blocks."""
    tip = await tip_node.rpc.getbestblockhash()
    tip_time = (await tip_node.rpc.getblock(tip))["time"]
    for node in nodes:
        if node is not tip_node:
            await node.set_mocktime_at_least(tip_time)
    await sync_blocks(nodes)


async def test_wallet_treestate(node_factory: NodeFactory) -> None:
    owner = await node_factory(0, extra_args=shielded_args(1, PROTECT_ARGS))
    miner = await node_factory(1, extra_args=shielded_args(1, PROTECT_ARGS))
    receiver = await node_factory(2, extra_args=shielded_args(1, PROTECT_ARGS))
    nodes = [owner, miner, receiver]
    await connect_nodes_bi(owner, miner)
    await connect_nodes_bi(miner, receiver)
    await connect_nodes_bi(owner, receiver)

    await owner.mine(COINBASE_MATURITY)
    await _sync_to(nodes, owner)
    await miner.mine(COINBASE_MATURITY + 1)  # mature owner's coinbase
    await _sync_to(nodes, miner)

    zaddr = await owner.rpc.z_getnewaddress("sprout")
    coinbases = await _coinbase_addrs(owner, 4)
    note_value = coinbases[0][1] - DEFAULT_FEE  # 149.9999

    # Three separate coinbase shields make three notes (forcing two joinsplits
    # in the consuming tx below). owner mines its own shields, so the tx is in
    # the mining node's mempool without a cross-node sync.
    for addr, _ in coinbases[:3]:
        opid = await owner.rpc.z_sendmany(addr, [{"address": zaddr, "amount": note_value}])
        await wait_and_assert_operationid_status(owner, opid)
        await owner.mine(1)
        await _sync_to(nodes, owner)
    assert Decimal(await owner.rpc.z_getbalance(zaddr)) == note_value * 3

    # Tx1: a joinsplit that will be mined mid-build to move the treestate.
    rzaddr = await receiver.rpc.z_getnewaddress("sprout")
    tx1 = await owner.rpc.z_sendmany(coinbases[3][0], [{"address": rzaddr, "amount": note_value}])
    await wait_and_assert_operationid_status(owner, tx1)

    # Tx2: consumes all three notes (two joinsplits) with no change.
    total = note_value * 3
    recipients = [
        {"address": await receiver.rpc.z_getnewaddress("sprout"), "amount": Decimal("300")},
        {
            "address": await receiver.rpc.z_getnewaddress("sprout"),
            "amount": total - DEFAULT_FEE - Decimal("300"),
        },
    ]
    tx2 = await owner.rpc.z_sendmany(zaddr, recipients)

    # Once Tx2 is executing, mine Tx1 to change the treestate beneath it.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 60
    while True:
        status = (await owner.rpc.z_getoperationstatus([tx2]))[0]["status"]
        if status == "executing":
            break
        assert loop.time() < deadline, f"Tx2 never reached executing (last {status!r})"
        await asyncio.sleep(0.2)
    await sync_mempools([owner, miner])
    await miner.mine(1)
    await _sync_to(nodes, miner)

    await wait_and_assert_operationid_status(owner, tx2)
    assert Decimal(await owner.rpc.z_getbalance(zaddr)) == 0
