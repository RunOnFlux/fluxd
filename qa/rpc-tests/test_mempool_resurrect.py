"""Mined transactions return to the mempool when their block is disconnected."""

from fluxtest.node import FluxNode


async def test_mempool_resurrect(funded_node: FluxNode) -> None:
    node = funded_node
    address = await node.rpc.getnewaddress()

    txids = {
        await node.rpc.sendtoaddress(address, 100),
        await node.rpc.sendtoaddress(address, 200),
    }

    # Mine them in; the mempool empties and they confirm.
    block = (await node.mine(1))[0]
    assert set(await node.rpc.getrawmempool()) == set()
    for txid in txids:
        assert (await node.rpc.gettransaction(txid))["confirmations"] > 0

    # Disconnecting that block resurrects the transactions into the mempool.
    await node.rpc.invalidateblock(block)
    assert set(await node.rpc.getrawmempool()) == txids
    for txid in txids:
        assert (await node.rpc.gettransaction(txid))["confirmations"] == 0

    # Re-mining confirms them again.
    await node.mine(1)
    assert set(await node.rpc.getrawmempool()) == set()
    for txid in txids:
        assert (await node.rpc.gettransaction(txid))["confirmations"] > 0
