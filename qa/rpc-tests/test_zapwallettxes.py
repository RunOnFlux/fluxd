"""Test -zapwallettxes: a restart drops unconfirmed wallet txs, keeps confirmed."""

import pytest
from conftest import POW_ARGS
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError


async def test_zapwallettxes(funded_node: FluxNode) -> None:
    node = funded_node
    address = await node.rpc.getnewaddress()

    confirmed = await node.rpc.sendtoaddress(address, 100)
    await node.mine(1)
    unconfirmed = await node.rpc.sendtoaddress(address, 200)

    # Both are in the wallet before the zap.
    assert (await node.rpc.gettransaction(confirmed))["txid"] == confirmed
    assert (await node.rpc.gettransaction(unconfirmed))["txid"] == unconfirmed

    await node.restart(extra_args=[*POW_ARGS, "-zapwallettxes=1"])

    # The confirmed transaction survives; the unconfirmed one is gone.
    assert (await node.rpc.gettransaction(confirmed))["txid"] == confirmed
    with pytest.raises(JSONRPCError):
        await node.rpc.gettransaction(unconfirmed)
