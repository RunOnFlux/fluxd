"""Regression test for the mining null coinbase-script guard.

When fluxd has no coinbase-script provider (no wallet and no -mineraddress,
e.g. -disablewallet), ScriptForMining yields a null CReserveScript. The mining
RPCs must report a clean error rather than dereference it and crash.
"""

import pytest
from conftest import NodeFactory
from fluxtest.rpc import JSONRPCError

RPC_INTERNAL_ERROR = -32603


async def test_generate_without_wallet_errors_cleanly(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=["-disablewallet"])

    with pytest.raises(JSONRPCError) as exc_info:
        await node.rpc.generate(1)

    assert exc_info.value.code == RPC_INTERNAL_ERROR
    assert "No coinbase script available" in str(exc_info.value)

    # The daemon must still be alive (pre-fix this dereferenced null and crashed).
    assert await node.rpc.getblockcount() == 0


async def test_generate_with_wallet_mints(node_factory: NodeFactory) -> None:
    node = await node_factory(1)
    await node.rpc.generate(1)
    assert await node.rpc.getblockcount() == 1
