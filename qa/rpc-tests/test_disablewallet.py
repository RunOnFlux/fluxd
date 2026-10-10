"""Exercise the RPC API with -disablewallet.

Non-wallet RPCs must still work when the wallet is disabled. validateaddress
is a pure address check: a mainnet (t3) address is invalid on regtest, a
testnet-prefixed (tm) address is valid.
"""

from conftest import NodeFactory


async def test_validateaddress_without_wallet(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=["-disablewallet"])

    mainnet_addr = await node.rpc.validateaddress("t3b1jtLvxCstdo1pJs9Tjzc5dmWyvGQSZj8")
    assert mainnet_addr["isvalid"] is False

    regtest_addr = await node.rpc.validateaddress("tmGqwWtL7RsbxikDSN26gsbicxVr2xJNe86")
    assert regtest_addr["isvalid"] is True
