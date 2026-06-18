"""Test gettxoutsetinfo against the chain's actual coinbase emission.

The original hardcoded zcash's emission; Flux's reward schedule (subsidy plus
foundation/exchange/swap fund outputs at set heights) differs, so the expected
totals are computed from the chain itself rather than hardcoded.
"""

from decimal import Decimal

from conftest import NodeFactory


async def test_gettxoutsetinfo(node_factory: NodeFactory) -> None:
    node = await node_factory(0)
    blocks = 20
    await node.mine(blocks)

    # Sum every coinbase's outputs; with no other transactions this is the
    # whole UTXO set.
    total = Decimal(0)
    txouts = 0
    for height in range(1, blocks + 1):
        block = await node.rpc.getblock(await node.rpc.getblockhash(height))
        coinbase = await node.rpc.getrawtransaction(block["tx"][0], 1)
        total += sum((vout["value"] for vout in coinbase["vout"]), Decimal(0))
        txouts += len(coinbase["vout"])

    info = await node.rpc.gettxoutsetinfo()
    assert info["height"] == blocks
    assert info["transactions"] == blocks
    assert info["txouts"] == txouts
    assert info["total_amount"] == total
    assert len(info["bestblock"]) == 64
    assert len(info["hash_serialized"]) == 64
