"""Check the mininode CTransaction round-trips the daemon's raw transaction bytes."""

import io

from conftest import COINBASE_MATURITY, NodeFactory
from fluxtest.mininode import CTransaction
from zhelpers import shielded_args


async def test_ctransaction_roundtrip(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=shielded_args(1))  # ACADIA active -> v4 format
    await node.mine(COINBASE_MATURITY + 2)
    utxo = next(u for u in await node.rpc.listunspent(1) if u["generated"] and u["spendable"])
    raw = await node.rpc.createrawtransaction(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}],
        {await node.rpc.getnewaddress(): utxo["amount"] - 1},
    )
    tx = CTransaction()
    tx.deserialize(io.BytesIO(bytes.fromhex(raw)))
    assert tx.serialize().hex() == raw, "CTransaction did not round-trip the raw bytes"
    assert tx.fOverwintered is True
    assert tx.nVersion == 4
