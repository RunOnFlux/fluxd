"""Relaying an expired transaction is penalized only once it is truly expired.

A transaction that has only just expired (its expiry height equals the current
tip) is rejected without raising the peer's ban score, since an honest peer can
race the chain tip. Once it has been expired for more than that one block, the
same transaction costs the peer ban score.
"""

import io
from decimal import Decimal

from conftest import NodeFactory
from fluxtest.mininode import CTransaction, NodeConn, NodeConnCB, msg_tx
from fluxtest.node import FluxNode
from zhelpers import shielded_args

PROTOCOL_VERSION = 170021  # at least the regtest ACADIA minimum of 170006
TIP = 110  # the tip when the transaction is first sent; expiry is set to match


async def _create_tx(
    node: FluxNode, utxo: dict, address: str, amount: Decimal, expiry: int
) -> CTransaction:
    raw = await node.rpc.createrawtransaction(
        [{"txid": utxo["txid"], "vout": utxo["vout"]}], {address: amount}
    )
    tx = CTransaction()
    tx.deserialize(io.BytesIO(bytes.fromhex(raw)))
    tx.nExpiryHeight = expiry
    signed = await node.rpc.signrawtransaction(tx.serialize().hex())
    assert signed["complete"] is True
    tx = CTransaction()
    tx.deserialize(io.BytesIO(bytes.fromhex(signed["hex"])))
    tx.rehash()
    return tx


async def _banscore(node: FluxNode) -> int:
    peer = next(p for p in await node.rpc.getpeerinfo() if "mininodetester" in p["subver"])
    return peer["banscore"]


async def test_p2p_txexpiry_dos(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=shielded_args(1))
    cb = NodeConnCB()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb, protocol_version=PROTOCOL_VERSION)
    await conn.connect()
    await cb.wait_for_verack()
    assert await _banscore(node) == 0

    await node.mine(TIP)
    utxo = min(
        (u for u in await node.rpc.listunspent(1) if u["generated"] and u["spendable"]),
        key=lambda u: u["amount"],
    )
    address = await node.rpc.getnewaddress()
    spendtx = await _create_tx(node, utxo, address, utxo["amount"] - Decimal("0.0001"), TIP)

    # Expiry height equals the tip, so the transaction has only just expired:
    # rejected, but the peer keeps a ban score of zero.
    conn.send_message(msg_tx(spendtx))
    await cb.sync_with_ping()
    assert await _banscore(node) == 0

    # One more block clears the reject cache and the transaction is now expired
    # by more than a block, so resending it costs the peer ban score.
    await node.mine(1)
    conn.send_message(msg_tx(spendtx))
    await cb.sync_with_ping()
    assert await _banscore(node) == 10

    await conn.disconnect_node()
