"""A node will not accept or relay a transaction that is expiring soon.

A transaction whose expiry height is within a few blocks of the tip is rejected
from the mempool, and one already in the mempool that drifts into that window is
no longer served to peers: a getdata for it is answered with notfound rather
than the transaction. This drives the relay path with a mininode peer.

Reframed for Flux: ACADIA is active (so transactions carry an expiry height) and
PON is off (so mined coinbase funds the wallet); the mininode connects at a
protocol version at least the regtest ACADIA minimum (170007). The expiring-soon
threshold is three blocks, as upstream, so the expiry heights track the tip.
"""

import io
from decimal import Decimal

import pytest
from conftest import NodeFactory
from fluxtest.mininode import (
    CInv,
    CTransaction,
    NodeConn,
    NodeConnCB,
    msg_getdata,
    msg_inv,
    msg_mempool,
    msg_notfound,
    msg_tx,
)
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError
from zhelpers import shielded_args

PROTOCOL_VERSION = 170021  # at least the regtest ACADIA minimum of 170007

TIP = 110
SOON_EXPIRY = TIP + 3  # within the 3-block threshold at the tip: rejected
OK_EXPIRY = TIP + 4  # just outside the threshold at the tip: accepted
# After one more block the tip is TIP + 1, so OK_EXPIRY drifts into the window;
# the minimum non-expiring-soon height is then (TIP + 1) + 1 + 3.
MIN_AFTER = TIP + 5


class _RelayNode(NodeConnCB):
    def __init__(self) -> None:
        super().__init__()
        self.last_inv: msg_inv | None = None
        self.last_tx: msg_tx | None = None
        self.last_notfound: msg_notfound | None = None

    def on_inv(self, conn: NodeConn, message: msg_inv) -> None:
        self.last_inv = message

    def on_tx(self, conn: NodeConn, message: msg_tx) -> None:
        self.last_tx = message

    def on_notfound(self, conn: NodeConn, message: msg_notfound) -> None:
        self.last_notfound = message


async def _bump_clocks(nodes: list[FluxNode]) -> None:
    latest = 0
    for node in nodes:
        latest = max(latest, (await node.rpc.getblock(await node.rpc.getbestblockhash()))["time"])
    for node in nodes:
        await node.set_mocktime_at_least(latest)


async def _create_tx(
    node: FluxNode, utxo: dict, address: str, amount: Decimal, expiry: int
) -> CTransaction:
    """Build, set the expiry height of, and sign a transaction spending ``utxo``."""
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


async def test_p2p_txexpiringsoon(node_factory: NodeFactory) -> None:
    args = shielded_args(1)
    n0 = await node_factory(0, extra_args=args)
    n1 = await node_factory(1, extra_args=args)
    n2 = await node_factory(2, extra_args=args)
    await connect_nodes_bi(n0, n1)
    await connect_nodes_bi(n0, n2)

    cb = _RelayNode()
    conn = NodeConn("127.0.0.1", n0.p2p_port, cb, protocol_version=PROTOCOL_VERSION)
    await conn.connect()
    await cb.wait_for_verack()
    peer = next(p for p in await n0.rpc.getpeerinfo() if "mininodetester" in p["subver"])
    assert peer["version"] == PROTOCOL_VERSION
    assert peer["banscore"] == 0

    # Build a chain that node2 shares, then isolate node2 (a restart drops its
    # peers) and let it mine one empty block, so it is one ahead with no mempool.
    await n0.mine(TIP)
    await _bump_clocks([n0, n1, n2])
    await sync_blocks([n0, n1, n2])
    address = await n0.rpc.getnewaddress()
    coinbases = sorted(
        (u for u in await n0.rpc.listunspent(1) if u["generated"] and u["spendable"]),
        key=lambda u: u["amount"],
    )[:3]
    amount = coinbases[0]["amount"] - Decimal("0.0001")

    await n2.restart()
    await n2.mine(1)
    assert await n0.rpc.getblockcount() == TIP
    assert await n2.rpc.getblockcount() == TIP + 1

    # An expiring-soon transaction is dropped: it never reaches any mempool.
    tx1 = await _create_tx(n0, coinbases[0], address, amount, SOON_EXPIRY)
    conn.send_message(msg_tx(tx1))
    await cb.sync_with_ping()
    assert await n0.rpc.getrawmempool() == []
    assert await n1.rpc.getrawmempool() == []

    # A transaction just outside the window is accepted and relayed to node1.
    tx2 = await _create_tx(n0, coinbases[1], address, amount, OK_EXPIRY)
    conn.send_message(msg_tx(tx2))
    await cb.sync_with_ping()
    await sync_mempools([n0, n1])
    assert await n0.rpc.getrawmempool() == [tx2.hash]
    assert await n1.rpc.getrawmempool() == [tx2.hash]

    # The node advertises tx2 in response to a mempool request and serves it.
    cb.last_inv = None
    conn.send_message(msg_mempool())
    await cb.sync_with_ping()
    assert cb.last_inv is not None
    assert [inv.hash for inv in cb.last_inv.inv] == [tx2.sha256]

    cb.last_tx = None
    getdata = msg_getdata([CInv(1, tx2.sha256)])
    conn.send_message(getdata)
    await cb.sync_with_ping()
    assert cb.last_tx is not None
    cb.last_tx.tx.rehash()
    assert cb.last_tx.tx.sha256 == tx2.sha256

    # Rejoin node2: node0 and node1 reorg onto its one-longer chain, leaving tx2
    # in their mempools but now within the expiring-soon window.
    await connect_nodes_bi(n0, n2)
    await _bump_clocks([n0, n1, n2])
    await sync_blocks([n0, n1, n2])
    assert await n0.rpc.getblockcount() == TIP + 1
    assert await n0.rpc.getrawmempool() == [tx2.hash]
    assert await n2.rpc.getrawmempool() == []

    # Submitting tx2 now is refused for expiring soon.
    with pytest.raises(JSONRPCError) as excinfo:
        await n2.rpc.sendrawtransaction(tx2.serialize().hex())
    assert (
        f"tx-expiring-soon: expiryheight is {OK_EXPIRY} but should be at least {MIN_AFTER} "
        "to avoid transaction expiring soon" in excinfo.value.error["message"]
    )

    # The node no longer serves tx2: a getdata is answered with notfound.
    cb.last_tx = None
    cb.last_notfound = None
    conn.send_message(msg_getdata([CInv(1, tx2.sha256)]))
    await cb.sync_with_ping()
    assert cb.last_tx is None
    assert cb.last_notfound is not None
    assert [inv.hash for inv in cb.last_notfound.inv] == [tx2.sha256]

    # A fresh, non-expiring transaction is still accepted and served normally.
    tx3 = await _create_tx(n0, coinbases[2], address, amount, 999)
    conn.send_message(msg_tx(tx3))
    await cb.sync_with_ping()
    await sync_mempools([n0, n1])
    cb.last_tx = None
    conn.send_message(msg_getdata([CInv(1, tx3.sha256)]))
    await cb.sync_with_ping()
    assert cb.last_tx is not None
    cb.last_tx.tx.rehash()
    assert cb.last_tx.tx.sha256 == tx3.sha256

    assert set(await n0.rpc.getrawmempool()) == {tx2.hash, tx3.hash}
    assert set(await n1.rpc.getrawmempool()) == {tx2.hash, tx3.hash}
    assert sum(p["banscore"] for p in await n0.rpc.getpeerinfo()) == 0

    await conn.disconnect_node()
