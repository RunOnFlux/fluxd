"""The node drops and rejects peers whose protocol version predates the upgrade.

Where upstream stages Overwinter then Sapling as two boundaries, Flux activates
both at the single ACADIA upgrade, so there is one. Below it a peer at an older
protocol version stays connected; once ACADIA activates, a peer below its
required version (170006 on regtest) is disconnected on its next message and a
new one is rejected on connect, while peers at or above the version stay.
"""

import asyncio

from conftest import POW_ARGS, NodeFactory
from fluxtest.mininode import (
    OVERWINTER_PROTO_VERSION,
    SAPLING_PROTO_VERSION,
    NodeConn,
    NodeConnCB,
    msg_ping,
    msg_reject,
)
from fluxtest.node import FluxNode

BELOW = OVERWINTER_PROTO_VERSION  # 170003, below the regtest ACADIA minimum
AT = SAPLING_PROTO_VERSION  # 170006, exactly the regtest ACADIA minimum
ACADIA_HEIGHT = 10
N = 3  # peers per version tier


class _RejectNode(NodeConnCB):
    def __init__(self) -> None:
        super().__init__()
        self.last_reject: msg_reject | None = None

    def on_reject(self, conn: NodeConn, message: msg_reject) -> None:
        self.last_reject = message


async def _count(node: FluxNode, version: int) -> int:
    return sum(1 for p in await node.rpc.getpeerinfo() if p["version"] == version)


async def _wait_count(node: FluxNode, version: int, expected: int, timeout: float = 30) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while await _count(node, version) != expected:
        if loop.time() > deadline:
            raise AssertionError(
                f"version {version}: wanted {expected} peers, have {await _count(node, version)}"
            )
        await asyncio.sleep(0.1)


async def _connect(node: FluxNode, version: int) -> tuple[NodeConn, _RejectNode]:
    cb = _RejectNode()
    conn = NodeConn("127.0.0.1", node.p2p_port, cb, protocol_version=version)
    await conn.connect()
    return conn, cb


async def test_p2p_nu_peer_management(node_factory: NodeFactory) -> None:
    node = await node_factory(
        0, extra_args=[*POW_ARGS, f"-acadiaactivation={ACADIA_HEIGHT}", "-whitelist=127.0.0.1"]
    )

    conns = []
    for version in (BELOW, AT):
        for _ in range(N):
            conn, cb = await _connect(node, version)
            await cb.wait_for_verack()
            conns.append((conn, cb))

    # Below ACADIA every peer stays connected.
    await node.mine(ACADIA_HEIGHT - 1)
    assert await _count(node, BELOW) == N
    assert await _count(node, AT) == N

    # ACADIA activates; a message from each peer triggers the version check, and
    # the below-version peers are dropped.
    await node.mine(1)
    for conn, _cb in conns:
        conn.send_message(msg_ping(1))
    await _wait_count(node, BELOW, 0)
    assert await _count(node, AT) == N

    # A new below-version peer is rejected on connect.
    rej_conn, rej_cb = await _connect(node, BELOW)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 30
    while rej_cb.last_reject is None:
        assert loop.time() < deadline, "expected a reject message"
        await asyncio.sleep(0.1)
    assert f"Version must be {AT} or greater" in rej_cb.last_reject.reason.decode()

    # A new at-version peer is accepted.
    ok_conn, ok_cb = await _connect(node, AT)
    await ok_cb.wait_for_verack()
    await _wait_count(node, AT, N + 1)

    for conn, _cb in (*conns, (rej_conn, rej_cb), (ok_conn, ok_cb)):
        await conn.disconnect_node()
