"""Seed nodes (-seednode): each is asked for addresses at most once, one at a
time, and only while the node is short of peers.

The seed nodes here are listeners of the test's, which see every connection the
node makes to them. The node runs with its open-connections thread on; on
regtest its address book stays empty, since only routable addresses enter it,
so that thread dials nothing but seed nodes.
"""

import asyncio
import socket
from collections.abc import Callable

from conftest import POW_ARGS, NodeFactory
from fluxtest.mininode import NodeConn, NodeConnCB
from fluxtest.node import FluxNode

# net.h: SEED_NODE_INTERVAL and ONE_SHOT_TIMEOUT, in seconds.
SEED_NODE_INTERVAL = 10
ONE_SHOT_TIMEOUT = 5 * 60


class ClosingCB(NodeConnCB):
    """Sets an event when its connection closes."""

    def __init__(self, closed: asyncio.Event) -> None:
        super().__init__()
        self.closed = closed

    def on_close(self, conn: NodeConn) -> None:
        self.closed.set()


class SeedNode:
    """A listener the node can be given as a seed node. With ``handshake`` it
    answers as a peer does, short of ever sending addresses; without, it
    accepts connections and says nothing."""

    def __init__(self, handshake: bool = False) -> None:
        self.handshake = handshake
        self.connections = 0
        self.closed = asyncio.Event()
        self._server: asyncio.Server | None = None
        self._conns: list[NodeConn] = []
        self._writers: list[asyncio.StreamWriter] = []
        self.port = 0

    async def start(self) -> "SeedNode":
        self._server = await asyncio.start_server(self._on_connect, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def _on_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        self._writers.append(writer)
        if self.handshake:
            cb = ClosingCB(self.closed)
            conn = NodeConn("127.0.0.1", self.port, cb)
            await conn.accept(reader, writer)
            self._conns.append(conn)

    @property
    def dest(self) -> str:
        return f"127.0.0.1:{self.port}"

    async def stop(self) -> None:
        for conn in self._conns:
            await conn.disconnect_node()
        for writer in self._writers:
            writer.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


def closed_port() -> int:
    """A loopback port nothing listens on: a dial to it is refused at once."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def start_with_seeds(node_factory: NodeFactory, seeds: list[str]) -> FluxNode:
    node = await node_factory(0, extra_args=POW_ARGS)
    node.auto_connect = True
    # The clock is mocked from the first moment, so the wait between seed nodes
    # passes only when the test advances it.
    await node.restart(
        [
            *POW_ARGS,
            "-debug=net",
            f"-mocktime={node._mocktime}",
            *(f"-seednode={seed}" for seed in seeds),
        ]
    )
    return node


async def wait_until(predicate: Callable[[], bool], timeout: float = 20) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not predicate():
        assert asyncio.get_running_loop().time() < deadline, "condition not reached"
        await asyncio.sleep(0.1)


def dials(node: FluxNode, dest: str) -> int:
    log = (node.datadir / "regtest" / "debug.log").read_text(errors="replace")
    return log.count(f"trying connection {dest}")


async def test_failed_seednode_is_dialled_once(node_factory: NodeFactory) -> None:
    dest = f"127.0.0.1:{closed_port()}"
    node = await start_with_seeds(node_factory, [dest])

    await wait_until(lambda: dials(node, dest) >= 1)
    # The open-connections thread passes its one-shot queue twice a second.
    await asyncio.sleep(5)
    assert dials(node, dest) == 1


async def test_seednodes_are_asked_one_at_a_time_while_short_of_peers(
    node_factory: NodeFactory,
) -> None:
    seeds = [await SeedNode().start() for _ in range(3)]
    peers = [await node_factory(1, extra_args=POW_ARGS), await node_factory(2, extra_args=POW_ARGS)]
    try:
        node = await start_with_seeds(node_factory, [seed.dest for seed in seeds])

        def asked() -> int:
            assert all(seed.connections <= 1 for seed in seeds), "a seed node was dialled twice"
            return sum(seed.connections for seed in seeds)

        # An empty address book: one seed node is asked at once, and only one.
        await wait_until(lambda: asked() == 1)
        await asyncio.sleep(2)
        assert asked() == 1

        # With two outbound peers no seed node is asked, however long it lasts.
        for peer in peers:
            await node.rpc.addnode(f"127.0.0.1:{peer.p2p_port}", "onetry")
        await wait_until(lambda: asked() == 1)

        async def outbound() -> int:
            return sum(1 for p in await node.rpc.getpeerinfo() if not p["inbound"])

        deadline = asyncio.get_running_loop().time() + 20
        while await outbound() < 3:  # the two peers and the silent seed node
            assert asyncio.get_running_loop().time() < deadline, "peers not connected"
            await asyncio.sleep(0.1)
        await node.advance_mocktime(10 * SEED_NODE_INTERVAL)
        await asyncio.sleep(3)
        assert asked() == 1

        # Short of peers again: the next is asked, and after the interval the last.
        for peer in peers:
            await peer.stop_daemon()
        await wait_until(lambda: asked() == 2)
        await asyncio.sleep(2)
        assert asked() == 2
        await node.advance_mocktime(SEED_NODE_INTERVAL)
        await wait_until(lambda: asked() == 3)

        # Every seed node asked once: none is asked again.
        await node.advance_mocktime(10 * SEED_NODE_INTERVAL)
        await asyncio.sleep(3)
        assert asked() == 3
    finally:
        for seed in seeds:
            await seed.stop()


async def test_seednode_that_sends_no_addresses_is_dropped(node_factory: NodeFactory) -> None:
    seed = await SeedNode(handshake=True).start()
    try:
        node = await start_with_seeds(node_factory, [seed.dest])
        await wait_until(lambda: seed.connections == 1)
        deadline = asyncio.get_running_loop().time() + 20
        while not await node.rpc.getpeerinfo():
            assert asyncio.get_running_loop().time() < deadline, "seed node not connected"
            await asyncio.sleep(0.1)

        # Short of the timeout it is kept.
        await node.advance_mocktime(ONE_SHOT_TIMEOUT - 30)
        await asyncio.sleep(3)
        assert len(await node.rpc.getpeerinfo()) == 1
        assert not seed.closed.is_set()

        await node.advance_mocktime(60)
        await asyncio.wait_for(seed.closed.wait(), timeout=20)
        assert await node.rpc.getpeerinfo() == []
        assert seed.connections == 1
    finally:
        await seed.stop()
