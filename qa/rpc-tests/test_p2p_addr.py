"""Processing of addr messages: rate limiting, relay, and oversized rejection.

The addr token bucket starts at 1 and refills at 0.1/s (capped at 1000); each
processed address spends a token and the rest are counted rate-limited
(getpeerinfo addr_processed / addr_rate_limited). The bucket's last-update stamp
is real time while the refill reads mocktime, so the node's clock is pinned to
real time at connect and advanced from there (mirroring the daemon's mixing of
the two clocks).
"""

import time

from conftest import NodeFactory
from fluxtest.mininode import CAddress, NodeConn, NodeConnCB, msg_addr

NODE_NETWORK = 1
START_PORT = 10000


class _AddrNode(NodeConnCB):
    def __init__(self) -> None:
        super().__init__()
        self.ports_received: list[int] = []

    def on_addr(self, conn: NodeConn, message: msg_addr) -> None:
        self.ports_received.extend(addr.port for addr in message.addrs)


class _AddrTest:
    def __init__(self, node) -> None:
        self.node = node
        self.counter = 0
        self.mocktime = 0
        self.send_node = _AddrNode()
        self.recv_nodes = [_AddrNode() for _ in range(4)]
        self._conns: list[NodeConn] = []

    async def connect_all(self) -> None:
        for cb in [self.send_node, *self.recv_nodes]:
            conn = NodeConn("127.0.0.1", self.node.p2p_port, cb)
            self._conns.append(conn)
            await conn.connect()
        for cb in [self.send_node, *self.recv_nodes]:
            await cb.wait_for_verack()

    async def disconnect_all(self) -> None:
        for conn in self._conns:
            await conn.disconnect_node()

    def _addr_msg(self, num: int, services: int = NODE_NETWORK) -> msg_addr:
        message = msg_addr()
        for _ in range(num):
            addr = CAddress()
            addr.nTime = self.mocktime - 5
            addr.nServices = services
            addr.ip = f"123.123.{self.counter // 256}.{self.counter % 256}"
            addr.port = START_PORT + self.counter
            self.counter += 1
            message.addrs.append(addr)
        return message

    async def _send_addr(self, num: int) -> None:
        assert self.send_node.connection is not None
        self.send_node.connection.send_message(self._addr_msg(num))
        await self.send_node.sync_with_ping()
        # Advance the clock 600s so the relay timer (mean 30s) fires and the
        # token bucket refills by 60 before the next batch.
        self.mocktime += 600
        await self.node.rpc.setmocktime(self.mocktime)
        for cb in self.recv_nodes:
            await cb.sync_with_ping()

    async def _wait_for_port(self, port: int, timeout: float = 30) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(port in cb.ports_received for cb in self.recv_nodes):
                return True
            for cb in self.recv_nodes:
                await cb.sync_with_ping()
        return any(port in cb.ports_received for cb in self.recv_nodes)

    def _has_port(self, port: int) -> bool:
        return any(port in cb.ports_received for cb in self.recv_nodes)

    async def rate_limiting_test(self) -> None:
        # 1 addr on connect, then 600s of refill = 60 tokens, then 69 more: across
        # the 70 the bucket admits 60 and rate-limits 10.
        await self._send_addr(1)
        await self._send_addr(69)
        peers = await self.node.rpc.getpeerinfo()
        counts = [(p["addr_processed"], p["addr_rate_limited"]) for p in peers]
        sender = next((p for p in peers if p["addr_processed"] == 60), None)
        assert sender is not None, counts
        assert sender["addr_rate_limited"] == 10, counts

    async def simple_relay_test(self) -> None:
        last = START_PORT + self.counter + 1  # the second of the two addrs
        await self._send_addr(2)
        assert await self._wait_for_port(last - 1) or await self._wait_for_port(last)

    async def oversized_addr_test(self) -> None:
        self.mocktime += 10010  # refill the bucket to its non-burst maximum
        await self.node.rpc.setmocktime(self.mocktime)
        valid_before = START_PORT + self.counter
        await self._send_addr(1)
        first_oversized = START_PORT + self.counter
        await self._send_addr(1010)  # > 1000 -> rejected wholesale
        valid_after = START_PORT + self.counter
        await self._send_addr(1)
        assert await self._wait_for_port(valid_before)
        assert await self._wait_for_port(valid_after)
        for port in range(first_oversized, valid_after):
            assert not self._has_port(port), port


async def test_p2p_addr(node_factory: NodeFactory) -> None:
    node = await node_factory(0)
    test = _AddrTest(node)
    test.mocktime = int(time.time())  # the bucket stamps connect with real time
    await node.rpc.setmocktime(0)  # real time, so the bucket's connect stamp aligns
    await test.connect_all()
    try:
        await test.rate_limiting_test()  # first, for the initial one-token state
        await test.simple_relay_test()
        await test.oversized_addr_test()
    finally:
        await test.disconnect_all()
