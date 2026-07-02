"""An asyncio ZeroMQ SUB client for fluxd's ``-zmqpub*`` notifiers.

fluxd binds a PUB socket for each ``-zmqpub<topic>=tcp://host:port`` option and
publishes a three-frame multipart message ``[topic, body, sequence]`` per event,
where ``sequence`` is a 4-byte little-endian counter kept independently per
topic. The daemon is the binder, so this subscriber connects out to it.

A ZMQ publisher silently drops messages to a subscriber whose subscription has
not yet reached it, so notifications published right after the node starts can be
lost regardless of when the subscriber connected. ``wait_until_live`` resolves
that race deterministically: it drives block production until a notification is
actually received, which proves the subscription has propagated; from that point
the (TCP, in-order) stream is reliable, so tests assert only on events produced
after it returns.
"""

import asyncio
import struct
from collections.abc import Awaitable, Callable

import zmq
import zmq.asyncio

# (topic, body, sequence) of one received notification.
Message = tuple[bytes, bytes, int]
# (body, sequence) of a message already known to be on a given topic.
TopicMessage = tuple[bytes, int]


class ZmqSubscriber:
    """A ZMQ SUB socket receiving fluxd notifications over asyncio.

    Usable as a context manager so the socket is always closed when the test
    leaves the block (the underlying context is process-wide and shared).
    """

    def __init__(self, port: int, topics: list[bytes]) -> None:
        # Sockets come from pyzmq's process-wide singleton context, which is
        # never terminated. Creating and tearing down a libzmq context per
        # subscriber intermittently corrupts the next test's fluxd subprocess,
        # so only sockets are opened and closed per subscriber.
        self._socket = zmq.asyncio.Context.instance().socket(zmq.SUB)
        self._socket.setsockopt(zmq.LINGER, 0)
        for topic in topics:
            self._socket.setsockopt(zmq.SUBSCRIBE, topic)
        self._socket.connect(f"tcp://127.0.0.1:{port}")
        self._poller = zmq.asyncio.Poller()
        self._poller.register(self._socket, zmq.POLLIN)

    def __enter__(self) -> "ZmqSubscriber":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    async def receive(self, timeout: float = 30) -> Message | None:
        """Return the next ``(topic, body, sequence)``, or None on timeout."""
        events = dict(await self._poller.poll(int(timeout * 1000)))
        if self._socket not in events:
            return None
        topic, body, raw_sequence = await self._socket.recv_multipart()
        return topic, body, struct.unpack("<I", raw_sequence)[0]

    async def expect(self, topic: bytes, timeout: float = 30) -> TopicMessage:
        """Wait for the next message on ``topic`` and return ``(body, sequence)``.

        Messages on other subscribed topics that arrive first are discarded, so
        do not use this when a later message on one of those topics is also
        needed -- use ``collect`` for that.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while True:
            remaining = deadline - loop.time()
            message = await self.receive(remaining) if remaining > 0 else None
            if message is None:
                raise AssertionError(f"no {topic.decode()} ZMQ message within {timeout}s")
            if message[0] == topic:
                return message[1], message[2]

    async def collect(self, topics: list[bytes], timeout: float = 30) -> dict[bytes, TopicMessage]:
        """Receive until the first message of each topic is seen.

        Returns ``{topic: (body, sequence)}``. Unlike repeated ``expect`` calls
        this keeps every requested topic regardless of arrival order.
        """
        wanted = set(topics)
        found: dict[bytes, TopicMessage] = {}
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while wanted:
            remaining = deadline - loop.time()
            message = await self.receive(remaining) if remaining > 0 else None
            if message is None:
                missing = [t.decode() for t in wanted]
                raise AssertionError(f"missing ZMQ topics {missing} within {timeout}s")
            topic, body, sequence = message
            if topic in wanted:
                found[topic] = (body, sequence)
                wanted.discard(topic)
        return found

    async def drain(self) -> None:
        """Discard any already-queued messages so the next receive is fresh."""
        while await self.receive(0.1) is not None:
            pass

    def close(self) -> None:
        self._poller.unregister(self._socket)
        self._socket.close()


async def wait_until_live(
    subscriber: ZmqSubscriber,
    mine_one: Callable[[], Awaitable[object]],
    timeout: float = 30,
) -> None:
    """Block until the subscriber actually receives a notification.

    A ZMQ publisher drops messages to a subscription that has not yet reached it,
    and fluxd only publishes block notifications once it is out of initial block
    download. Driving ``mine_one`` until a message arrives proves both conditions
    hold; the warm-up traffic is then drained so the caller starts from a clean,
    reliable stream. ``mine_one`` must trigger a subscribed topic (block
    production does, for every topic except chainreorg).
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        await mine_one()
        if await subscriber.receive(1) is not None:
            await subscriber.drain()
            return
    raise AssertionError("ZMQ subscription did not become live within the timeout")
