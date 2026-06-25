"""fluxd's FluxNode-specific ZMQ notifiers: hashblockheight, chainreorg, and
fluxnodelistdelta.

Each connected block publishes a ``hashblockheight`` (the 32-byte block hash in
display order followed by a little-endian height) and a ``fluxnodelistdelta``
spanning the previous tip to the new one; a reorg publishes a ``chainreorg``
carrying the old tip, the new tip, and the fork point, and makes the next delta
chain from the pre-reorg tip with its is_reorg flag set. The delta body is
``from_height(4) + to_height(4) + from_hash(32) + to_hash(32) + flags(1)`` then
compact-size counts of added / removed / updated fluxnodes with their payloads.
On regtest no fluxnode start transactions exist, so every delta carries empty
node sets, which makes the chain-spanning header and its hashes the thing under
test -- cross-checked against getblockhash and getfluxnodesnapshot.

Each sequence counter increments by one per message. The exact starting value is
not asserted -- the first notifications are gated by initial block download and
the ZMQ slow-joiner, and ``wait_until_live`` consumes an unknown few (see
zmq_sub) -- but it must be small: a per-topic counter left uninitialized would
start from a multi-billion garbage value, so the test guards against that.
"""

import asyncio
import struct
from typing import NamedTuple

from conftest import NodeFactory, claim_free_port
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from zmq_sub import ZmqSubscriber, wait_until_live

HASHBLOCKHEIGHT = b"hashblockheight"
CHAINREORG = b"chainreorg"
FLUXNODELISTDELTA = b"fluxnodelistdelta"


class DeltaHeader(NamedTuple):
    from_height: int
    to_height: int
    from_hash: str
    to_hash: str
    is_reorg: bool


class ChainReorg(NamedTuple):
    old_hash: str
    old_height: int
    new_hash: str
    new_height: int
    fork_hash: str
    fork_height: int


def _parse_hashblockheight(body: bytes) -> tuple[str, int]:
    assert len(body) == 36, f"hashblockheight should be 36 bytes, got {len(body)}"
    return body[0:32].hex(), struct.unpack_from("<I", body, 32)[0]


def _parse_delta_header(body: bytes) -> DeltaHeader:
    assert len(body) >= 73, f"delta shorter than its header: {len(body)} bytes"
    return DeltaHeader(
        from_height=struct.unpack_from("<I", body, 0)[0],
        to_height=struct.unpack_from("<I", body, 4)[0],
        from_hash=body[8:40].hex(),
        to_hash=body[40:72].hex(),
        is_reorg=bool(body[72] & 0x01),
    )


def _read_compact_size(body: bytes, offset: int) -> tuple[int, int]:
    first = body[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        return struct.unpack_from("<H", body, offset + 1)[0], offset + 3
    if first == 0xFE:
        return struct.unpack_from("<I", body, offset + 1)[0], offset + 5
    return struct.unpack_from("<Q", body, offset + 1)[0], offset + 9


def _delta_counts(body: bytes) -> tuple[int, int, int, int]:
    """Return (added, removed, updated, end_offset).

    Only valid to walk past the added section when it is empty (there are no
    node payloads to skip), which holds on a fluxnode-free regtest chain.
    """
    added, offset = _read_compact_size(body, 73)
    removed, offset = _read_compact_size(body, offset)
    updated, offset = _read_compact_size(body, offset)
    return added, removed, updated, offset


def _parse_chainreorg(body: bytes) -> ChainReorg:
    assert len(body) == 108, f"chainreorg should be 108 bytes, got {len(body)}"
    return ChainReorg(
        old_hash=body[0:32].hex(),
        old_height=struct.unpack_from("<I", body, 32)[0],
        new_hash=body[36:68].hex(),
        new_height=struct.unpack_from("<I", body, 68)[0],
        fork_hash=body[72:104].hex(),
        fork_height=struct.unpack_from("<I", body, 104)[0],
    )


async def _tip_time(node: FluxNode) -> int:
    return int((await node.rpc.getblock(await node.rpc.getbestblockhash()))["time"])


async def _disconnect_all(node: FluxNode, timeout: float = 30) -> None:
    """Disconnect every peer and wait until the node is fully isolated."""
    for peer in await node.rpc.getpeerinfo():
        await node.rpc.disconnectnode(peer["addr"])
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while await node.rpc.getpeerinfo():
        if loop.time() > deadline:
            raise AssertionError(f"node {node.index} still has peers after disconnect")
        await asyncio.sleep(0.1)


async def _expect_reorg_from(
    subscriber: ZmqSubscriber, old_hash: str, timeout: float = 30
) -> ChainReorg:
    """Return the chainreorg message whose old tip is ``old_hash``."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        message = await subscriber.receive(remaining) if remaining > 0 else None
        if message is None:
            raise AssertionError(f"no chainreorg with old tip {old_hash[:16]} within {timeout}s")
        topic, body, _ = message
        if topic == CHAINREORG:
            reorg = _parse_chainreorg(body)
            if reorg.old_hash == old_hash:
                return reorg


async def test_hashblockheight_matches_chain(node_factory: NodeFactory) -> None:
    """hashblockheight publishes the new block's hash and height in display order."""
    port = claim_free_port()
    with ZmqSubscriber(port, [HASHBLOCKHEIGHT]) as subscriber:
        node = await node_factory(
            0, extra_args=["-debug=zmq", f"-zmqpubhashblockheight=tcp://127.0.0.1:{port}"]
        )
        await wait_until_live(subscriber, lambda: node.mine(1))

        [block_hash] = await node.mine(1)
        body, _ = await subscriber.expect(HASHBLOCKHEIGHT)
        published_hash, height = _parse_hashblockheight(body)
        assert published_hash == block_hash
        assert published_hash == await node.rpc.getbestblockhash()
        assert height == await node.rpc.getblockcount()


async def test_snapshot_has_blockhash(node_factory: NodeFactory) -> None:
    """getfluxnodesnapshot reports the tip height/hash atomically with the list."""
    node = await node_factory(0)
    await node.mine(3)
    snapshot = await node.rpc.getfluxnodesnapshot()
    assert snapshot["height"] == await node.rpc.getblockcount()
    assert snapshot["blockhash"] == await node.rpc.getbestblockhash()
    assert snapshot["blockhash"] == await node.rpc.getblockhash(snapshot["height"])
    assert snapshot["nodes"] == []


async def test_delta_format_and_span(node_factory: NodeFactory) -> None:
    """A normal-block delta spans the previous tip to the new one and, with no
    fluxnodes, carries empty added/removed/updated sets."""
    port = claim_free_port()
    with ZmqSubscriber(port, [FLUXNODELISTDELTA]) as subscriber:
        node = await node_factory(
            0, extra_args=["-debug=zmq", f"-zmqpubfluxnodelistdelta=tcp://127.0.0.1:{port}"]
        )
        await wait_until_live(subscriber, lambda: node.mine(1))
        from_height = await node.rpc.getblockcount()
        from_hash = await node.rpc.getbestblockhash()

        await node.mine(1)
        body, _ = await subscriber.expect(FLUXNODELISTDELTA)
        delta = _parse_delta_header(body)
        assert delta.from_height == from_height
        assert delta.to_height == from_height + 1
        assert delta.from_hash == from_hash
        assert delta.to_hash == await node.rpc.getblockhash(delta.to_height)
        assert delta.is_reorg is False

        added, removed, updated, end = _delta_counts(body)
        assert (added, removed, updated) == (0, 0, 0)
        assert end == len(body) == 76

        snapshot = await node.rpc.getfluxnodesnapshot()
        assert snapshot["height"] == delta.to_height
        assert snapshot["blockhash"] == delta.to_hash
        assert snapshot["nodes"] == []


async def test_delta_hash_chaining(node_factory: NodeFactory) -> None:
    """Across consecutive blocks each delta's from_hash is the previous to_hash,
    and the sequence counter increments by one."""
    port = claim_free_port()
    with ZmqSubscriber(port, [FLUXNODELISTDELTA]) as subscriber:
        node = await node_factory(
            0, extra_args=["-debug=zmq", f"-zmqpubfluxnodelistdelta=tcp://127.0.0.1:{port}"]
        )
        await wait_until_live(subscriber, lambda: node.mine(1))

        blocks = 5
        await node.mine(blocks)
        previous: DeltaHeader | None = None
        previous_sequence: int | None = None
        for _ in range(blocks):
            body, sequence = await subscriber.expect(FLUXNODELISTDELTA)
            delta = _parse_delta_header(body)
            if previous_sequence is not None:
                assert sequence == previous_sequence + 1
            previous_sequence = sequence
            assert delta.to_height == delta.from_height + 1
            assert delta.is_reorg is False
            if previous is not None:
                assert delta.from_height == previous.to_height
                assert delta.from_hash == previous.to_hash
            previous = delta


async def test_delta_after_reorg(node_factory: NodeFactory) -> None:
    """After a reorg the next delta is flagged is_reorg and chains its from_hash
    from the pre-reorg tip (the daemon caches it across the chain switch)."""
    port = claim_free_port()
    with ZmqSubscriber(port, [FLUXNODELISTDELTA]) as subscriber:
        node = await node_factory(
            0, extra_args=["-debug=zmq", f"-zmqpubfluxnodelistdelta=tcp://127.0.0.1:{port}"]
        )
        await wait_until_live(subscriber, lambda: node.mine(1))
        await node.mine(6)

        old_height = await node.rpc.getblockcount()
        old_hash = await node.rpc.getbestblockhash()
        await subscriber.drain()

        # Invalidate two blocks back so the tip rolls to old_height-3, then mine
        # a fresh block: that block's delta reports the reorg.
        await node.rpc.invalidateblock(await node.rpc.getblockhash(old_height - 2))
        await node.mine(1)
        body, _ = await subscriber.expect(FLUXNODELISTDELTA)
        delta = _parse_delta_header(body)

        assert delta.is_reorg is True
        assert delta.from_height == old_height
        assert delta.from_hash == old_hash  # the pre-reorg tip, now off-chain
        assert delta.to_height == old_height - 2
        assert delta.to_hash == await node.rpc.getbestblockhash()

        added, removed, updated, end = _delta_counts(body)
        assert (added, removed, updated) == (0, 0, 0)
        assert end == len(body) == 76


async def test_byte_order_consistency(node_factory: NodeFactory) -> None:
    """The same block hash appears, identically, across hashblockheight, the
    delta to_hash, the snapshot, and the block RPCs."""
    port = claim_free_port()
    with ZmqSubscriber(port, [HASHBLOCKHEIGHT, FLUXNODELISTDELTA]) as subscriber:
        node = await node_factory(
            0,
            extra_args=[
                "-debug=zmq",
                f"-zmqpubhashblockheight=tcp://127.0.0.1:{port}",
                f"-zmqpubfluxnodelistdelta=tcp://127.0.0.1:{port}",
            ],
        )
        await wait_until_live(subscriber, lambda: node.mine(1))

        [block_hash] = await node.mine(1)
        found = await subscriber.collect([HASHBLOCKHEIGHT, FLUXNODELISTDELTA])
        published_hash, height = _parse_hashblockheight(found[HASHBLOCKHEIGHT][0])
        delta = _parse_delta_header(found[FLUXNODELISTDELTA][0])
        snapshot = await node.rpc.getfluxnodesnapshot()

        assert published_hash == block_hash
        assert delta.to_hash == block_hash
        assert snapshot["blockhash"] == block_hash
        assert await node.rpc.getbestblockhash() == block_hash
        assert height == await node.rpc.getblockcount()


async def test_message_sequencing(node_factory: NodeFactory) -> None:
    """Each topic's sequence counter increments by one per block, independently."""
    port = claim_free_port()
    with ZmqSubscriber(port, [HASHBLOCKHEIGHT, FLUXNODELISTDELTA]) as subscriber:
        node = await node_factory(
            0,
            extra_args=[
                "-debug=zmq",
                f"-zmqpubhashblockheight=tcp://127.0.0.1:{port}",
                f"-zmqpubfluxnodelistdelta=tcp://127.0.0.1:{port}",
            ],
        )
        await wait_until_live(subscriber, lambda: node.mine(1))

        blocks = 3
        await node.mine(blocks)
        sequences: dict[bytes, list[int]] = {HASHBLOCKHEIGHT: [], FLUXNODELISTDELTA: []}
        for _ in range(blocks * 2):
            message = await subscriber.receive()
            assert message is not None, "expected one of each topic per block"
            topic, _, sequence = message
            sequences[topic].append(sequence)

        for topic, values in sequences.items():
            assert len(values) == blocks, f"{topic.decode()}: {values}"
            # A small base, not the multi-billion value an uninitialized counter
            # would emit.
            assert values[0] < 100000, f"{topic.decode()} sequence base uninitialized: {values[0]}"
            assert values == list(range(values[0], values[0] + blocks)), (
                f"{topic.decode()} not consecutive: {values}"
            )


async def test_chainreorg_on_invalidateblock(node_factory: NodeFactory) -> None:
    """invalidateblock rolls the tip back to the fork and publishes a chainreorg
    naming the old tip, the new tip, and the (identical) fork point."""
    port = claim_free_port()
    with ZmqSubscriber(port, [CHAINREORG, b"hashblock"]) as subscriber:
        node = await node_factory(
            0,
            extra_args=[
                "-debug=zmq",
                f"-zmqpubchainreorg=tcp://127.0.0.1:{port}",
                f"-zmqpubhashblock=tcp://127.0.0.1:{port}",
            ],
        )
        await wait_until_live(subscriber, lambda: node.mine(1))
        await node.mine(6)
        old_height = await node.rpc.getblockcount()
        old_hash = await node.rpc.getbestblockhash()
        invalidate_height = old_height - 2

        await subscriber.drain()
        await node.rpc.invalidateblock(await node.rpc.getblockhash(invalidate_height))

        new_height = await node.rpc.getblockcount()
        new_hash = await node.rpc.getbestblockhash()
        assert new_height == invalidate_height - 1  # rolled back to the parent of the invalid block

        body, _ = await subscriber.expect(CHAINREORG)
        reorg = _parse_chainreorg(body)
        assert reorg.old_height == old_height
        assert reorg.old_hash == old_hash
        assert reorg.new_height == new_height
        assert reorg.new_hash == new_hash
        # With no replacement branch the new tip and the fork point are the same.
        assert reorg.fork_height == new_height
        assert reorg.fork_hash == new_hash


async def test_chainreorg_on_competing_chains(node_factory: NodeFactory) -> None:
    """Adopting a peer's longer chain publishes a chainreorg from the old tip,
    forking at the last common block."""
    port = claim_free_port()
    with ZmqSubscriber(port, [CHAINREORG, b"hashblock"]) as subscriber:
        node0 = await node_factory(
            0,
            extra_args=[
                "-debug=zmq",
                f"-zmqpubchainreorg=tcp://127.0.0.1:{port}",
                f"-zmqpubhashblock=tcp://127.0.0.1:{port}",
            ],
        )
        node1 = await node_factory(1)
        await wait_until_live(subscriber, lambda: node0.mine(1))

        # Build a shared history, then isolate the nodes so their chains diverge.
        await connect_nodes_bi(node0, node1)
        await node0.mine(3)
        await sync_blocks([node0, node1])
        fork_height = await node0.rpc.getblockcount()
        fork_hash = await node0.rpc.getbestblockhash()
        await _disconnect_all(node0)
        await _disconnect_all(node1)

        # node1's chain is longer (more work), so node0 will reorg onto it.
        await node0.mine(2)
        await node1.mine(4)
        old_height = await node0.rpc.getblockcount()
        old_hash = await node0.rpc.getbestblockhash()
        node1_height = await node1.rpc.getblockcount()
        node1_hash = await node1.rpc.getbestblockhash()

        # Pull node0's clock up so it accepts node1's later-timestamped blocks.
        await node0.set_mocktime_at_least(await _tip_time(node1))
        await subscriber.drain()
        await connect_nodes_bi(node0, node1)
        await sync_blocks([node0, node1])
        assert await node0.rpc.getbestblockhash() == node1_hash

        reorg = await _expect_reorg_from(subscriber, old_hash)
        assert reorg.old_height == old_height
        assert reorg.fork_height == fork_height
        assert reorg.fork_hash == fork_hash
        # The reorg may report a tip partway along node1's chain (the connect
        # loop returns once it is ahead), but always one of node1's blocks.
        assert fork_height < reorg.new_height <= node1_height
        assert reorg.new_hash == await node1.rpc.getblockhash(reorg.new_height)
