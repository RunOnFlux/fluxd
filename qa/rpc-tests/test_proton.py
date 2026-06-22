"""The AMQP 1.0 block/transaction hash notifier.

fluxd, given -amqppubhashblock and -amqppubhashtx (both gated behind
-experimentalfeatures), publishes a block hash under the subject "hashblock" and
a transaction hash under "hashtx" as a 32-byte AMQP 1.0 message body, every
message carrying an incrementing integer property "x-opt-sequence-number". On
connect it publishes the current chain tip, then one of each per block as the
chain advances.

The listener below IS the AMQP server: qpid-proton's reactor listens on a local
port and the daemon connects out to it, so no external broker is needed. It
collects the published hashes, asserts the per-subject sequence numbers increment
by one, and the test then cross-checks every block hash against getblockhash and
every transaction hash against that block's coinbase txid. The C++ notifier
writes the hash most-significant-byte-first (data[31 - i] = hash.begin()[i]), so
the received hex is already in getblockhash display order and compares directly.
"""

import asyncio
import threading

import pytest
from conftest import NodeFactory, claim_free_port

# qpid-proton ships no manylinux wheel, so it is installed only in the Linux run
# environment; skip the whole module wherever it is unavailable (e.g. macOS lint).
pytest.importorskip("proton")

from proton import Event, Message  # noqa: E402
from proton.handlers import MessagingHandler  # noqa: E402
from proton.reactor import Container  # noqa: E402

NUM_BLOCKS = 10

# The node starts on a fresh regtest chain (tip = genesis) and publishes that tip
# once on connect, so the listener sees the genesis block plus the NUM_BLOCKS
# mined blocks: NUM_BLOCKS + 1 of each subject.
EXPECTED_PER_SUBJECT = NUM_BLOCKS + 1

# How long the listener thread is allowed to collect all expected messages.
JOIN_TIMEOUT = 60.0


class Server(MessagingHandler):
    """An AMQP 1.0 listener that records the hashes fluxd publishes.

    Stops its own container once ``limit`` messages have arrived, which lets the
    background thread running the reactor exit so the test can join it.
    """

    def __init__(self, url: str, limit: int) -> None:
        super().__init__()
        self.url = url
        self.counter = limit
        self.blockhashes: list[str] = []
        self.txids: list[str] = []
        self.blockseq = -1
        self.txidseq = -1

    def on_start(self, event: Event) -> None:
        self.container = event.container
        self.acceptor = event.container.listen(self.url)

    def on_message(self, event: Event) -> None:
        m: Message = event.message
        # The notifier always sends the raw 32-byte hash (proton delivers it as a
        # memoryview) and the sequence property; asserting both narrows the
        # proton stubs' wide types and guards the wire format.
        assert isinstance(m.body, bytes | bytearray | memoryview)
        assert m.properties is not None
        value = bytes(m.body).hex()
        sequence = m.properties["x-opt-sequence-number"]
        if m.subject == "hashtx":
            self.txids.append(value)
            # Sequence numbers are published strictly incrementing per subject.
            assert sequence == 1 + self.txidseq
            self.txidseq = sequence
        elif m.subject == "hashblock":
            self.blockhashes.append(value)
            assert sequence == 1 + self.blockseq
            self.blockseq = sequence

        self.counter -= 1
        if self.counter == 0:
            self.container.stop()


async def test_amqp_publishes_block_and_tx_hashes(node_factory: NodeFactory) -> None:
    """The initial tip and each mined block each yield a hashblock and a hashtx."""
    # A free port from the shared allocator -- monotonic, so it is distinct from
    # the node's own ports regardless of when the listener thread binds it.
    url = f"127.0.0.1:{claim_free_port()}"

    # The listener terminates after one block hash and one coinbase txid for the
    # genesis tip plus every mined block.
    server = Server(url, EXPECTED_PER_SUBJECT * 2)
    container = Container(server)
    thread = threading.Thread(target=container.run)
    thread.start()
    try:
        node = await node_factory(
            0,
            extra_args=[
                "-experimentalfeatures",
                "-debug=amqp",
                f"-amqppubhashtx=amqp://{url}",
                f"-amqppubhashblock=amqp://{url}",
            ],
        )
        # Fresh regtest node: the tip published on connect is genesis (height 0).
        baseheight = await node.rpc.getblockcount()

        # Block production alone drives both notifications: a hashblock for the
        # block and a hashtx for its coinbase.
        await node.mine(NUM_BLOCKS)

        # Join off the event loop so the loop is not blocked by the reactor wait.
        await asyncio.to_thread(thread.join, JOIN_TIMEOUT)
        assert not thread.is_alive(), (
            f"AMQP listener received only {len(server.blockhashes)} block / "
            f"{len(server.txids)} tx messages within {JOIN_TIMEOUT}s"
        )

        # Per-subject sequence increments were checked as messages arrived.
        assert len(server.blockhashes) == EXPECTED_PER_SUBJECT
        assert len(server.txids) == EXPECTED_PER_SUBJECT

        # Every published hash matches the chain: the initial tip then each mined
        # block, with the block's hash and its coinbase txid.
        for i in range(EXPECTED_PER_SUBJECT):
            blockhash = await node.rpc.getblockhash(baseheight + i)
            assert blockhash == server.blockhashes[i]
            block = await node.rpc.getblock(blockhash)
            assert block["tx"][0] == server.txids[i]
    finally:
        if thread.is_alive():
            container.stop()
            thread.join(5)
