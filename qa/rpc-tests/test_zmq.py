"""fluxd's hashblock / hashtx ZMQ notifiers (-zmqpubhashblock, -zmqpubhashtx).

Every connected block publishes its block hash under "hashblock" and its
coinbase transaction hash under "hashtx"; any transaction entering the mempool --
locally created or relayed in from a peer -- publishes its hash under "hashtx".
Each topic carries an independent sequence counter that increments by one per
message, and each 32-byte body is the hash in display byte order, so it compares
directly against getblockhash and a coinbase txid.

Both topics share one address, so the daemon reuses a single PUB socket and the
two streams arrive in send order. The nodes run in PoW mode so mining funds the
wallet (under PON the coinbase is redirected to the dev-fund).
"""

from decimal import Decimal

from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory, claim_free_port
from fluxtest.network import connect_nodes_bi, sync_blocks, sync_mempools
from zmq_sub import ZmqSubscriber, wait_until_live

HASHBLOCK = b"hashblock"
HASHTX = b"hashtx"


def _zmq_args(port: int) -> list[str]:
    return [
        *POW_ARGS,
        "-debug=zmq",
        f"-zmqpubhashblock=tcp://127.0.0.1:{port}",
        f"-zmqpubhashtx=tcp://127.0.0.1:{port}",
    ]


async def test_hashblock_and_hashtx(node_factory: NodeFactory) -> None:
    """Mining drives one hashblock and one (coinbase) hashtx per block, and a
    wallet send drives a further hashtx for the broadcast transaction."""
    port = claim_free_port()
    with ZmqSubscriber(port, [HASHBLOCK, HASHTX]) as subscriber:
        node = await node_factory(0, extra_args=_zmq_args(port))
        await wait_until_live(subscriber, lambda: node.mine(1))

        # Mine a measured batch over the now-live subscription; this also matures
        # earlier coinbases so the wallet can broadcast a transaction below.
        batch = COINBASE_MATURITY + 1
        block_hashes = await node.mine(batch)

        published_blocks: list[tuple[int, str]] = []
        published_txs: list[tuple[int, str]] = []
        for _ in range(batch * 2):
            message = await subscriber.receive()
            assert message is not None, "expected a hashblock and a hashtx for every mined block"
            topic, body, sequence = message
            (published_blocks if topic == HASHBLOCK else published_txs).append(
                (sequence, body.hex())
            )

        block_seqs = [seq for seq, _ in published_blocks]
        tx_seqs = [seq for seq, _ in published_txs]
        # Each topic's sequence counter increments by one per published message.
        assert block_seqs == list(range(block_seqs[0], block_seqs[0] + batch))
        assert tx_seqs == list(range(tx_seqs[0], tx_seqs[0] + batch))

        # The hashblock bodies are the generated block hashes, in order.
        assert [h for _, h in published_blocks] == block_hashes
        # Each hashtx body is the corresponding block's coinbase txid.
        for (_, txid), block_hash in zip(published_txs, block_hashes, strict=True):
            block = await node.rpc.getblock(block_hash)
            assert block["tx"][0] == txid

        # A broadcast wallet transaction publishes its hashtx, continuing the
        # hashtx sequence past the coinbase notifications.
        await subscriber.drain()
        sent_txid = await node.rpc.sendtoaddress(await node.rpc.getnewaddress(), Decimal("1.0"))
        body, sequence = await subscriber.expect(HASHTX)
        assert body.hex() == sent_txid
        assert sequence == tx_seqs[-1] + 1


async def test_hashtx_on_relayed_transaction(node_factory: NodeFactory) -> None:
    """A transaction created on a peer and relayed in is published as hashtx
    locally -- the notifier fires on mempool acceptance regardless of origin."""
    port = claim_free_port()
    with ZmqSubscriber(port, [HASHTX]) as subscriber:
        node0 = await node_factory(0, extra_args=_zmq_args(port))
        node1 = await node_factory(1, extra_args=POW_ARGS)
        await wait_until_live(subscriber, lambda: node0.mine(1))

        # Fund node1 from node0 so node1 can originate a transaction, then wire
        # the nodes together and let node1 catch up to see its funds.
        await node0.mine(COINBASE_MATURITY + 1)
        await node0.rpc.sendtoaddress(await node1.rpc.getnewaddress(), Decimal("10.0"))
        await node0.mine(1)
        await connect_nodes_bi(node0, node1)
        await sync_blocks([node0, node1])
        assert await node1.rpc.getbalance() >= Decimal("10.0")

        # node1 originates a transaction; node0 publishes its hashtx purely from
        # receiving it over the network.
        await subscriber.drain()
        relayed = await node1.rpc.sendtoaddress(await node1.rpc.getnewaddress(), Decimal("1.0"))
        await sync_mempools([node0, node1])
        body, _ = await subscriber.expect(HASHTX)
        assert body.hex() == relayed
