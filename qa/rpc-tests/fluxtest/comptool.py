"""A block/transaction comparison harness for the consensus P2P tests.

A test supplies a sequence of blocks and transactions, each tagged with an
expected outcome -- accepted, rejected, or ``None`` meaning "every node must
merely agree" -- and the manager feeds them to one or more regtest nodes over
P2P and checks each node's resulting tip (or mempool) against the expectation.

Objects are announced with an inv and then served from an in-memory store when
the node requests them. Serving on request (rather than pushing the block) is
what lets the malleated-block case work: a block rejected for a duplicated
transaction leaves a header with no valid data, so the node re-requests it and
the honest block carrying the same hash can be served in its place. Each node's
resulting tip / mempool is read back over RPC.

The nodes must be out of initial block download for this to work (they neither
answer getheaders nor fetch block bodies while in IBD); a test keeps mocktime
level with the tip to ensure that.

A test object implements ``get_tests()`` as an async generator yielding
``TestInstance`` objects; it may interleave RPC calls between yields.
"""

import asyncio

from .mininode import (
    MAX_INV_SZ,
    CBlock,
    CBlockHeader,
    CBlockLocator,
    CInv,
    CTransaction,
    NodeConn,
    NodeConnCB,
    msg_block,
    msg_getdata,
    msg_getheaders,
    msg_headers,
    msg_inv,
    msg_ping,
    msg_pong,
    msg_tx,
)
from .node import FluxNode

MSG_TX = 1
MSG_BLOCK = 2


async def _wait_until(predicate, timeout: float = 60) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.05)
    return predicate()


class BlockStore:
    """In-memory map of blocks; answers getheaders and getdata."""

    def __init__(self) -> None:
        self._blocks: dict[int, CBlock] = {}
        self.current_block = 0

    def get(self, blockhash: int) -> CBlock | None:
        return self._blocks.get(blockhash)

    def add_block(self, block: CBlock) -> None:
        block.calc_sha256()
        assert block.sha256 is not None
        self._blocks[block.sha256] = block
        self.current_block = block.sha256

    def _header(self, block: CBlock) -> CBlockHeader:
        header = CBlockHeader(block)
        header.calc_sha256()
        return header

    def headers_for(self, locator: CBlockLocator, hash_stop: int) -> msg_headers | None:
        current = self.get(self.current_block)
        if current is None:
            return None
        headers = [self._header(current)]
        while headers[0].sha256 not in locator.vHave:
            prev = self.get(headers[0].hashPrevBlock)
            if prev is None:
                break
            headers.insert(0, self._header(prev))
        headers = headers[:2000]  # the wire limit
        hashes = [h.sha256 for h in headers]
        index = hashes.index(hash_stop) + 1 if hash_stop in hashes else len(headers)
        response = msg_headers()
        response.headers = headers[:index]
        return response

    def get_blocks(self, inv: list[CInv]) -> list[msg_block]:
        wanted = (self.get(i.hash) for i in inv if i.type == MSG_BLOCK)
        return [msg_block(b) for b in wanted if b is not None]


class TxStore:
    """In-memory map of transactions; answers getdata."""

    def __init__(self) -> None:
        self._txs: dict[int, CTransaction] = {}

    def add_transaction(self, tx: CTransaction) -> None:
        tx.calc_sha256()
        assert tx.sha256 is not None
        self._txs[tx.sha256] = tx

    def get_transactions(self, inv: list[CInv]) -> list[msg_tx]:
        wanted = (self._txs.get(i.hash) for i in inv if i.type == MSG_TX)
        return [msg_tx(t) for t in wanted if t is not None]


class TestNode(NodeConnCB):
    """Answers the node's getheaders/getdata from the shared stores and records
    which blocks and transactions it has been asked for."""

    __test__ = False  # not a pytest test class

    def __init__(self, block_store: BlockStore, tx_store: TxStore) -> None:
        super().__init__()
        self.block_store = block_store
        self.tx_store = tx_store
        self.block_request_map: dict[int, bool] = {}
        self.tx_request_map: dict[int, bool] = {}
        self.ping_map: dict[int, bool] = {}
        self.closed = False

    def on_close(self, conn: NodeConn) -> None:
        self.closed = True

    def on_getheaders(self, conn: NodeConn, message: msg_getheaders) -> None:
        response = self.block_store.headers_for(message.locator, message.hashstop)
        if response is not None:
            conn.send_message(response)

    def on_getdata(self, conn: NodeConn, message: msg_getdata) -> None:
        for response in self.block_store.get_blocks(message.inv):
            conn.send_message(response)
        for response in self.tx_store.get_transactions(message.inv):
            conn.send_message(response)
        for i in message.inv:
            if i.type == MSG_TX:
                self.tx_request_map[i.hash] = True
            elif i.type == MSG_BLOCK:
                self.block_request_map[i.hash] = True

    def on_pong(self, conn: NodeConn, message: msg_pong) -> None:
        self.ping_map.pop(message.nonce, None)

    def send_inv(self, obj: CBlock | CTransaction) -> None:
        assert self.connection is not None and obj.sha256 is not None
        mtype = MSG_BLOCK if isinstance(obj, CBlock) else MSG_TX
        self.connection.send_message(msg_inv([CInv(mtype, obj.sha256)]))

    def send_ping(self, nonce: int) -> None:
        assert self.connection is not None
        self.ping_map[nonce] = True
        self.connection.send_message(msg_ping(nonce))

    def received_ping_response(self, nonce: int) -> bool:
        return nonce not in self.ping_map


class TestInstance:
    """A batch of (object, expected-outcome) pairs.

    ``sync_every_block`` syncs and checks each block as it is delivered;
    otherwise invs accumulate and only the final block is checked. The outcome is
    ``True`` (must become the tip / enter the mempool), ``False`` (must not), or
    ``None`` (all nodes must merely agree).
    """

    __test__ = False  # not a pytest test class

    def __init__(
        self,
        objects: list[list] | None = None,
        sync_every_block: bool = True,
        sync_every_tx: bool = False,
    ) -> None:
        self.blocks_and_transactions = objects if objects is not None else []
        self.sync_every_block = sync_every_block
        self.sync_every_tx = sync_every_tx


class TestManager:
    __test__ = False  # not a pytest test class

    def __init__(self, testgen) -> None:
        self.test_generator = testgen
        self.connections: list[NodeConn] = []
        self.test_nodes: list[TestNode] = []
        self.nodes: list[FluxNode] = []
        self.block_store = BlockStore()
        self.tx_store = TxStore()
        self.ping_counter = 1

    async def add_all_connections(self, nodes: list[FluxNode]) -> None:
        self.nodes = list(nodes)
        for node in nodes:
            test_node = TestNode(self.block_store, self.tx_store)
            self.test_nodes.append(test_node)
            self.connections.append(NodeConn("127.0.0.1", node.p2p_port, test_node))
        for conn in self.connections:
            await conn.connect()

    async def _wait_for_verack(self) -> None:
        if not await _wait_until(lambda: all(n.verack_received for n in self.test_nodes), 10):
            raise AssertionError("verack not received from all nodes")

    async def _ping_round(self) -> None:
        nonce = self.ping_counter
        for node in self.test_nodes:
            node.send_ping(nonce)
        await _wait_until(lambda: all(n.received_ping_response(nonce) for n in self.test_nodes))
        self.ping_counter += 1

    async def _await_block_request(self, blockhash: int, num_blocks: int) -> None:
        def requested() -> bool:
            return all(n.block_request_map.get(blockhash, False) for n in self.test_nodes)

        if not await _wait_until(requested, timeout=max(60, num_blocks)):
            raise AssertionError(f"not all nodes requested block {blockhash:#x}")
        await self._ping_round()  # the served block is processed

    async def _await_tx_request(self, txhash: int, num_events: int) -> None:
        def requested() -> bool:
            return all(n.tx_request_map.get(txhash, False) for n in self.test_nodes)

        if not await _wait_until(requested, timeout=max(60, num_events)):
            raise AssertionError(f"not all nodes requested transaction {txhash:#x}")
        await self._ping_round()

    async def check_results(self, block: CBlock, outcome: bool | None) -> bool:
        tips = [await node.rpc.getbestblockhash() for node in self.nodes]
        if outcome is None:
            return all(tip == tips[0] for tip in tips)
        return all((tip == block.hash) == outcome for tip in tips)

    async def check_mempool(self, tx: CTransaction, outcome: bool | None) -> bool:
        pools = [set(await node.rpc.getrawmempool()) for node in self.nodes]
        if outcome is None:
            return all(pool == pools[0] for pool in pools)
        return all((tx.hash in pool) == outcome for pool in pools)

    async def run(self) -> None:
        await self._wait_for_verack()
        test_number = 0
        async for test_instance in self.test_generator.get_tests():
            test_number += 1
            block: CBlock | None = None
            block_outcome: bool | None = None
            tx: CTransaction | None = None
            tx_outcome: bool | None = None
            invqueue: list[CInv] = []

            for b_or_t, outcome in test_instance.blocks_and_transactions:
                if isinstance(b_or_t, CBlock):
                    block, block_outcome = b_or_t, outcome
                    self.block_store.add_block(block)
                    assert block.sha256 is not None
                    for node in self.test_nodes:
                        node.block_request_map[block.sha256] = False
                    if test_instance.sync_every_block:
                        for node in self.test_nodes:
                            node.send_inv(block)
                        await self._await_block_request(block.sha256, 1)
                        if not await self.check_results(block, outcome):
                            raise AssertionError(f"block {test_number}: {block.hash} != {outcome}")
                    else:
                        invqueue.append(CInv(MSG_BLOCK, block.sha256))
                else:
                    assert isinstance(b_or_t, CTransaction)
                    tx, tx_outcome = b_or_t, outcome
                    self.tx_store.add_transaction(tx)
                    assert tx.sha256 is not None
                    for node in self.test_nodes:
                        node.tx_request_map[tx.sha256] = False
                    if test_instance.sync_every_tx:
                        for node in self.test_nodes:
                            node.send_inv(tx)
                        await self._await_tx_request(tx.sha256, 1)
                        if not await self.check_mempool(tx, outcome):
                            raise AssertionError(f"mempool {test_number}: {tx.hash} != {outcome}")
                    else:
                        invqueue.append(CInv(MSG_TX, tx.sha256))
                if len(invqueue) == MAX_INV_SZ:
                    for conn in self.connections:
                        conn.send_message(msg_inv(invqueue))
                    invqueue = []

            if not test_instance.sync_every_block and block is not None:
                if invqueue:
                    for conn in self.connections:
                        conn.send_message(msg_inv(invqueue))
                    invqueue = []
                assert block.sha256 is not None
                count = len(test_instance.blocks_and_transactions)
                await self._await_block_request(block.sha256, count)
                if not await self.check_results(block, block_outcome):
                    raise AssertionError(f"block {test_number}: {block.hash} != {block_outcome}")
            if not test_instance.sync_every_tx and tx is not None:
                if invqueue:
                    for conn in self.connections:
                        conn.send_message(msg_inv(invqueue))
                    invqueue = []
                assert tx.sha256 is not None
                await self._await_tx_request(tx.sha256, len(test_instance.blocks_and_transactions))
                if not await self.check_mempool(tx, tx_outcome):
                    raise AssertionError(f"mempool test {test_number}: {tx.hash} != {tx_outcome}")

        for conn in self.connections:
            await conn.disconnect_node()
        await _wait_until(lambda: all(n.closed for n in self.test_nodes), 10)
