"""The mininode equihash solver matches the daemon and solves regtest blocks fast."""

import io
import time

from conftest import POW_ARGS, NodeFactory
from fluxtest.mininode import CBlock


async def test_equihash_solver(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    block_hash = (await node.mine(1))[0]
    block = CBlock()
    block.deserialize(io.BytesIO(bytes.fromhex(await node.rpc.getblock(block_hash, 0))))

    # Correctness: the recomputed hash matches the daemon, and the solver
    # validates the daemon's own equihash solution -- which only holds if the
    # personalization and (n, k) match the regtest proof of work.
    block.rehash()
    assert block.hash == block_hash
    assert block.is_valid()

    # Speed: re-solving the header from scratch at the regtest (48, 5) parameters
    # takes a fraction of a second in pure python.
    block.nSolution = []
    block.nNonce = 0
    start = time.monotonic()
    block.solve()
    elapsed = time.monotonic() - start
    assert block.is_valid()
    assert elapsed < 30
