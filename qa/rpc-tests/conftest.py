"""Shared pytest fixtures for the asyncio RPC integration tests."""

import itertools
import os
import socket
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path

import pytest
import pytest_asyncio
from fluxtest.node import FluxNode

NodeFactory = Callable[..., Awaitable[FluxNode]]

# Pushing PON past the test makes regtest mine PoW blocks, whose coinbase pays
# the wallet -- under PON the coinbase is redirected to the dev-fund address, so
# the wallet cannot otherwise be funded by mining.
POW_ARGS = ["-ponactivation=1000000"]
COINBASE_MATURITY = 100

# Ports for regtest nodes are drawn from a band below the ephemeral range
# (ip_local_port_range starts at 32768), so the kernel never auto-assigns one of
# these as an outbound source port. The counter only moves forward, so no two
# nodes in a run ever share a port: reusing one can leave a node unable to bind
# its P2P listener (EADDRINUSE) when a prior node's socket on that port has not
# been released, and a node with no listener cannot be connected to. The bind
# probe steps over anything else already holding a port.
_PORT_LO, _PORT_HI = 12000, 16000
_port_seq = itertools.count(os.getpid() % (_PORT_HI - _PORT_LO))


def claim_free_port() -> int:
    span = _PORT_HI - _PORT_LO
    for _ in range(span):
        port = _PORT_LO + (next(_port_seq) % span)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind(("0.0.0.0", port))
            except OSError:
                continue  # in use right now -- skip and never return to it
        return port
    raise RuntimeError(f"no free port in {_PORT_LO}-{_PORT_HI}")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--fluxd",
        default=os.getenv("BITCOIND", "fluxd"),
        help="Path to the fluxd binary under test",
    )


@pytest.fixture
def fluxd_binary(request: pytest.FixtureRequest) -> str:
    return request.config.getoption("--fluxd")


@pytest_asyncio.fixture
async def node_factory(fluxd_binary: str, tmp_path: Path) -> AsyncIterator[NodeFactory]:
    """Start regtest fluxd nodes on demand and stop them after the test."""
    nodes: list[FluxNode] = []

    async def make(index: int = 0, extra_args: list[str] | None = None) -> FluxNode:
        node = FluxNode(
            index=index,
            datadir=tmp_path / f"node{index}",
            binary=fluxd_binary,
            rpc_port=claim_free_port(),
            p2p_port=claim_free_port(),
            extra_args=extra_args,
        )
        await node.start()
        nodes.append(node)
        return node

    yield make

    for node in nodes:
        await node.stop()


@pytest_asyncio.fixture
async def funded_node(node_factory: NodeFactory) -> FluxNode:
    """A single PoW-mode regtest node with a matured, spendable balance."""
    node = await node_factory(0, extra_args=POW_ARGS)
    await node.mine(COINBASE_MATURITY + 1)  # mature block 1's coinbase
    return node
