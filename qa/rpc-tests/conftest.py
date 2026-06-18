"""Shared pytest fixtures for the asyncio RPC integration tests."""

import os
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
    # Per-process port base to keep concurrent test runs from colliding.
    port_base = 12000 + os.getpid() % 990

    async def make(index: int = 0, extra_args: list[str] | None = None) -> FluxNode:
        node = FluxNode(
            index=index,
            datadir=tmp_path / f"node{index}",
            binary=fluxd_binary,
            rpc_port=port_base + index,
            p2p_port=port_base + 500 + index,
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
