# Copyright (c) 2014 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

"""Base classes for the RPC integration tests."""

import argparse
import logging
import os
import shutil
import sys
import tempfile
import traceback

from .authproxy import AuthServiceProxy, JSONRPCException
from .util import (
    assert_equal,
    check_json_precision,
    connect_nodes_bi,
    initialize_chain,
    initialize_chain_clean,
    start_nodes,
    stop_nodes,
    sync_blocks,
    sync_mempools,
    wait_bitcoinds,
)

logger = logging.getLogger("TestFramework")


def _configure_logging(verbose: bool) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
        )
    )
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.DEBUG if verbose else logging.INFO)


class BitcoinTestFramework:
    def __init__(self) -> None:
        self.nodes: list[AuthServiceProxy] = []
        self.is_network_split = False
        self.options = argparse.Namespace()

    # These may be overridden by subclasses.
    def run_test(self) -> None:
        for node in self.nodes:
            assert_equal(node.getblockcount(), 200)
            assert_equal(node.getbalance(), 25 * 10)

    def add_options(self, parser: argparse.ArgumentParser) -> None:
        pass

    def setup_chain(self) -> None:
        logger.info("Initializing test directory %s", self.options.tmpdir)
        initialize_chain(self.options.tmpdir)

    def setup_nodes(self) -> list[AuthServiceProxy]:
        return start_nodes(4, self.options.tmpdir)

    def setup_network(self, split: bool = False) -> None:
        self.nodes = self.setup_nodes()

        # Connect the nodes as a "chain" so the network can later be split
        # between nodes 1 and 2 into two halves working on competing chains.
        if not split:
            connect_nodes_bi(self.nodes, 1, 2)
            sync_blocks(self.nodes[1:3])
            sync_mempools(self.nodes[1:3])

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 2, 3)
        self.is_network_split = split
        self.sync_all()

    def split_network(self) -> None:
        """Split the network of four nodes into nodes 0/1 and 2/3."""
        assert not self.is_network_split
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.setup_network(True)

    def sync_all(self) -> None:
        if self.is_network_split:
            sync_blocks(self.nodes[:2])
            sync_blocks(self.nodes[2:])
            sync_mempools(self.nodes[:2])
            sync_mempools(self.nodes[2:])
        else:
            sync_blocks(self.nodes)
            sync_mempools(self.nodes)

    def join_network(self) -> None:
        """Join the (previously split) network halves back together."""
        assert self.is_network_split
        stop_nodes(self.nodes)
        wait_bitcoinds()
        self.setup_network(False)

    def main(self) -> None:
        parser = argparse.ArgumentParser(description=self.__class__.__name__)
        parser.add_argument(
            "--nocleanup",
            action="store_true",
            help="Leave fluxds and test.* datadir on exit or error",
        )
        parser.add_argument(
            "--noshutdown",
            action="store_true",
            help="Don't stop fluxds after the test execution",
        )
        parser.add_argument(
            "--srcdir",
            default="../../src",
            help="Source directory containing fluxd/flux-cli (default: %(default)s)",
        )
        parser.add_argument(
            "--tmpdir",
            default=tempfile.mkdtemp(prefix="test"),
            help="Root directory for datadirs",
        )
        parser.add_argument(
            "--tracerpc",
            action="store_true",
            help="Log all RPC calls as they are made",
        )
        self.add_options(parser)
        self.options = parser.parse_args()

        _configure_logging(self.options.tracerpc)

        os.environ["PATH"] = self.options.srcdir + os.pathsep + os.environ["PATH"]

        check_json_precision()

        success = False
        try:
            os.makedirs(self.options.tmpdir, exist_ok=True)
            self.setup_chain()
            self.setup_network()
            self.run_test()
            success = True
        except JSONRPCException as e:
            logger.error("JSONRPC error: %s", e.error["message"])
            traceback.print_tb(sys.exc_info()[2])
        except AssertionError as e:
            logger.error("Assertion failed: %s", e)
            traceback.print_tb(sys.exc_info()[2])
        except Exception as e:
            logger.error("Unexpected exception caught during testing: %r", e)
            traceback.print_tb(sys.exc_info()[2])

        if not self.options.noshutdown:
            logger.info("Stopping nodes")
            stop_nodes(self.nodes)
            wait_bitcoinds()
        else:
            logger.info("Note: fluxds were not stopped and may still be running")

        if not self.options.nocleanup and not self.options.noshutdown:
            logger.info("Cleaning up")
            shutil.rmtree(self.options.tmpdir)

        if success:
            logger.info("Tests successful")
            sys.exit(0)
        else:
            logger.error("Failed")
            sys.exit(1)


# Test framework for doing p2p comparison testing, which sets up some fluxd
# binaries:
#   1 binary:  test binary
#   2 binaries: 1 test binary, 1 ref binary
#   n>2 binaries: 1 test binary, n-1 ref binaries
class ComparisonTestFramework(BitcoinTestFramework):
    # Can override num_nodes to indicate how many nodes to run.
    def __init__(self) -> None:
        super().__init__()
        self.num_nodes = 2

    def add_options(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--testbinary",
            default=os.getenv("BITCOIND", "fluxd"),
            help="fluxd binary to test",
        )
        parser.add_argument(
            "--refbinary",
            default=os.getenv("BITCOIND", "fluxd"),
            help="fluxd binary to use for reference nodes (if any)",
        )

    def setup_chain(self) -> None:
        logger.info("Initializing test directory %s", self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, self.num_nodes)

    def setup_network(self, split: bool = False) -> None:
        self.nodes = start_nodes(
            self.num_nodes,
            self.options.tmpdir,
            extra_args=[["-debug", "-whitelist=127.0.0.1"]] * self.num_nodes,
            binary=[self.options.testbinary] + [self.options.refbinary] * (self.num_nodes - 1),
        )
