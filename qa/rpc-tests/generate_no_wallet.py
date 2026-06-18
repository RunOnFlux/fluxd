#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Regression test for the mining RPC null coinbase-script guard.

When fluxd runs with no script provider for the coinbase (no wallet and no
-mineraddress, e.g. -disablewallet), ScriptForMining yields a null
CReserveScript. The mining entry points must report a clean RPC error rather
than dereference the null pointer and crash the daemon.

  node 0 (-disablewallet): `generate` returns RPC_INTERNAL_ERROR with the
                           "No coinbase script available" message, and the
                           daemon stays alive afterwards.
  node 1 (default wallet):  `generate` still mints a block (the guard does not
                           regress the normal path).
"""

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    initialize_chain_clean,
    start_nodes,
)

RPC_INTERNAL_ERROR = -32603


class GenerateNoWalletTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 2

    def setup_chain(self):
        print(f"Initializing test directory {self.options.tmpdir}")
        initialize_chain_clean(self.options.tmpdir, self.num_nodes)

    def setup_network(self, split=False):
        # Two independent nodes; no peering needed for this test.
        self.nodes = start_nodes(
            self.num_nodes,
            self.options.tmpdir,
            extra_args=[["-disablewallet"], []],
        )
        self.is_network_split = False

    def run_test(self):
        nowallet = self.nodes[0]

        # Without a coinbase-script provider, generate must error cleanly.
        try:
            nowallet.generate(1)
            raise AssertionError("generate succeeded with -disablewallet")
        except JSONRPCException as e:
            assert_equal(e.error["code"], RPC_INTERNAL_ERROR)
            assert "No coinbase script available" in e.error["message"], (
                f"unexpected error message: {e.error['message']}"
            )

        # The daemon must still be alive (pre-fix this dereferenced null and
        # crashed, so the next RPC would fail with a connection error).
        assert_equal(nowallet.getblockcount(), 0)

        # The guard must not regress the normal path: a node with a wallet
        # still mints.
        wallet = self.nodes[1]
        wallet.generate(1)
        assert_equal(wallet.getblockcount(), 1)


if __name__ == "__main__":
    GenerateNoWalletTest().main()
