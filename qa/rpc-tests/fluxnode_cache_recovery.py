#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test fluxnode cache crash-recovery (RecoverFluxnodeCache).

Covers the M1/M7 fixes from the 2026-06 memory-branch review:

- clean restart: recovery must NOT run ("sync state matches chain tip")
- stale marker (hash unknown to the block index): repaired ONCE — the forced
  PersistToDisk must actually write the fresh marker even though the cache is
  clean (M7); the next restart must skip recovery (pre-M7 the repair was a
  silent no-op and recovery re-ran on every restart)
- marker behind the tip on the active chain: chainstate disconnect + replay,
  node converges back to the same tip
- marker on a stale fork (the crash-during-reorg shape): fluxnode-only rewind
  along the marker's chain (M1 phase 1) followed by the chainstate
  disconnect; node converges to the best tip

The sync marker is manipulated directly in <datadir>/regtest/determ_zelnodes
with plyvel while the node is stopped. Key = b's'; value = 32-byte block hash
in internal byte order followed by an int32-LE height. The DB is written by
the old-style CDBWrapper (no obfuscation key).

Requires the 'plyvel' python package (pip install plyvel).
"""

import os
import struct

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    initialize_chain_clean,
    start_node,
    stop_node,
)

import plyvel


class FluxnodeCacheRecoveryTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 1

    def setup_chain(self):
        print(f"Initializing test directory {self.options.tmpdir}")
        initialize_chain_clean(self.options.tmpdir, self.num_nodes)

    def setup_network(self, split=False):
        self.nodes = [start_node(0, self.options.tmpdir, ["-debug"])]
        self.is_network_split = False

    # --- fluxnode DB marker helpers -------------------------------------

    def fluxnode_db_path(self):
        return os.path.join(self.options.tmpdir, "node0", "regtest", "determ_zelnodes")

    def read_marker(self):
        db = plyvel.DB(self.fluxnode_db_path())
        try:
            raw = db.get(b"s")
            assert raw is not None and len(raw) == 36, f"unexpected marker record: {raw!r}"
            block_hash = raw[:32][::-1].hex()
            height = struct.unpack("<i", raw[32:36])[0]
            return block_hash, height
        finally:
            db.close()

    def write_marker(self, block_hash_hex, height):
        db = plyvel.DB(self.fluxnode_db_path())
        try:
            raw = bytes.fromhex(block_hash_hex)[::-1] + struct.pack("<i", height)
            db.put(b"s", raw)
        finally:
            db.close()

    # --- debug.log helpers ----------------------------------------------

    def debug_log_path(self):
        return os.path.join(self.options.tmpdir, "node0", "regtest", "debug.log")

    def mark_log(self):
        return os.path.getsize(self.debug_log_path())

    def log_since(self, offset):
        with open(self.debug_log_path(), "r", errors="replace") as f:
            f.seek(offset)
            return f.read()

    # --- node lifecycle ---------------------------------------------------

    def restart_node(self):
        offset = self.mark_log()
        self.nodes[0] = start_node(0, self.options.tmpdir, ["-debug"])
        return offset

    def stop(self):
        stop_node(self.nodes[0], 0)

    # --- the test ---------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]

        print("Mining 50 blocks...")
        node.generate(50)
        tip_hash = node.getbestblockhash()
        tip_height = node.getblockcount()
        assert_equal(tip_height, 50)
        behind_hash = node.getblockhash(tip_height - 10)
        self.stop()

        # Sanity: a clean shutdown leaves the marker at the tip.
        marker_hash, marker_height = self.read_marker()
        assert_equal(marker_hash, tip_hash)
        assert_equal(marker_height, tip_height)

        print("Clean restart: recovery must not run...")
        offset = self.restart_node()
        log = self.log_since(offset)
        assert "no recovery needed" in log, "expected recovery skip on clean restart"
        assert "RecoverFluxnodeCache: disconnecting" not in log
        self.stop()

        print("Stale marker: repaired once, then skipped (M7)...")
        self.write_marker("ff" * 32, tip_height + 5)
        offset = self.restart_node()
        log = self.log_since(offset)
        assert "stale marker" in log, "expected stale-marker repair path"
        self.stop()
        # The forced persist must have actually written the fresh marker even
        # though the cache was clean — this is the M7 regression assertion.
        marker_hash, marker_height = self.read_marker()
        assert_equal(marker_hash, tip_hash)
        assert_equal(marker_height, tip_height)
        offset = self.restart_node()
        log = self.log_since(offset)
        assert "no recovery needed" in log, \
            "stale-marker repair did not stick: recovery re-ran on the next restart"
        self.stop()

        print("Marker behind the tip: disconnect and replay...")
        self.write_marker(behind_hash, tip_height - 10)
        offset = self.restart_node()
        log = self.log_since(offset)
        assert "RecoverFluxnodeCache: disconnecting 10 blocks" in log, \
            "expected a 10-block chainstate disconnect"
        node = self.nodes[0]
        assert_equal(node.getblockcount(), tip_height)
        assert_equal(node.getbestblockhash(), tip_hash)

        print("Marker on a stale fork: fluxnode-only rewind along the marker's chain (M1)...")
        # Manufacture a fork: invalidate the tip, mine a competing chain that
        # is longer, leaving the old tip as a stale fork block in the index.
        fork_hash = node.getbestblockhash()           # height 50, chain A
        node.invalidateblock(fork_hash)
        assert_equal(node.getblockcount(), 49)
        node.generate(2)                              # chain B, height 51
        new_tip_hash = node.getbestblockhash()
        assert_equal(node.getblockcount(), 51)
        self.stop()

        self.write_marker(fork_hash, 50)
        offset = self.restart_node()
        log = self.log_since(offset)
        assert "rewinding 1 blocks of fluxnode state along the marker's chain" in log, \
            "expected the marker-chain fluxnode-only rewind (M1 phase 1)"
        assert "RecoverFluxnodeCache: disconnecting 2 blocks" in log, \
            "expected the 2-block chainstate disconnect to the common ancestor"
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 51)
        assert_equal(node.getbestblockhash(), new_tip_hash)
        self.stop()

        # After the recovery + clean shutdown the marker sits at the new tip.
        marker_hash, marker_height = self.read_marker()
        assert_equal(marker_hash, new_tip_hash)
        assert_equal(marker_height, 51)

        # Leave a running node behind so the framework teardown is happy.
        self.restart_node()

        print("All fluxnode cache recovery scenarios passed.")


if __name__ == '__main__':
    FluxnodeCacheRecoveryTest().main()
