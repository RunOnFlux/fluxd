#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test fluxnode cache crash-recovery (RecoverFluxnodeCache).

The fluxnode DB persists a sync-state marker naming the block its data
reflects; at startup, recovery compares the marker against the active chain
and rewinds/replays as needed. Scenarios:

- clean restart: recovery must NOT run ("sync state matches chain tip")
- stale marker (hash unknown to the block index): repaired ONCE — the forced
  PersistToDisk must actually write the fresh marker even though the cache is
  clean — and the next restart must skip recovery (if the repair silently
  skipped the write, recovery would re-run on every restart)
- marker behind the tip on the active chain: chainstate disconnect + replay,
  node converges back to the same tip
- marker on a stale fork (the crash-during-reorg shape): fluxnode-only rewind
  along the marker's chain followed by the chainstate disconnect; node
  converges to the best tip

Marker divergence is manufactured with directory snapshots of
<datadir>/regtest/determ_zelnodes taken between restarts — i.e. only fluxd's
own leveldb writes. plyvel must NEVER open a DB directory the daemon will
reopen: the daemon's bundled leveldb is older and built without snappy,
while merely OPENING a DB with modern plyvel compacts the write-ahead log
into snappy-compressed tables (poisoning the DB — the daemon then dies with
"corrupted compressed block contents") and its explicit writes land in a
MANIFEST the old leveldb silently ignores. Marker assertions therefore read
a throwaway COPY of the DB directory (key = b's', value = 32-byte block hash
in internal byte order + int32-LE height, no obfuscation). The stale-marker
scenario takes its foreign fluxnode DB from a second, never-connected node
whose blocks node0 has never seen.

Requires the 'plyvel' python package (pip install plyvel).
"""

import os
import shutil
import struct
import time

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
        self.num_nodes = 2

    def setup_chain(self):
        print(f"Initializing test directory {self.options.tmpdir}")
        initialize_chain_clean(self.options.tmpdir, self.num_nodes)

    def setup_network(self, split=False):
        # node1 exists only to produce a foreign fluxnode DB for the
        # stale-marker scenario; the nodes are never connected. Regtest
        # mining is deterministic enough that two isolated nodes produce
        # identical block hashes, so node1 runs on a mocked clock to force
        # its chain to genuinely diverge — its marker hash must be unknown
        # to node0's block index.
        self.nodes = [
            start_node(0, self.options.tmpdir, ["-debug"]),
            start_node(1, self.options.tmpdir, ["-debug", "-mocktime=1900000000"]),
        ]
        self.is_network_split = False

    # --- fluxnode DB helpers ----------------------------------------------

    def fluxnode_db_path(self, node_index=0):
        return os.path.join(self.options.tmpdir, f"node{node_index}",
                            "regtest", "determ_zelnodes")

    def read_marker(self):
        """Read the marker from a throwaway copy: plyvel must never open the
        live DB directory (see module docstring)."""
        src = self.fluxnode_db_path()
        tmp = src + ".inspect"
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.copytree(src, tmp)
        db = plyvel.DB(tmp)
        try:
            raw = db.get(b"s")
            assert raw is not None and len(raw) == 36, f"unexpected marker record: {raw!r}"
            block_hash = raw[:32][::-1].hex()
            height = struct.unpack("<i", raw[32:36])[0]
            return block_hash, height
        finally:
            db.close()
            shutil.rmtree(tmp, ignore_errors=True)

    def snapshot_db(self, name):
        src = self.fluxnode_db_path()
        dst = src + "." + name
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(src, dst)

    def restore_db(self, name, from_node=0):
        src = self.fluxnode_db_path(from_node) + ("." + name if name else "")
        dst = self.fluxnode_db_path()
        shutil.rmtree(dst)
        shutil.copytree(src, dst)

    # --- debug.log helpers ------------------------------------------------

    def debug_log_path(self):
        return os.path.join(self.options.tmpdir, "node0", "regtest", "debug.log")

    def mark_log(self):
        return os.path.getsize(self.debug_log_path())

    def log_since(self, offset):
        with open(self.debug_log_path(), "r", errors="replace") as f:
            f.seek(offset)
            return f.read()

    # --- node lifecycle -----------------------------------------------------

    def restart_node0(self):
        offset = self.mark_log()
        self.nodes[0] = start_node(0, self.options.tmpdir, ["-debug"])
        return offset

    def stop0(self):
        stop_node(self.nodes[0], 0)

    # --- the test -------------------------------------------------------------

    def run_test(self):
        node = self.nodes[0]

        # node1: mine a short foreign chain (same genesis, blocks node0 has
        # never seen) and capture its fluxnode DB, then retire it.
        self.nodes[1].generate(5)
        stop_node(self.nodes[1], 1)

        print("Mining 40 blocks on node0...")
        node.generate(40)
        self.stop0()
        self.snapshot_db("h40")            # marker = active-chain block at height 40

        print("Mining 10 more blocks...")
        self.restart_node0()
        node = self.nodes[0]
        node.generate(10)
        tip_hash = node.getbestblockhash()
        tip_height = node.getblockcount()
        assert_equal(tip_height, 50)
        self.stop0()

        # Sanity: a clean shutdown leaves the marker at the tip.
        marker_hash, marker_height = self.read_marker()
        assert_equal(marker_hash, tip_hash)
        assert_equal(marker_height, tip_height)

        print("Clean restart: recovery must not run...")
        offset = self.restart_node0()
        log = self.log_since(offset)
        assert "no recovery needed" in log, "expected recovery skip on clean restart"
        assert "RecoverFluxnodeCache: disconnecting" not in log
        self.stop0()

        print("Stale marker (foreign DB): repaired once, then skipped...")
        self.snapshot_db("clean50")
        self.restore_db("", from_node=1)   # node1's DB: marker unknown to node0
        offset = self.restart_node0()
        log = self.log_since(offset)
        assert "stale marker" in log, "expected stale-marker repair path"
        self.stop0()
        # The forced persist must have actually written the fresh marker even
        # though the cache was clean.
        marker_hash, marker_height = self.read_marker()
        assert_equal(marker_hash, tip_hash)
        assert_equal(marker_height, tip_height)
        offset = self.restart_node0()
        log = self.log_since(offset)
        assert "no recovery needed" in log, \
            "stale-marker repair did not stick: recovery re-ran on the next restart"
        self.stop0()

        print("Marker behind the tip: disconnect and replay...")
        self.restore_db("h40")
        offset = self.restart_node0()
        log = self.log_since(offset)
        assert "RecoverFluxnodeCache: disconnecting 10 blocks" in log, \
            "expected a 10-block chainstate disconnect"
        node = self.nodes[0]
        assert_equal(node.getblockcount(), tip_height)
        assert_equal(node.getbestblockhash(), tip_hash)
        self.stop0()
        self.snapshot_db("forkA")          # marker = tip A (height 50)

        print("Marker on a stale fork: fluxnode-only rewind along the marker's chain...")
        # Manufacture a fork: invalidate tip A and mine a longer chain B,
        # leaving A as a stale fork block in the index. Then restore the
        # snapshot whose marker points at A.
        self.restart_node0()
        node = self.nodes[0]
        fork_hash = node.getbestblockhash()            # A, height 50
        assert_equal(fork_hash, tip_hash)
        node.invalidateblock(fork_hash)
        assert_equal(node.getblockcount(), 49)
        # Regtest mining is deterministic: without a clock shift, re-mining at
        # height 50 reproduces the exact block that was just invalidated and
        # the daemon rejects it. Mock the clock forward so chain B's blocks
        # get different timestamps (and therefore different hashes).
        node.setmocktime(int(time.time()) + 3600)
        node.generate(2)                               # chain B, height 51
        node.setmocktime(0)
        new_tip_hash = node.getbestblockhash()
        assert_equal(node.getblockcount(), 51)
        self.stop0()

        self.restore_db("forkA")
        offset = self.restart_node0()
        log = self.log_since(offset)
        assert "rewinding 1 blocks of fluxnode state along the marker's chain" in log, \
            "expected the marker-chain fluxnode-only rewind"
        assert "RecoverFluxnodeCache: disconnecting 2 blocks" in log, \
            "expected the 2-block chainstate disconnect to the common ancestor"
        node = self.nodes[0]
        assert_equal(node.getblockcount(), 51)
        assert_equal(node.getbestblockhash(), new_tip_hash)
        self.stop0()

        # After the recovery + clean shutdown the marker sits at the new tip.
        marker_hash, marker_height = self.read_marker()
        assert_equal(marker_hash, new_tip_hash)
        assert_equal(marker_height, 51)

        # Leave running nodes behind so the framework teardown is happy.
        self.restart_node0()
        self.nodes[1] = start_node(1, self.options.tmpdir, ["-debug"])

        print("All fluxnode cache recovery scenarios passed.")


if __name__ == '__main__':
    FluxnodeCacheRecoveryTest().main()
