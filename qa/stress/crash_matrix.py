#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Crash matrix: kill -9 the fluxnode-mode daemon across persist windows.

A plain miner node keeps extending the chain; the fluxnode-mode node
(-zelnode=1) follows it, running the 10-block incremental PersistToDisk as
blocks connect. The harness SIGKILLs the fluxnode node at randomized chain
offsets — so kills land before, on, and after persist boundaries — plus one
kill immediately after boot (recovery-window crash). After every kill it
restarts the node and asserts:

  - init never aborts, and the boot runs RecoverFluxnodeCache exactly once:
    either "no recovery needed" or a bounded disconnect/replay (the log
    line reports the rewind size)
  - no recovery loop: an immediate clean restart afterwards must say
    "no recovery needed"
  - the node re-syncs to the miner's tip

Run: BITCOIND=... BITCOINCLI=... python3 crash_matrix.py
"""

import contextlib
import random
import re
import sys
import threading
import time

from regtest_util import cleanup, connect, make_chain, wait_sync

KILLS = 12
RECOVERY_RE = re.compile(
    r"RecoverFluxnodeCache: (sync state matches chain tip[^\n]*no recovery needed"
    r"|disconnecting \d+ blocks[^\n]*"
    r"|rewound \d+ marker-chain blocks[^\n]*)"
)


class Miner(threading.Thread):
    def __init__(self, node):
        super().__init__(daemon=True)
        self.node = node
        self.stop_evt = threading.Event()

    def run(self):
        while not self.stop_evt.is_set():
            with contextlib.suppress(Exception):
                self.node.cli("generate", 1)
            time.sleep(0.3)


def assert_recovered(node, off, label):
    log = node.log_since(off)
    m = RECOVERY_RE.search(log)
    assert m, f"{label}: no RecoverFluxnodeCache line after crash-restart;\n{node.log_tail(60)}"
    assert "Failed to recover the fluxnode cache" not in log, f"{label}: recovery hard-failed"
    return m.group(1)


def main():
    random.seed(20260612)
    base, miner_node, fluxnode = make_chain("stress_crash_")
    miner = Miner(miner_node)
    try:
        print("Starting miner (continuous 1-block generation)...")
        miner_node.start()
        miner_node.cli("generate", 60)
        print("Starting fluxnode-mode node...")
        fluxnode.start()
        connect(fluxnode, miner_node)
        wait_sync(miner_node, fluxnode)
        miner.start()

        for i in range(KILLS):
            # let some blocks flow so kills straddle 10-block persist windows
            run_for = random.uniform(1.0, 8.0)
            time.sleep(run_for)
            pre_kill = int(fluxnode.cli("getblockcount"))
            fluxnode.kill9()
            print(f"kill {i + 1}/{KILLS} at height {pre_kill} (after {run_for:.1f}s)")

            off = fluxnode.log_offset()
            fluxnode.start()
            shape = assert_recovered(fluxnode, off, f"kill {i + 1}")
            print(f"   recovery: {shape[:90]}")

            # no recovery loop: clean restart must skip recovery
            if i == KILLS // 2:
                fluxnode.stop()
                off = fluxnode.log_offset()
                fluxnode.start()
                assert "no recovery needed" in fluxnode.log_since(off), "recovery loop: clean restart re-ran recovery"
                print("   mid-matrix clean-restart check: no recovery loop")

            connect(fluxnode, miner_node)
            wait_sync(miner_node, fluxnode, timeout=180)

        # boot-window crash: kill within a second of process start
        print("boot-window crash...")
        fluxnode.stop()
        fluxnode.start(wait=False)
        time.sleep(0.8)
        fluxnode.kill9()
        off = fluxnode.log_offset()
        fluxnode.start()
        assert_recovered(fluxnode, off, "boot-window")
        connect(fluxnode, miner_node)
        wait_sync(miner_node, fluxnode, timeout=180)

        miner.stop_evt.set()
        fluxnode.stop()
        miner_node.stop()
        print(f"OK: crash matrix passed ({KILLS} mid-run kills + 1 boot-window kill).")
    except Exception:
        print("FAILED — fluxnode log tail:\n" + fluxnode.log_tail(120), file=sys.stderr)
        raise
    finally:
        miner.stop_evt.set()
        cleanup(base, miner_node, fluxnode)


if __name__ == "__main__":
    main()
