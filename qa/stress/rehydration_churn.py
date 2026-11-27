#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Rehydration churn: HeaderData restore on reorgs + flush-side restore.

Setup: a plain miner node builds a 350-block regtest chain; a fluxnode-mode
node (-zelnode=1) syncs it, then restarts so the load-time HeaderData prune
runs over the whole index. The churn then forces the rehydration paths:

  - repeated deep invalidateblock/reconsiderblock cycles (each disconnect
    rehydrates HeaderData for the disconnected blocks; each reconnect
    re-dirties the entries)
  - getblockheader spot checks at random pruned depths after every cycle
    (served fields must be real, never zeroed)
  - a clean stop while entries are dirty-and-pruned (the flush must restore
    header data from disk before serializing — writing zeroes was the M2
    failure shape), then a final restart proving the leveldb still
    round-trips and the chain re-validates

Run: BITCOIND=... BITCOINCLI=... python3 rehydration_churn.py
"""

import json
import random
import sys

from regtest_util import cleanup, connect, make_chain, wait_sync

CHAIN_HEIGHT = 350
CYCLES = 25


def check_header(node, height):
    h = node.cli("getblockhash", height)
    hdr = json.loads(node.cli("getblockheader", h))
    assert hdr["merkleroot"] != "0" * 64, f"zeroed merkleroot at height {height}"
    if hdr.get("nonce"):
        assert hdr["nonce"] != "0" * 64, f"zeroed nonce at height {height}"
    return hdr


def main():
    random.seed(20260612)
    base, miner, fluxnode = make_chain("stress_rehydrate_")
    try:
        print(f"Starting miner; building {CHAIN_HEIGHT}-block chain...")
        miner.start()
        miner.cli("generate", 100)
        miner.cli("generate", CHAIN_HEIGHT - 100)

        print("Starting fluxnode-mode node and syncing...")
        fluxnode.start()
        connect(fluxnode, miner)
        wait_sync(miner, fluxnode)

        print("Restarting fluxnode node (load-time HeaderData prune)...")
        fluxnode.stop()
        off = 0
        fluxnode.start()
        assert "no recovery needed" in fluxnode.log_since(off) or "no recovery needed" in fluxnode.log_tail(), (
            "clean restart must skip recovery"
        )

        tip = int(fluxnode.cli("getblockcount"))
        assert tip == CHAIN_HEIGHT
        print(f"Churn: {CYCLES} invalidate/reconsider cycles...")
        for i in range(CYCLES):
            depth = random.randint(20, 250)
            target = tip - depth
            inv_hash = fluxnode.cli("getblockhash", target + 1)
            fluxnode.cli("invalidateblock", inv_hash)  # disconnect = rehydrate
            now = int(fluxnode.cli("getblockcount"))
            assert now == target, f"cycle {i}: expected tip {target} after invalidate, got {now}"
            fluxnode.cli("reconsiderblock", inv_hash)  # reconnect = re-dirty
            now = int(fluxnode.cli("getblockcount"))
            assert now == tip, f"cycle {i}: expected tip {tip} after reconsider, got {now}"
            check_header(fluxnode, random.randint(1, tip - 1))
            if (i + 1) % 5 == 0:
                print(f"  cycle {i + 1}/{CYCLES} ok (depth {depth})")

        print("Clean stop with dirty pruned entries (flush-side restore)...")
        deep = fluxnode.cli("getblockhash", 30)
        fluxnode.cli("invalidateblock", deep)  # dirties a long range
        fluxnode.cli("reconsiderblock", deep)
        fluxnode.stop()  # flush must read from disk, not write zeroes

        print("Final restart: leveldb must round-trip...")
        fluxnode.start()
        assert int(fluxnode.cli("getblockcount")) == tip
        for h in random.sample(range(1, tip), 25):
            check_header(fluxnode, h)
        fluxnode.stop()
        miner.stop()
        print(f"OK: rehydration churn passed ({CYCLES} cycles, {CYCLES + 25} header spot checks).")
    except Exception:
        print("FAILED — fluxnode log tail:\n" + fluxnode.log_tail(120), file=sys.stderr)
        raise
    finally:
        cleanup(base, miner, fluxnode)


if __name__ == "__main__":
    main()
