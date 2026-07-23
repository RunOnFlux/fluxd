# Bounded-blockindex stress suite

Deliberately exercises every new code path of the fluxnode memory work
(file-backed arena, HeaderData prune/rehydrate, incremental persist + crash
recovery, resident fork-choice) — not just the steady state the soak covers.

| # | Path exercised | Script | Where it runs |
|---|---|---|---|
| 1 | Header serving from pruned entries (disk header reads, no `cs_main` stalls) | `header_storm.py` | any host → mainnet node |
| 2 | HeaderData rehydration on reorg + flush-side restore of dirty pruned entries | `rehydration_churn.py` | regtest (build host) |
| 3 | Crash recovery: kill -9 across persist/reorg windows | `crash_matrix.py` | regtest (build host) |
| 4 | Arena eviction under hard memory pressure (no OOM, no swap) | `memory_pressure.sh` | mainnet node (operator) |
| 5 | Init transient + arena `O_TRUNC`/rebuild lifecycle | `restart_storm.sh` | mainnet node (operator) |
| 6 | Wallet rescan/merkle checks against pruned headers | `wallet_rescan.sh` | wallet node (operator) |
| 7 | PON fork choice on pruned entries | gtest (`test_pon.cpp`, see below) | gtest |
| 8 | Fresh-peer IBD served entirely by patched nodes (block + header disk reads at sustained rate) | `ibd_sync.sh` | spare host → fleet |

## Notes per test

**1 — header_storm.py** (python3, stdlib only). Speaks the P2P protocol
directly: handshake, then N concurrent connections each walking the entire
header chain from genesis in `getheaders` strides. Runs in two modes
matching the two serving paths: default advertises a pre-CMPHEADERS
protocol version so every stride is a full `headers` message (160/batch,
PoW solutions on the wire — the heaviest path), `--compact` advertises the
current version so checkpointed history arrives as `cmpheaders`
(2000/batch, solution omitted). Every header is parsed per its version's
wire format and validated: non-zero merkle root and chain continuity via
hashPrevBlock everywhere; PoW non-zero nonce (+ non-empty solution in
legacy mode); PON non-empty block signature.
The serving node must stay responsive (the script interleaves `ping`
round-trip timing as a stall probe).

**2 — rehydration_churn.py** (regtest, `-zelnode=1` so load-time pruning is
active). Mines a chain, restarts to prune it, then loops deep
`invalidateblock`/`reconsiderblock` cycles — every disconnect must rehydrate
HeaderData from disk; every reconnect re-dirties entries; the clean stop at
the end forces the flush-side restore (dirty-but-pruned entries must be
re-read from disk before serialization, never written as zeroes). A final
restart asserts the leveldb round-trips intact.

**3 — crash_matrix.py** (regtest, `-zelnode=1`). A background miner extends
the chain while the harness `kill -9`s the daemon at randomized offsets —
including inside the 10-block persist window and immediately after boot —
then restarts and asserts every boot takes a legitimate
`RecoverFluxnodeCache` outcome (never an abort, never a recovery loop) and
the node reconverges to the miner's tip. Note kill -9 on regtest usually
loses the recent unflushed chain wholesale, so the *specific*
marker-divergence recovery shapes are not deterministically reached here —
they are manufactured byte-exactly by `qa/rpc-tests/fluxnode_cache_recovery.py`;
this test adds the randomized-timing, always-converges guarantee on top.

**4 — memory_pressure.sh** (operator runbook — touches a mainnet node).
Re-runs the daemon inside a `systemd-run` scope with `MemoryHigh=500M` +
`MemorySwapMax=0` and logs RssAnon/RssFile/major-fault counters while the
node syncs to tip and (optionally) serves `header_storm.py` — cold arena
pages must evict and fault back, the process must not OOM and must use zero
swap.

**5 — restart_storm.sh** (operator runbook). N restart cycles asserting per
cycle: RPC comes back, the boot logs `no recovery needed`, `blockindex.arena`
is recreated and sized, and post-settle RssAnon stays in band.

**6 — wallet_rescan.sh** (operator runbook, needs a node with a wallet).
Restarts with `-rescan` and asserts zero transactions report `conflicted`
afterwards (the M3 failure shape: merkle checks against zeroed pruned
roots marked every confirmed tx conflicted).

**7 — fork choice** is covered at the gtest level
(`src/gtest/test_pon.cpp`: `ForkChoice*`,
`ForkChoicePrunedEntries*`): producing real PON blocks in regtest
requires staked fluxnode infrastructure, but the comparator itself is a pure
function of resident index fields — the gtests compare entries scored by the
cached `hashPON` (with `pHeaderData` deliberately null to model a pruned
entry) and assert determinism, antisymmetry, and that comparison never
touches prunable data.

**8 — ibd_sync.sh** (spare host with disk; build server works). Fresh
datadir, `connect=` lines pinned to the patched fleet only, `listen=0`. The
syncing peer pulls every historic block from the patched nodes — sustained
`getdata`/`getheaders` service from pruned entries — while the script logs
sync rate; check the serving fleet stays at tip with flat RssAnon during the
run (soak-check command).

## Regtest prerequisites

Build `fluxd`/`flux-cli`, then:

```
BITCOIND=/path/to/fluxd BITCOINCLI=/path/to/flux-cli python3 rehydration_churn.py
BITCOIND=/path/to/fluxd BITCOINCLI=/path/to/flux-cli python3 crash_matrix.py
```

Both create throwaway datadirs under `/tmp` and clean up on success.
