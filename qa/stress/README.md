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
| 7 | Mixed legacy-PON / VRF fork choice on pruned entries | gtest (`test_pon.cpp`, see below) | gtest |
| 8 | Fresh-peer IBD served entirely by patched nodes (block + header disk reads at sustained rate) | `ibd_sync.sh` | spare host → fleet |

## Notes per test

**1 — header_storm.py** (python3, stdlib only). Speaks the P2P protocol
directly: handshake, then N concurrent connections each walking the entire
header chain from genesis in 2000-header `getheaders` strides (~1340
requests per walk at current height). Every header is parsed per its
version's wire format and validated: PoW headers must carry a non-zero
nonce, non-empty equihash solution and non-zero merkle root (the fields that
were zeroed by the pre-fix serving bug); PON headers a non-empty block
signature. The serving node must stay responsive (the script interleaves
`ping` round-trip timing as a stall probe).

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
then restarts and asserts the recovery path engages cleanly
(`RecoverFluxnodeCache: … no recovery needed` or a bounded
disconnect/replay; never an abort, never a recovery loop) and that the node
returns to the pre-kill tip.

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

**7 — mixed fork choice** is covered at the gtest level
(`src/gtest/test_pon.cpp`: `MixedVersionForkChoice*`,
`ForkChoicePrunedEntries*`): producing real PON/VRF blocks in regtest
requires staked fluxnode infrastructure, but the comparator itself is a pure
function of resident index fields — the gtests pit legacy entries (cached
`hashPON`, `pHeaderData` deliberately null to model a pruned entry) against
VRF entries and assert determinism, antisymmetry, and that comparison never
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
