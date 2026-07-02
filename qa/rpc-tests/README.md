Regression tests of the RPC and P2P interfaces
==============================================

A python3 + pytest + asyncio suite. Each test starts its own regtest fluxd
nodes (via the `node_factory` fixture in [conftest.py](conftest.py)) and talks
to them over JSON-RPC ([fluxtest/rpc.py](fluxtest/rpc.py)) or raw P2P
([fluxtest/mininode.py](fluxtest/mininode.py)).

Layout
------

* [conftest.py](conftest.py) — fixtures: node startup/teardown, unique port
  allocation, the `--fluxd`/`BITCOIND` binary option.
* [fluxtest/](fluxtest/) — the framework package: RPC client, node process
  management, network wiring/sync helpers, the asyncio mininode with a regtest
  equihash solver, block construction, the comparison harness (`comptool`),
  and the regtest difficulty rule (`pow`).
* [zhelpers.py](zhelpers.py) — shared helpers for the shielded (`z_*`) tests:
  async-operation polling and the ACADIA/PoW argument sets.
* `test_*.py` — the tests. Support modules some of them share sit alongside
  (`_bip_enforcement.py`, `socks5.py`, `zmq_sub.py`, `netutil.py`,
  `alertnotify.py`, `addressindex_dup_output_tx.py`).

Running
-------

From the `qa/` directory (the pytest rootdir), with
[uv](https://docs.astral.sh/uv/) installed:

```bash
BITCOIND=/path/to/fluxd uv run pytest rpc-tests/                 # everything
BITCOIND=/path/to/fluxd uv run pytest rpc-tests/ -m 'not slow'   # skip the minutes-long tests
BITCOIND=/path/to/fluxd uv run pytest rpc-tests/test_wallet.py   # one file
```

The daemon binary can also be passed as `--fluxd=/path/to/fluxd`. Nodes run in
pytest's per-test temporary directories and are stopped (and their datadirs
discarded) automatically, including on failure.

Regtest notes
-------------

* Wallet funding: tests run with `-ponactivation=1000000` so regtest mines
  PoW blocks whose coinbase pays the wallet (under PON the coinbase goes to
  the dev fund). Block 1 carries the 13.02M premine; later coinbases are
  ~150 each, and a coinbase input forbids change in `z_sendmany`.
* Shielded behaviour (Sapling AND Sprout transaction creation) is gated on the
  ACADIA upgrade: tests pass `-acadiaactivation=<height>` (see
  `zhelpers.shielded_args`).
* Every node's clock is frozen with `setmocktime` at start; use the
  `FluxNode.mine` / `advance_mocktime` / `fluxtest.network.bump_clocks`
  helpers rather than sleeping.
