"""Fluxnode cache crash recovery (RecoverFluxnodeCache).

The fluxnode DB persists a sync-state marker naming the block its data reflects; at startup,
recovery compares the marker against the active chain and rewinds/replays as needed:

- clean restart: recovery does not run ("no recovery needed");
- stale marker (its block is unknown to the block index): repaired once — the forced
  PersistToDisk writes the fresh marker even though the cache is clean, so a node that crashes
  right after the repair restarts with no recovery to do;
- marker behind the tip on the active chain: chainstate disconnect and replay, back to the same
  tip;
- marker on a stale fork (the crash-during-reorg shape): fluxnode-only rewind along the marker's
  chain, then the chainstate disconnect; the node converges on the best tip.

Marker divergence is manufactured from copies of ``<datadir>/regtest/determ_zelnodes`` taken
between restarts — only fluxd's own leveldb writes. plyvel never opens a DB directory the daemon
will reopen: fluxd's bundled leveldb is older and built without snappy, and opening a DB with
modern plyvel compacts its write-ahead log into snappy-compressed tables the daemon cannot read.
Marker reads therefore use a throwaway copy (key ``b"s"``; value = 32-byte block hash in internal
byte order + int32-LE height). The stale-marker scenario takes its fluxnode DB from a second,
never-connected node whose blocks node0 has never seen.
"""

import shutil
import struct
from pathlib import Path

import plyvel
from conftest import POW_ARGS, NodeFactory
from fluxtest.node import FluxNode


def _db(node: FluxNode) -> Path:
    return node.datadir / "regtest" / "determ_zelnodes"


def _debug_log(node: FluxNode) -> Path:
    return node.datadir / "regtest" / "debug.log"


def _read_marker(node: FluxNode) -> tuple[str, int]:
    """The sync marker (block hash, height), read from a copy of the stopped node's DB."""
    src = _db(node)
    tmp = src.with_name(src.name + ".inspect")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(src, tmp)
    db = plyvel.DB(str(tmp))
    try:
        raw = db.get(b"s")
        assert raw is not None and len(raw) == 36, f"unexpected marker record: {raw!r}"
        return raw[:32][::-1].hex(), struct.unpack("<i", raw[32:36])[0]
    finally:
        db.close()
        shutil.rmtree(tmp, ignore_errors=True)


def _snapshot(node: FluxNode, name: str) -> None:
    dst = _db(node).with_name(f"determ_zelnodes.{name}")
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(_db(node), dst)


def _restore(node: FluxNode, src: Path) -> None:
    shutil.rmtree(_db(node))
    shutil.copytree(src, _db(node))


async def _start_reading_log(node: FluxNode) -> str:
    """Start the stopped node and return what its debug.log gained during startup."""
    offset = _debug_log(node).stat().st_size
    await node.start()
    with open(_debug_log(node), errors="replace") as f:
        f.seek(offset)
        return f.read()


async def test_fluxnode_cache_recovery(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    foreign = await node_factory(1, extra_args=POW_ARGS)

    # A short chain node0 has never seen (node1's mocktime offset makes it diverge); its fluxnode
    # DB is the stale marker's source.
    await foreign.mine(5)
    await foreign.stop_daemon()

    await node.mine(40)
    await node.stop_daemon()
    _snapshot(node, "h40")  # marker = active-chain block at height 40

    await node.start()
    await node.mine(10)
    tip_hash = await node.rpc.getbestblockhash()
    tip_height = await node.rpc.getblockcount()
    assert tip_height == 50
    await node.stop_daemon()

    # A clean shutdown leaves the marker at the tip.
    assert _read_marker(node) == (tip_hash, tip_height)

    # Clean restart: recovery does not run.
    log = await _start_reading_log(node)
    assert "no recovery needed" in log
    assert "RecoverFluxnodeCache: disconnecting" not in log
    await node.stop_daemon()

    # Stale marker: repaired once, then skipped. The node is killed right after the repair, so the
    # marker on disk is the repair's own write — a clean shutdown would write it regardless.
    _restore(node, _db(foreign))
    log = await _start_reading_log(node)
    assert "stale marker" in log
    await node.kill()
    assert _read_marker(node) == (tip_hash, tip_height), "the repair did not write the marker"
    log = await _start_reading_log(node)
    assert "no recovery needed" in log, "the stale-marker repair did not stick"
    await node.stop_daemon()

    # Marker behind the tip: disconnect and replay.
    _restore(node, _db(node).with_name("determ_zelnodes.h40"))
    log = await _start_reading_log(node)
    assert "RecoverFluxnodeCache: disconnecting 10 blocks" in log
    assert await node.rpc.getblockcount() == tip_height
    assert await node.rpc.getbestblockhash() == tip_hash
    await node.stop_daemon()
    _snapshot(node, "forkA")  # marker = tip A, height 50

    # Marker on a stale fork. Invalidate tip A and mine a longer chain B; reconsidering A leaves it
    # a fully valid losing fork in the index, as a crash during a reorg does (a block still marked
    # failed would be erased at load and recovery would take the stale-marker path instead).
    await node.start()
    assert await node.rpc.getbestblockhash() == tip_hash
    await node.rpc.invalidateblock(tip_hash)
    assert await node.rpc.getblockcount() == 49
    await node.mine(2)
    await node.rpc.reconsiderblock(tip_hash)
    new_tip_hash = await node.rpc.getbestblockhash()
    assert await node.rpc.getblockcount() == 51
    await node.stop_daemon()

    _restore(node, _db(node).with_name("determ_zelnodes.forkA"))
    log = await _start_reading_log(node)
    assert "rewinding 1 blocks of fluxnode state along the marker's chain" in log
    assert "RecoverFluxnodeCache: disconnecting 2 blocks" in log
    assert await node.rpc.getblockcount() == 51
    assert await node.rpc.getbestblockhash() == new_tip_hash
    await node.stop_daemon()

    # After recovery and a clean shutdown the marker sits at the new tip.
    assert _read_marker(node) == (new_tip_hash, 51)
