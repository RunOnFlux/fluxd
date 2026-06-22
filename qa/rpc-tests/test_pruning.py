"""Block-file pruning: a -prune node deletes old block files yet can still reorg.

A node started with -prune=<MB> keeps its on-disk block/undo data under the
configured target by deleting the oldest block files once the chain has grown
past them. Flux's floor is MIN_DISK_SPACE_FOR_BLOCK_FILES = 550 MB
(src/main.h); -prune is rejected below it. Pruning does not begin until the tip
is past the regtest PruneAfterHeight (1000) and on-disk usage approaches the
target, and it never removes a file holding a block within MIN_BLOCKS_TO_KEEP
(288) of the tip -- so a recent reorg always has its undo data.

This drives a real prune: a wallet-less prune node syncs a chain from a miner
that mines hundreds of ~2 MB blocks (stuffed with oversized OP_RETURN outputs,
non-standard but accepted on regtest) until on-disk usage exceeds 550 MB and the
tip is well past height 1000+288. The earliest block file (blk00000.dat) is then
deleted, while a short reorg near the tip -- across blocks whose files were
written recently and thus retained -- still succeeds because the prune node kept
the undo data for the last 288 blocks.

Flux refuses any reorg of MAX_REORG_LENGTH (40) blocks or more
(bad-fork-prior-to-maxreorgdepth), so the reorg exercised here is a short one
well inside that limit -- which is also well inside the 288-block retention
window, exactly the region a prune node must keep reorganizable.
"""

from decimal import Decimal
from pathlib import Path

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# src/main.h: -prune is rejected below this, and FindFilesToPrune targets it.
MIN_PRUNE_MB = 550
# src/main.h MIN_BLOCKS_TO_KEEP -- block files holding a block within this many
# of the tip are never pruned, so a reorg this shallow always has undo data.
MIN_BLOCKS_TO_KEEP = 288
# src/main.h MAX_BLOCK_SIZE is 2 MB; mine just under it for dense block files.
BLOCK_MAX_SIZE = 1999000
MINER_ARGS = [*POW_ARGS, f"-blockmaxsize={BLOCK_MAX_SIZE}"]
# regtest CRegTestParams nPruneAfterHeight -- no pruning until the tip exceeds it.
PRUNE_AFTER_HEIGHT = 1000

# Each stuffed transaction carries this many oversized OP_RETURN outputs, making
# it roughly 66 KB; ~28 such transactions fill a block close to the 2 MB cap, so
# fewer blocks are needed to cross the 550 MB prune target.
OP_RETURN_OUTPUTS_PER_TX = 128
OP_RETURN_PAYLOAD_BYTES = 512
STUFFED_TXS_PER_BLOCK = 28

# A fee comfortably above the relay minimum for a ~66 KB transaction, so the
# non-standard stuffed transactions are accepted into the mempool.
STUFF_FEE = Decimal("0.001")

# Mine with 1-second timestamp steps: the chain spans well over a thousand
# blocks, and at the default 30 s step its tip time would race more than two
# hours ahead of the never-mining prune node's frozen clock, tripping the
# time-too-new block check (src/main.cpp). A 1 s step keeps the whole chain
# inside that window so the prune node accepts every block.
MINE_INTERVAL = 1


def _blocks_dir(node: FluxNode) -> Path:
    return node.datadir / "regtest" / "blocks"


def _disk_usage_mb(node: FluxNode) -> float:
    blocks = _blocks_dir(node)
    total = sum(f.stat().st_size for f in blocks.iterdir() if f.is_file())
    return total / (1024 * 1024)


def _read_varint(data: bytearray, offset: int) -> tuple[int, int]:
    """Read a Bitcoin compact-size varint at ``offset``; return (value, next)."""
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), offset + 3
    if first == 0xFE:
        return int.from_bytes(data[offset + 1 : offset + 5], "little"), offset + 5
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), offset + 9


def _encode_varint(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _op_return_output() -> bytes:
    """A single zero-value OP_RETURN txout carrying an oversized payload.

    Non-standard (the payload exceeds MAX_OP_RETURN_RELAY), which regtest accepts
    because CRegTestParams sets fRequireStandard = false.
    """
    # OP_RETURN OP_PUSHDATA2 <len> <payload>
    script = b"\x6a\x4d" + OP_RETURN_PAYLOAD_BYTES.to_bytes(2, "little")
    script += b"\x01" * OP_RETURN_PAYLOAD_BYTES
    return (0).to_bytes(8, "little") + _encode_varint(len(script)) + script


def _stuff_transaction(raw_hex: str) -> str:
    """Splice many OP_RETURN outputs into a legacy (v1) raw transaction.

    The skeleton from createrawtransaction has a single change output. The extra
    outputs are inserted before it and the output count is bumped accordingly.
    Regtest defaults to pre-Overwinter so transactions use the v1 layout:
    version(4) | vin-count | vins | vout-count | vouts | locktime(4).
    """
    data = bytearray.fromhex(raw_hex)
    offset = 4  # past version
    vin_count, offset = _read_varint(data, offset)
    for _ in range(vin_count):
        offset += 36  # 32-byte txid + 4-byte vout
        script_len, offset = _read_varint(data, offset)
        offset += script_len + 4  # scriptSig + sequence

    vout_count_start = offset
    vout_count, vout_body_start = _read_varint(data, offset)

    extra = b"".join(_op_return_output() for _ in range(OP_RETURN_OUTPUTS_PER_TX))
    new_count = _encode_varint(vout_count + OP_RETURN_OUTPUTS_PER_TX)
    spliced = data[:vout_count_start] + new_count + extra + data[vout_body_start:]
    return spliced.hex()


async def _spendable_utxos(node: FluxNode) -> list[dict]:
    return [u for u in await node.rpc.listunspent(1) if u["spendable"]]


async def _mine_full_block(node: FluxNode, address: str, utxos: list[dict]) -> None:
    """Build and mine one block stuffed close to the 2 MB cap.

    Pops matured coinbases off ``utxos`` to fund STUFFED_TXS_PER_BLOCK large
    transactions, each forwarding its value (minus a fee) back to ``address``
    alongside the OP_RETURN padding.
    """
    for _ in range(STUFFED_TXS_PER_BLOCK):
        utxo = utxos.pop()
        change = utxo["amount"] - STUFF_FEE
        raw = await node.rpc.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            {address: change},
        )
        stuffed = _stuff_transaction(raw)
        signed = await node.rpc.signrawtransaction(stuffed)
        assert signed["complete"] is True, signed
        await node.rpc.sendrawtransaction(signed["hex"], True)
    await node.mine(1, interval=MINE_INTERVAL)


@pytest.mark.slow
async def test_prune_deletes_old_block_files_and_still_reorgs(
    node_factory: NodeFactory,
) -> None:
    miner = await node_factory(0, extra_args=MINER_ARGS)
    pruned = await node_factory(2, extra_args=[f"-prune={MIN_PRUNE_MB}"])
    await connect_nodes_bi(miner, pruned)

    address = await miner.rpc.getnewaddress()

    # Mature a pool of coinbases to spend into the stuffed blocks.
    await miner.mine(COINBASE_MATURITY + 60, interval=MINE_INTERVAL)
    await sync_blocks([miner, pruned])

    # Fill block files past the 550 MB target with dense ~2 MB blocks. Each block
    # consumes STUFFED_TXS_PER_BLOCK matured coinbases and produces that many
    # fresh spendable change outputs, so the spendable pool stays replenished as
    # the chain grows.
    utxos = await _spendable_utxos(miner)
    while _disk_usage_mb(pruned) < MIN_PRUNE_MB + 15:
        if len(utxos) < STUFFED_TXS_PER_BLOCK:
            utxos = await _spendable_utxos(miner)
        await _mine_full_block(miner, address, utxos)
        await sync_blocks([miner, pruned])

    # No pruning yet: the tip has not passed PruneAfterHeight, so even though
    # usage is already over target the earliest block file must remain.
    assert await pruned.rpc.getblockcount() <= PRUNE_AFTER_HEIGHT
    assert (_blocks_dir(pruned) / "blk00000.dat").is_file()

    # Push the tip well past PruneAfterHeight, and past the 288-block retention
    # window over the early (now prunable) files, with cheap empty blocks.
    target_height = PRUNE_AFTER_HEIGHT + MIN_BLOCKS_TO_KEEP + 50
    while await miner.rpc.getblockcount() < target_height:
        await miner.mine(1, interval=MINE_INTERVAL)
        await sync_blocks([miner, pruned])

    # Still no pruning: the daemon only checks for files to prune when a new
    # block-file chunk is allocated, and the empty blocks above are far too small
    # to cross a chunk boundary.
    assert (_blocks_dir(pruned) / "blk00000.dat").is_file()

    # Mine a handful more dense blocks. These allocate fresh block-file chunks,
    # which flips the prune check on: with the tip now well past the height gate
    # and usage over target, the oldest files (holding blocks far outside the
    # retention window) are deleted.
    utxos = await _spendable_utxos(miner)
    for _ in range(20):
        if len(utxos) < STUFFED_TXS_PER_BLOCK:
            utxos = await _spendable_utxos(miner)
        await _mine_full_block(miner, address, utxos)
        await sync_blocks([miner, pruned])

    assert not (_blocks_dir(pruned) / "blk00000.dat").is_file(), (
        f"blk00000.dat was not pruned (usage {_disk_usage_mb(pruned):.0f} MB, "
        f"tip {await pruned.rpc.getblockcount()})"
    )
    # The prune target is being met.
    assert _disk_usage_mb(pruned) <= MIN_PRUNE_MB

    # The prune node retains undo data for the last MIN_BLOCKS_TO_KEEP blocks, so
    # a short reorg near the tip -- shallower than both that window and Flux's
    # 40-block reorg limit -- still succeeds. Roll back a handful of tip blocks
    # by invalidating them on the miner, mining a longer competing branch, and
    # confirming the prune node follows the reorg.
    tip_height = await miner.rpc.getblockcount()
    rollback = 5
    fork_point = tip_height - rollback
    branch_base_hash = await miner.rpc.getblockhash(fork_point)
    invalidate_hash = await miner.rpc.getblockhash(fork_point + 1)

    # The prune node must still hold the block being rolled back across.
    assert (await pruned.rpc.getblock(branch_base_hash))["height"] == fork_point

    await miner.rpc.invalidateblock(invalidate_hash)
    assert await miner.rpc.getblockcount() == fork_point
    assert await miner.rpc.getbestblockhash() == branch_base_hash

    # Mine a strictly longer branch off the fork point; the prune node reorgs
    # onto it using its retained recent undo data.
    await miner.mine(rollback + 2, interval=MINE_INTERVAL)
    new_tip = await miner.rpc.getbestblockhash()
    new_height = await miner.rpc.getblockcount()
    assert new_height == fork_point + rollback + 2

    await sync_blocks([miner, pruned])
    assert await pruned.rpc.getbestblockhash() == new_tip
    assert await pruned.rpc.getblockcount() == new_height

    # An early block whose file was pruned is no longer retrievable, confirming
    # the reorg succeeded without that ancient data while the recent window
    # remained intact.
    early_hash = await miner.rpc.getblockhash(1)
    with pytest.raises(JSONRPCError):
        await pruned.rpc.getblock(early_hash)

    # Pruning still holds after the reorg.
    assert _disk_usage_mb(pruned) <= MIN_PRUNE_MB
