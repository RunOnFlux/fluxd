"""getblocktemplate proposal mode accepts a valid block and names each defect.

A block is assembled by hand from the template fields and its coinbase, then
resubmitted with ``{"mode": "proposal", "data": <blockhex>}``. A well-formed
block built on the current tip is accepted (result ``null``); each deliberately
corrupted variant is rejected with the specific reason fluxd records in its
validation state (bad input hash, truncated tx, duplicate/missing-input tx,
non-final locktime, wrong difficulty bits, mutated merkle root, out-of-range
timestamps) or with a JSON-RPC deserialization error for byte-level garbage.

Block layout is Flux's Zcash-derived PoW header
(version || hashPrevBlock || hashMerkleRoot || hashFinalSaplingRoot || nTime ||
nBits || nNonce || nSolution) followed by the transaction vector. Proposal mode
calls TestBlockValidity with proof-of-work disabled, and a zero-length Equihash
solution is explicitly let through, so the block needs no mined solution -- only
the structural and contextual checks run. The node must have a peer for
getblocktemplate to serve a template at all.
"""

import struct
from collections.abc import Sequence
from hashlib import sha256
from typing import Any

from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# fluxd reports a block whose bytes cannot be deserialized as RPC_DESERIALIZATION_ERROR.
RPC_DESERIALIZATION_ERROR = -22

# Header field offsets used to mutate a serialized block in place: 4-byte version
# then the 32-byte previous-block hash precede the merkle root.
MERKLE_ROOT_OFFSET = 4 + 32

# A timestamp far enough in the future to trip the future-block guard, and one
# far enough in the past to be at-or-before the previous block's median time.
TIME_TOO_NEW = 0x7FFFFFFF
TIME_TOO_OLD = 0


def _dblsha(data: bytes | bytearray) -> bytes:
    return sha256(sha256(data).digest()).digest()


def _read_compact_size(tx: bytes | bytearray, offset: int) -> tuple[int, int]:
    """Decode a CompactSize at ``offset``; return its value and the next offset."""
    first = tx[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        return int.from_bytes(tx[offset + 1 : offset + 3], "little"), offset + 3
    if first == 0xFE:
        return int.from_bytes(tx[offset + 1 : offset + 5], "little"), offset + 5
    return int.from_bytes(tx[offset + 1 : offset + 9], "little"), offset + 9


def _coinbase_sequence_offset(tx: bytes | bytearray) -> int:
    """Byte offset of the (single) coinbase input's nSequence field.

    The template's coinbase is a plain v1 transaction: 4-byte version, an input
    count, then the input's 36-byte outpoint, its CompactSize-prefixed scriptSig,
    and the 4-byte sequence. The scriptSig length varies with the block height
    pushed into it, so the field is located by walking the structure rather than
    by a fixed offset.
    """
    offset = 4  # nVersion
    vin_count, offset = _read_compact_size(tx, offset)
    assert vin_count == 1, "coinbase has a single input"
    offset += 36  # prevout
    script_len, offset = _read_compact_size(tx, offset)
    offset += script_len
    return offset


def _merkle_root(tx_hashes: Sequence[bytes]) -> bytes:
    """Bitcoin double-SHA256 merkle root over already-hashed leaves."""
    level: list[bytes] = list(tx_hashes)
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [_dblsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def _varint(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<L", n)
    return b"\xff" + struct.pack("<Q", n)


def _serialize_block(tmpl: dict[str, Any], txlist: Sequence[bytes | bytearray]) -> bytearray:
    """Assemble a PoW block from template fields and serialized transactions.

    The Equihash solution is left empty (a single zero length byte) and the
    nonce is zeroed; proposal mode validates with proof-of-work disabled and
    accepts a zero-length solution, so neither needs a real value.
    """
    merkle = _merkle_root([_dblsha(tx) for tx in txlist])
    header = struct.pack("<L", tmpl["version"])
    header += bytes.fromhex(tmpl["previousblockhash"])[::-1]
    header += merkle
    header += bytes.fromhex(tmpl["finalsaplingroothash"])[::-1]
    header += struct.pack("<L", tmpl["curtime"])
    header += bytes.fromhex(tmpl["bits"])[::-1]
    header += b"\x00" * 32  # nNonce
    header += b"\x00"  # nSolution: CompactSize length 0
    block = bytearray(header)
    block += _varint(len(txlist))
    for tx in txlist:
        block += tx
    return block


async def _propose(node: FluxNode, block_hex: str) -> Any:
    return await node.rpc.getblocktemplate({"mode": "proposal", "data": block_hex})


async def _assert_proposal(
    node: FluxNode, tmpl: dict[str, Any], txlist: Sequence[bytes | bytearray], expect: Any
) -> None:
    result = await _propose(node, _serialize_block(tmpl, txlist).hex())
    assert result == expect, f"expected {expect!r}, got {result!r}"


async def _template_and_txlist(
    node: FluxNode,
) -> tuple[dict[str, Any], list[bytearray]]:
    """Fetch a template and the mutable serialized-transaction list it implies."""
    tmpl = await node.rpc.getblocktemplate()
    raw = [tmpl["coinbasetxn"], *tmpl["transactions"]]
    txlist = [bytearray.fromhex(entry["data"]) for entry in raw]
    return tmpl, txlist


async def test_proposal_capability_advertised(node_factory: NodeFactory) -> None:
    """The default template advertises the proposal capability."""
    node = await node_factory(0, extra_args=POW_ARGS)
    peer = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(node, peer)
    await node.mine(1)  # leave initial block download
    tmpl = await node.rpc.getblocktemplate()
    assert "proposal" in tmpl["capabilities"]


async def test_proposal_valid_block(node_factory: NodeFactory) -> None:
    """A block built faithfully from the template is accepted (result null)."""
    node = await node_factory(0, extra_args=POW_ARGS)
    peer = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(node, peer)
    await node.mine(1)
    tmpl, txlist = await _template_and_txlist(node)
    await _assert_proposal(node, tmpl, txlist, None)


async def test_proposal_rejections(node_factory: NodeFactory) -> None:
    """Each deliberately malformed block is rejected with its specific reason.

    Driven from a single fresh template so the variants share one tip; the
    template is refetched only where a prior mutation alters the tip-relative
    timestamp window.
    """
    node = await node_factory(0, extra_args=POW_ARGS)
    peer = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(node, peer)
    await node.mine(1)
    tmpl, txlist = await _template_and_txlist(node)

    # Bad input hash for the generation tx: the first tx no longer looks like a
    # coinbase, so the block has no coinbase. Offset 4 (after the 4-byte tx
    # version) + 1 (the input-count byte) is the first byte of the prevout hash.
    txlist[0][4 + 1] += 1
    await _assert_proposal(node, tmpl, txlist, "bad-cb-missing")
    txlist[0][4 + 1] -= 1

    # Truncating the final tx leaves bytes that cannot be deserialized as a block.
    lastbyte = txlist[-1].pop()
    try:
        with_truncated = _serialize_block(tmpl, txlist).hex()
        try:
            await _propose(node, with_truncated)
            raise AssertionError("truncated tx was not rejected")
        except JSONRPCError as exc:
            assert exc.code == RPC_DESERIALIZATION_ERROR
    finally:
        txlist[-1].append(lastbyte)

    # Appending a byte-for-byte duplicate of the coinbase mutates the merkle tree.
    txlist.append(txlist[0])
    await _assert_proposal(node, tmpl, txlist, "bad-txns-duplicate")
    txlist.pop()

    # A non-duplicate extra tx whose input is unknown: spends a missing output.
    extra = bytearray(txlist[0])
    extra[4 + 1] = 0xFF
    txlist.append(extra)
    await _assert_proposal(node, tmpl, txlist, "bad-txns-inputs-missingorspent")
    txlist.pop()

    # A future locktime on the coinbase makes it non-final -- but only once its
    # input is also non-final, since a max-sequence input forces finality
    # regardless of locktime. The template's coinbase is a v1 tx, so its locktime
    # is its last 4 bytes; the input sequence is located by walking the tx.
    seq_off = _coinbase_sequence_offset(txlist[0])
    saved_seq = bytes(txlist[0][seq_off : seq_off + 4])
    saved_locktime = bytes(txlist[0][-4:])
    txlist[0][seq_off : seq_off + 4] = b"\xfe\xff\xff\xff"
    txlist[0][-4:] = b"\xff\xff\xff\xff"
    await _assert_proposal(node, tmpl, txlist, "bad-txns-nonfinal")
    txlist[0][seq_off : seq_off + 4] = saved_seq
    txlist[0][-4:] = saved_locktime

    # Impossible difficulty bits for this chain position.
    real_bits = tmpl["bits"]
    tmpl["bits"] = "1c0000ff"
    await _assert_proposal(node, tmpl, txlist, "bad-diffbits")
    tmpl["bits"] = real_bits

    # Flipping a byte of the serialized merkle root breaks the merkle check
    # without disturbing any transaction the node recomputes the root from.
    raw_block = _serialize_block(tmpl, txlist)
    raw_block[MERKLE_ROOT_OFFSET] = (raw_block[MERKLE_ROOT_OFFSET] + 1) % 0x100
    result = await _propose(node, raw_block.hex())
    assert result == "bad-txnmrklroot", f"expected bad-txnmrklroot, got {result!r}"

    # An extreme future timestamp trips the future-block guard.
    real_time = tmpl["curtime"]
    tmpl["curtime"] = TIME_TOO_NEW
    await _assert_proposal(node, tmpl, txlist, "time-too-new")
    # A zero timestamp is at or before the previous block's median time past.
    tmpl["curtime"] = TIME_TOO_OLD
    await _assert_proposal(node, tmpl, txlist, "time-too-old")
    tmpl["curtime"] = real_time

    # A valid build on the same tip is still accepted after the mutations.
    await _assert_proposal(node, tmpl, txlist, None)


async def test_proposal_bad_tx_count(node_factory: NodeFactory) -> None:
    """A transaction count that overruns the block's bytes fails to deserialize."""
    node = await node_factory(0, extra_args=POW_ARGS)
    peer = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(node, peer)
    await node.mine(1)
    tmpl, txlist = await _template_and_txlist(node)

    # An empty trailing "transaction" makes the declared count exceed the bytes.
    txlist.append(bytearray())
    block_hex = _serialize_block(tmpl, txlist).hex()
    try:
        await _propose(node, block_hex)
        raise AssertionError("bad tx count was not rejected")
    except JSONRPCError as exc:
        assert exc.code == RPC_DESERIALIZATION_ERROR


async def test_proposal_orphan_block(node_factory: NodeFactory) -> None:
    """A block whose previous hash is not the tip is inconclusive, not rejected."""
    node = await node_factory(0, extra_args=POW_ARGS)
    peer = await node_factory(1, extra_args=POW_ARGS)
    await connect_nodes_bi(node, peer)
    await node.mine(1)
    tmpl, txlist = await _template_and_txlist(node)

    tmpl["previousblockhash"] = "ff00" * 16
    await _assert_proposal(node, tmpl, txlist, "inconclusive-not-best-prevblk")
