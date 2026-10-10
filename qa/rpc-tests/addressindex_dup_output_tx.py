"""Hand-splice a transaction's output vector so two outputs share one address.

``createrawtransaction`` deduplicates outputs that pay the same address, which
defeats the addressindex sub-case that needs two outputs to one address plus a
non-standard (address-less) output in a single transaction. fluxd's Sapling
transaction layout is too involved to serialize from scratch, so a valid raw
transaction produced by the node (one input, one output) is parsed only far
enough to locate its output vector, which is then replaced wholesale with the
desired outputs. Everything after the outputs (locktime, expiry height, the
empty Sapling/Sprout sections) is preserved byte-for-byte.
"""

import struct
from collections.abc import Sequence

# Standard Bitcoin script opcodes used to build the spliced outputs.
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_EQUAL = 0x87
OP_DROP = 0x75

# The Overwintered header bit lives in the top bit of the 4-byte version word;
# a Sapling/Overwinter transaction additionally carries a 4-byte version group
# id immediately after the version word.
OVERWINTERED_HEADER_BIT = 0x80000000


def _read_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a CompactSize at ``offset``; return its value and the next offset."""
    first = data[offset]
    if first < 0xFD:
        return first, offset + 1
    if first == 0xFD:
        return int.from_bytes(data[offset + 1 : offset + 3], "little"), offset + 3
    if first == 0xFE:
        return int.from_bytes(data[offset + 1 : offset + 5], "little"), offset + 5
    return int.from_bytes(data[offset + 1 : offset + 9], "little"), offset + 9


def _compact_size(n: int) -> bytes:
    if n < 0xFD:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<L", n)
    return b"\xff" + struct.pack("<Q", n)


def p2pkh_script(address_hash: bytes) -> bytes:
    """A pay-to-public-key-hash script (the form a t-address validates to)."""
    return (
        bytes([OP_DUP, OP_HASH160, len(address_hash)])
        + address_hash
        + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    )


def unrecognized_script(address_hash: bytes) -> bytes:
    """A legal-but-non-standard script that pays no extractable address.

    No address template matches it, so it never touches the addressindex; it is
    present only to confirm an address-less output does not perturb the result.
    """
    return (
        bytes([OP_HASH160, OP_DUP, OP_DROP, len(address_hash)]) + address_hash + bytes([OP_EQUAL])
    )


def _serialize_output(value_sat: int, script: bytes) -> bytes:
    return struct.pack("<q", value_sat) + _compact_size(len(script)) + script


def _output_vector_span(raw: bytes) -> tuple[int, int]:
    """Return the (start, end) byte offsets of the output vector in ``raw``.

    Walks the transaction header, optional Overwinter version group id, and the
    input vector, then walks the single existing output to find where the vector
    ends. The transaction is assumed to carry exactly one input and one output,
    as produced by createrawtransaction for a single-input single-output spend.
    """
    offset = 0
    header = int.from_bytes(raw[offset : offset + 4], "little")
    offset += 4
    if header & OVERWINTERED_HEADER_BIT:
        offset += 4  # nVersionGroupId

    vin_count, offset = _read_compact_size(raw, offset)
    for _ in range(vin_count):
        offset += 36  # prevout: 32-byte hash + 4-byte index
        script_len, offset = _read_compact_size(raw, offset)
        offset += script_len
        offset += 4  # nSequence

    vout_start = offset
    vout_count, offset = _read_compact_size(raw, offset)
    for _ in range(vout_count):
        offset += 8  # value
        script_len, offset = _read_compact_size(raw, offset)
        offset += script_len
    return vout_start, offset


def splice_outputs(rawtx_hex: str, outputs: Sequence[tuple[int, bytes]]) -> str:
    """Replace the output vector of ``rawtx_hex`` with ``outputs``.

    ``outputs`` is a sequence of ``(value_in_satoshis, scriptPubKey)`` pairs. The
    bytes before the output vector (header, version group id, inputs) and after it
    (locktime, expiry, shielded sections) are kept exactly as the node produced.
    """
    raw = bytes.fromhex(rawtx_hex)
    vout_start, vout_end = _output_vector_span(raw)
    new_vector = _compact_size(len(outputs))
    for value_sat, script in outputs:
        new_vector += _serialize_output(value_sat, script)
    return (raw[:vout_start] + new_vector + raw[vout_end:]).hex()
