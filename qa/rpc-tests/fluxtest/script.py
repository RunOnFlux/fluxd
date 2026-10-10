"""A minimal Bitcoin script builder for constructing test transactions.

Only the opcodes and encoding the block/coinbase helpers and the soft-fork tests
need are provided. CScript serializes a sequence of opcodes, integers and data
pushes to script bytecode, matching the consensus encoding.
"""

import struct
from collections.abc import Iterable


class CScriptOp(int):
    """A single script opcode."""

    @staticmethod
    def encode_op_pushdata(d: bytes) -> bytes:
        if len(d) < 0x4C:
            return bytes([len(d)]) + d
        if len(d) <= 0xFF:
            return b"\x4c" + bytes([len(d)]) + d
        if len(d) <= 0xFFFF:
            return b"\x4d" + struct.pack("<H", len(d)) + d
        return b"\x4e" + struct.pack("<I", len(d)) + d

    @staticmethod
    def encode_op_n(n: int) -> "CScriptOp":
        assert 0 <= n <= 16
        return OP_0 if n == 0 else CScriptOp(OP_1 + n - 1)


OP_0 = CScriptOp(0x00)
OP_FALSE = OP_0
OP_1NEGATE = CScriptOp(0x4F)
OP_1 = CScriptOp(0x51)
OP_TRUE = OP_1
OP_2 = CScriptOp(0x52)
OP_16 = CScriptOp(0x60)
OP_DROP = CScriptOp(0x75)
OP_EQUAL = CScriptOp(0x87)
OP_EQUALVERIFY = CScriptOp(0x88)
OP_DUP = CScriptOp(0x76)
OP_HASH160 = CScriptOp(0xA9)
OP_CHECKSIG = CScriptOp(0xAC)
OP_NOP2 = CScriptOp(0xB1)
OP_CHECKLOCKTIMEVERIFY = OP_NOP2


def _bn2vch(value: int) -> bytes:
    """Minimal sign-magnitude little-endian encoding of an integer."""
    if value == 0:
        return b""
    neg = value < 0
    v = -value if neg else value
    r = bytearray()
    while v:
        r.append(v & 0xFF)
        v >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0x00)
    elif neg:
        r[-1] |= 0x80
    return bytes(r)


class CScriptNum:
    """An integer pushed onto the stack with the minimal encoding (e.g. BIP34)."""

    def __init__(self, value: int = 0) -> None:
        self.value = value


class CScript(bytes):
    """Serialized script: a bytes subclass built from a sequence of items."""

    @staticmethod
    def _coerce(other: object) -> bytes:
        if isinstance(other, CScriptOp):
            return bytes([other])
        if isinstance(other, CScriptNum):
            if other.value == 0:
                return bytes([OP_0])
            return CScriptOp.encode_op_pushdata(_bn2vch(other.value))
        if isinstance(other, int):
            if 0 <= other <= 16:
                return bytes([CScriptOp.encode_op_n(other)])
            if other == -1:
                return bytes([OP_1NEGATE])
            return CScriptOp.encode_op_pushdata(_bn2vch(other))
        if isinstance(other, (bytes, bytearray)):
            return CScriptOp.encode_op_pushdata(bytes(other))
        raise TypeError(f"cannot encode {other!r} in a script")

    def __new__(cls, items: "bytes | bytearray | Iterable[object]" = b"") -> "CScript":
        if isinstance(items, (bytes, bytearray)):
            return super().__new__(cls, bytes(items))
        return super().__new__(cls, b"".join(cls._coerce(x) for x in items))

    def __repr__(self) -> str:
        return f"CScript({bytes(self).hex()})"


_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_REGTEST_PUBKEY_PREFIX = bytes([0x1D, 0x25])
_REGTEST_SCRIPT_PREFIX = bytes([0x1C, 0xBA])


def _b58check_decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + _B58.index(c)
    raw = (b"\x00" * (len(s) - len(s.lstrip("1")))) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return raw[:-4]  # drop the four-byte checksum


def script_for_address(addr: str) -> CScript:
    """The scriptPubKey paying a base58 regtest t-address (P2PKH or P2SH)."""
    payload = _b58check_decode(addr)
    version, h160 = payload[:2], payload[2:]
    if version == _REGTEST_PUBKEY_PREFIX:
        return CScript([OP_DUP, OP_HASH160, h160, OP_EQUALVERIFY, OP_CHECKSIG])
    if version == _REGTEST_SCRIPT_PREFIX:
        return CScript([OP_HASH160, h160, OP_EQUAL])
    raise ValueError(f"unsupported address version {version.hex()}")
