"""A minimal asyncio P2P peer for driving fluxd over the wire.

NodeConn opens a TCP connection to a regtest node and speaks the Zcash/Flux
network protocol: it performs the version/verack handshake, frames and checksums
messages, and dispatches incoming messages to a NodeConnCB. Tests subclass
NodeConnCB to react to and assert on P2P messages.

This is the asyncio rewrite of the legacy asyncore mininode. Block solving
(equihash) is not ported; tests that need to mine blocks over P2P are out of
scope here.
"""

import asyncio
import io
import random
import socket
import struct
import time
from collections.abc import Callable
from hashlib import blake2b
from hashlib import sha256 as _sha256
from typing import Any

from .equihash import gbp_basic, gbp_validate, hash_nonce, zelcash_person

OVERWINTER_PROTO_VERSION = 170003
SPROUT_PROTO_VERSION = 170002
SAPLING_PROTO_VERSION = 170006
BIP0031_VERSION = 60000
MY_SUBVERSION = b"/python-mininode-tester:0.0.1/"

OVERWINTER_VERSION_GROUP_ID = 0x03C48270
SAPLING_VERSION_GROUP_ID = 0x892F2085

MAX_INV_SZ = 50000
COIN = 100000000


def sha256(s: bytes) -> bytes:
    return _sha256(s).digest()


def hash256(s: bytes) -> bytes:
    return sha256(sha256(s))


# ---- serialization helpers ----------------------------------------------


def _deser_compact_size(f: io.BytesIO) -> int:
    nit = struct.unpack("<B", f.read(1))[0]
    if nit == 253:
        nit = struct.unpack("<H", f.read(2))[0]
    elif nit == 254:
        nit = struct.unpack("<I", f.read(4))[0]
    elif nit == 255:
        nit = struct.unpack("<Q", f.read(8))[0]
    return nit


def _ser_compact_size(n: int) -> bytes:
    if n < 253:
        return struct.pack("<B", n)
    if n < 0x10000:
        return struct.pack("<B", 253) + struct.pack("<H", n)
    if n < 0x100000000:
        return struct.pack("<B", 254) + struct.pack("<I", n)
    return struct.pack("<B", 255) + struct.pack("<Q", n)


def deser_string(f: io.BytesIO) -> bytes:
    return f.read(_deser_compact_size(f))


def ser_string(s: bytes) -> bytes:
    return _ser_compact_size(len(s)) + s


def deser_uint256(f: io.BytesIO) -> int:
    r = 0
    for i in range(8):
        r += struct.unpack("<I", f.read(4))[0] << (i * 32)
    return r


def ser_uint256(u: int) -> bytes:
    rs = b""
    for _ in range(8):
        rs += struct.pack("<I", u & 0xFFFFFFFF)
        u >>= 32
    return rs


def uint256_from_str(s: bytes) -> int:
    r = 0
    t = struct.unpack("<IIIIIIII", s[:32])
    for i in range(8):
        r += t[i] << (i * 32)
    return r


def uint256_from_compact(c: int) -> int:
    nbytes = (c >> 24) & 0xFF
    return (c & 0xFFFFFF) << (8 * (nbytes - 3))


def deser_vector(f: io.BytesIO, c: type) -> list:
    r = []
    for _ in range(_deser_compact_size(f)):
        t = c()
        t.deserialize(f)
        r.append(t)
    return r


def ser_vector(items: list) -> bytes:
    r = _ser_compact_size(len(items))
    for i in items:
        r += i.serialize()
    return r


def deser_uint256_vector(f: io.BytesIO) -> list[int]:
    return [deser_uint256(f) for _ in range(_deser_compact_size(f))]


def ser_uint256_vector(items: list[int]) -> bytes:
    r = _ser_compact_size(len(items))
    for i in items:
        r += ser_uint256(i)
    return r


def deser_char_vector(f: io.BytesIO) -> list[int]:
    return [struct.unpack("<B", f.read(1))[0] for _ in range(_deser_compact_size(f))]


def ser_char_vector(items: list[int]) -> bytes:
    return _ser_compact_size(len(items)) + bytes(items)


# ---- network/structure objects ------------------------------------------


class CAddress:
    def __init__(self) -> None:
        self.nServices = 1
        self.nTime = 0  # carried only inside addr messages, not in version
        self.pchReserved = b"\x00" * 10 + b"\xff" * 2
        self.ip = "0.0.0.0"
        self.port = 0

    def deserialize(self, f: io.BytesIO) -> None:
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        self.pchReserved = f.read(12)
        self.ip = socket.inet_ntoa(f.read(4))
        self.port = struct.unpack(">H", f.read(2))[0]

    def serialize(self) -> bytes:
        return (
            struct.pack("<Q", self.nServices)
            + self.pchReserved
            + socket.inet_aton(self.ip)
            + struct.pack(">H", self.port)
        )

    def __repr__(self) -> str:
        return f"CAddress(nServices={self.nServices} ip={self.ip} port={self.port})"


class CInv:
    typemap = {0: "Error", 1: "TX", 2: "Block"}

    def __init__(self, t: int = 0, h: int = 0) -> None:
        self.type = t
        self.hash = h

    def deserialize(self, f: io.BytesIO) -> None:
        self.type = struct.unpack("<i", f.read(4))[0]
        self.hash = deser_uint256(f)

    def serialize(self) -> bytes:
        return struct.pack("<i", self.type) + ser_uint256(self.hash)

    def __repr__(self) -> str:
        return f"CInv(type={self.typemap.get(self.type, self.type)} hash={self.hash:064x})"


class CBlockLocator:
    def __init__(self) -> None:
        self.nVersion = SPROUT_PROTO_VERSION
        self.vHave: list[int] = []

    def deserialize(self, f: io.BytesIO) -> None:
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.vHave = deser_uint256_vector(f)

    def serialize(self) -> bytes:
        return struct.pack("<i", self.nVersion) + ser_uint256_vector(self.vHave)

    def __repr__(self) -> str:
        return f"CBlockLocator(nVersion={self.nVersion} vHave={self.vHave!r})"


class SpendDescription:
    def __init__(self) -> None:
        self.cv = self.anchor = self.nullifier = self.rk = 0
        self.zkproof = b""
        self.spendAuthSig = b""

    def deserialize(self, f: io.BytesIO) -> None:
        self.cv = deser_uint256(f)
        self.anchor = deser_uint256(f)
        self.nullifier = deser_uint256(f)
        self.rk = deser_uint256(f)
        self.zkproof = f.read(192)
        self.spendAuthSig = f.read(64)

    def serialize(self) -> bytes:
        return (
            ser_uint256(self.cv)
            + ser_uint256(self.anchor)
            + ser_uint256(self.nullifier)
            + ser_uint256(self.rk)
            + self.zkproof
            + self.spendAuthSig
        )


class OutputDescription:
    def __init__(self) -> None:
        self.cv = self.cmu = self.ephemeralKey = 0
        self.encCiphertext = self.outCiphertext = self.zkproof = b""

    def deserialize(self, f: io.BytesIO) -> None:
        self.cv = deser_uint256(f)
        self.cmu = deser_uint256(f)
        self.ephemeralKey = deser_uint256(f)
        self.encCiphertext = f.read(580)
        self.outCiphertext = f.read(80)
        self.zkproof = f.read(192)

    def serialize(self) -> bytes:
        return (
            ser_uint256(self.cv)
            + ser_uint256(self.cmu)
            + ser_uint256(self.ephemeralKey)
            + self.encCiphertext
            + self.outCiphertext
            + self.zkproof
        )


ZC_NUM_JS_INPUTS = 2
ZC_NUM_JS_OUTPUTS = 2
ZC_NOTECIPHERTEXT_SIZE = 1 + 8 + 32 + 32 + 512 + 16


class JSDescription:
    """A Sprout joinsplit. The Groth proof is a fixed 192-byte blob after Sapling."""

    def __init__(self) -> None:
        self.vpub_old = 0
        self.vpub_new = 0
        self.anchor = 0
        self.nullifiers = [0] * ZC_NUM_JS_INPUTS
        self.commitments = [0] * ZC_NUM_JS_OUTPUTS
        self.onetimePubKey = 0
        self.randomSeed = 0
        self.macs = [0] * ZC_NUM_JS_INPUTS
        self.proof = b""
        self.ciphertexts = [b""] * ZC_NUM_JS_OUTPUTS

    def deserialize(self, f: io.BytesIO) -> None:
        self.vpub_old = struct.unpack("<q", f.read(8))[0]
        self.vpub_new = struct.unpack("<q", f.read(8))[0]
        self.anchor = deser_uint256(f)
        self.nullifiers = [deser_uint256(f) for _ in range(ZC_NUM_JS_INPUTS)]
        self.commitments = [deser_uint256(f) for _ in range(ZC_NUM_JS_OUTPUTS)]
        self.onetimePubKey = deser_uint256(f)
        self.randomSeed = deser_uint256(f)
        self.macs = [deser_uint256(f) for _ in range(ZC_NUM_JS_INPUTS)]
        self.proof = f.read(192)
        self.ciphertexts = [f.read(ZC_NOTECIPHERTEXT_SIZE) for _ in range(ZC_NUM_JS_OUTPUTS)]

    def serialize(self) -> bytes:
        r = struct.pack("<q", self.vpub_old) + struct.pack("<q", self.vpub_new)
        r += ser_uint256(self.anchor)
        r += b"".join(ser_uint256(x) for x in self.nullifiers)
        r += b"".join(ser_uint256(x) for x in self.commitments)
        r += ser_uint256(self.onetimePubKey) + ser_uint256(self.randomSeed)
        r += b"".join(ser_uint256(x) for x in self.macs)
        r += self.proof
        r += b"".join(self.ciphertexts)
        return r


class COutPoint:
    def __init__(self, hash: int = 0, n: int = 0) -> None:
        self.hash = hash
        self.n = n

    def deserialize(self, f: io.BytesIO) -> None:
        self.hash = deser_uint256(f)
        self.n = struct.unpack("<I", f.read(4))[0]

    def serialize(self) -> bytes:
        return ser_uint256(self.hash) + struct.pack("<I", self.n)

    def __repr__(self) -> str:
        return f"COutPoint(hash={self.hash:064x} n={self.n})"


class CTxIn:
    def __init__(
        self, outpoint: COutPoint | None = None, scriptSig: bytes = b"", nSequence: int = 0
    ) -> None:
        self.prevout = outpoint if outpoint is not None else COutPoint()
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f: io.BytesIO) -> None:
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = struct.unpack("<I", f.read(4))[0]

    def serialize(self) -> bytes:
        return (
            self.prevout.serialize()
            + ser_string(self.scriptSig)
            + struct.pack("<I", self.nSequence)
        )

    def __repr__(self) -> str:
        return f"CTxIn(prevout={self.prevout!r} nSequence={self.nSequence})"


class CTxOut:
    def __init__(self, nValue: int = 0, scriptPubKey: bytes = b"") -> None:
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f: io.BytesIO) -> None:
        self.nValue = struct.unpack("<q", f.read(8))[0]
        self.scriptPubKey = deser_string(f)

    def serialize(self) -> bytes:
        return struct.pack("<q", self.nValue) + ser_string(self.scriptPubKey)

    def __repr__(self) -> str:
        return f"CTxOut(nValue={self.nValue} scriptPubKey={self.scriptPubKey.hex()})"


class CTransaction:
    def __init__(self, tx: "CTransaction | None" = None) -> None:
        if tx is None:
            self.fOverwintered = False
            self.nVersion = 1
            self.nVersionGroupId = 0
            self.vin: list[CTxIn] = []
            self.vout: list[CTxOut] = []
            self.nLockTime = 0
            self.nExpiryHeight = 0
            self.valueBalance = 0
            self.shieldedSpends: list[SpendDescription] = []
            self.shieldedOutputs: list[OutputDescription] = []
            self.vJoinSplit: list[JSDescription] = []
            self.joinSplitPubKey = 0
            self.joinSplitSig = b""
            self.bindingSig = b""
        else:
            self.fOverwintered = tx.fOverwintered
            self.nVersion = tx.nVersion
            self.nVersionGroupId = tx.nVersionGroupId
            self.vin = list(tx.vin)
            self.vout = list(tx.vout)
            self.nLockTime = tx.nLockTime
            self.nExpiryHeight = tx.nExpiryHeight
            self.valueBalance = tx.valueBalance
            self.shieldedSpends = list(tx.shieldedSpends)
            self.shieldedOutputs = list(tx.shieldedOutputs)
            self.vJoinSplit = list(tx.vJoinSplit)
            self.joinSplitPubKey = tx.joinSplitPubKey
            self.joinSplitSig = tx.joinSplitSig
            self.bindingSig = tx.bindingSig
        self.sha256: int | None = None
        self.hash: str | None = None

    def _is_overwinter_v3(self) -> bool:
        return (
            self.fOverwintered
            and self.nVersionGroupId == OVERWINTER_VERSION_GROUP_ID
            and self.nVersion == 3
        )

    def _is_sapling_v4(self) -> bool:
        return (
            self.fOverwintered
            and self.nVersionGroupId == SAPLING_VERSION_GROUP_ID
            and self.nVersion == 4
        )

    def deserialize(self, f: io.BytesIO) -> None:
        header = struct.unpack("<I", f.read(4))[0]
        self.fOverwintered = bool(header >> 31)
        self.nVersion = header & 0x7FFFFFFF
        self.nVersionGroupId = struct.unpack("<I", f.read(4))[0] if self.fOverwintered else 0
        self.vin = deser_vector(f, CTxIn)
        self.vout = deser_vector(f, CTxOut)
        self.nLockTime = struct.unpack("<I", f.read(4))[0]
        if self._is_overwinter_v3() or self._is_sapling_v4():
            self.nExpiryHeight = struct.unpack("<I", f.read(4))[0]
        if self._is_sapling_v4():
            self.valueBalance = struct.unpack("<q", f.read(8))[0]
            self.shieldedSpends = deser_vector(f, SpendDescription)
            self.shieldedOutputs = deser_vector(f, OutputDescription)
        if self.nVersion >= 2:
            self.vJoinSplit = deser_vector(f, JSDescription)
            if len(self.vJoinSplit) > 0:
                self.joinSplitPubKey = deser_uint256(f)
                self.joinSplitSig = f.read(64)
        if self._is_sapling_v4() and (self.shieldedSpends or self.shieldedOutputs):
            self.bindingSig = f.read(64)
        self.sha256 = None
        self.hash = None

    def serialize(self) -> bytes:
        header = (int(self.fOverwintered) << 31) | self.nVersion
        r = struct.pack("<I", header)
        if self.fOverwintered:
            r += struct.pack("<I", self.nVersionGroupId)
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += struct.pack("<I", self.nLockTime)
        if self._is_overwinter_v3() or self._is_sapling_v4():
            r += struct.pack("<I", self.nExpiryHeight)
        if self._is_sapling_v4():
            r += struct.pack("<q", self.valueBalance)
            r += ser_vector(self.shieldedSpends)
            r += ser_vector(self.shieldedOutputs)
        if self.nVersion >= 2:
            r += ser_vector(self.vJoinSplit)
            if len(self.vJoinSplit) > 0:
                r += ser_uint256(self.joinSplitPubKey)
                r += self.joinSplitSig
        if self._is_sapling_v4() and (self.shieldedSpends or self.shieldedOutputs):
            r += self.bindingSig
        return r

    def rehash(self) -> None:
        self.sha256 = None
        self.calc_sha256()

    def calc_sha256(self) -> None:
        if self.sha256 is None:
            self.sha256 = uint256_from_str(hash256(self.serialize()))
        self.hash = hash256(self.serialize())[::-1].hex()

    def __repr__(self) -> str:
        return (
            f"CTransaction(fOverwintered={self.fOverwintered} nVersion={self.nVersion} "
            f"nVersionGroupId=0x{self.nVersionGroupId:08x} vin={self.vin!r} vout={self.vout!r} "
            f"nLockTime={self.nLockTime} nExpiryHeight={self.nExpiryHeight})"
        )


class CBlockHeader:
    def __init__(self, header: "CBlockHeader | None" = None) -> None:
        if header is None:
            self.nVersion = 4
            self.hashPrevBlock = 0
            self.hashMerkleRoot = 0
            self.hashFinalSaplingRoot = 0
            self.nTime = 0
            self.nBits = 0
            self.nNonce = 0
            self.nSolution: list[int] = []
        else:
            self.nVersion = header.nVersion
            self.hashPrevBlock = header.hashPrevBlock
            self.hashMerkleRoot = header.hashMerkleRoot
            self.hashFinalSaplingRoot = header.hashFinalSaplingRoot
            self.nTime = header.nTime
            self.nBits = header.nBits
            self.nNonce = header.nNonce
            self.nSolution = list(header.nSolution)
        self.sha256: int | None = None
        self.hash: str | None = None

    def deserialize(self, f: io.BytesIO) -> None:
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.hashPrevBlock = deser_uint256(f)
        self.hashMerkleRoot = deser_uint256(f)
        self.hashFinalSaplingRoot = deser_uint256(f)
        self.nTime = struct.unpack("<I", f.read(4))[0]
        self.nBits = struct.unpack("<I", f.read(4))[0]
        self.nNonce = deser_uint256(f)
        self.nSolution = deser_char_vector(f)
        self.sha256 = None
        self.hash = None

    def serialize(self) -> bytes:
        return (
            struct.pack("<i", self.nVersion)
            + ser_uint256(self.hashPrevBlock)
            + ser_uint256(self.hashMerkleRoot)
            + ser_uint256(self.hashFinalSaplingRoot)
            + struct.pack("<I", self.nTime)
            + struct.pack("<I", self.nBits)
            + ser_uint256(self.nNonce)
            + ser_char_vector(self.nSolution)
        )

    def calc_sha256(self) -> None:
        if self.sha256 is None:
            # The block hash is over the header only; serialize it explicitly so a
            # CBlock subclass does not fold its transactions into the hash.
            r = CBlockHeader.serialize(self)
            self.sha256 = uint256_from_str(hash256(r))
            self.hash = hash256(r)[::-1].hex()

    def rehash(self) -> int:
        self.sha256 = None
        self.calc_sha256()
        assert self.sha256 is not None
        return self.sha256

    def __repr__(self) -> str:
        return f"CBlockHeader(nVersion={self.nVersion} hashPrevBlock={self.hashPrevBlock:064x})"


class CBlock(CBlockHeader):
    def __init__(self, header: CBlockHeader | None = None) -> None:
        super().__init__(header)
        self.vtx: list[CTransaction] = []

    def deserialize(self, f: io.BytesIO) -> None:
        super().deserialize(f)
        self.vtx = deser_vector(f, CTransaction)

    def serialize(self) -> bytes:
        return super().serialize() + ser_vector(self.vtx)

    def calc_merkle_root(self) -> int:
        hashes = []
        for tx in self.vtx:
            tx.calc_sha256()
            assert tx.sha256 is not None
            hashes.append(ser_uint256(tx.sha256))
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i + 1, len(hashes) - 1)
                newhashes.append(hash256(hashes[i] + hashes[i2]))
            hashes = newhashes
        return uint256_from_str(hashes[0])

    def _equihash_digest(self, n: int, k: int):
        digest = blake2b(digest_size=(512 // n) * n // 8, person=zelcash_person(n, k))
        digest.update(CBlockHeader.serialize(self)[:108])
        return digest

    def is_valid(self, n: int = 48, k: int = 5) -> bool:
        """Validate the equihash solution.

        Regtest CheckProofOfWork returns true unconditionally, so a regtest block
        only needs a valid equihash solution, not a hash that meets the target.
        """
        digest = self._equihash_digest(n, k)
        hash_nonce(digest, self.nNonce)
        return gbp_validate(digest, bytes(self.nSolution), n, k)

    def solve(self, n: int = 48, k: int = 5) -> None:
        """Find a nonce whose equihash solution the daemon accepts on regtest."""
        base = self._equihash_digest(n, k)
        self.nNonce = 0
        while True:
            digest = base.copy()
            hash_nonce(digest, self.nNonce)
            solns = gbp_basic(digest, n, k)
            if solns:
                self.nSolution = list(solns[0])
                self.rehash()
                return
            self.nNonce += 1

    def __repr__(self) -> str:
        return f"CBlock(hash={self.hash} vtx={self.vtx!r})"


# ---- messages ------------------------------------------------------------


class msg_version:
    command = "version"

    def __init__(self, protocol_version: int = SPROUT_PROTO_VERSION) -> None:
        self.nVersion = protocol_version
        self.nServices = 1
        self.nTime = int(time.time())
        self.addrTo = CAddress()
        self.addrFrom = CAddress()
        self.nNonce = random.getrandbits(64)
        self.strSubVer = MY_SUBVERSION
        self.nStartingHeight = -1

    def deserialize(self, f: io.BytesIO) -> None:
        self.nVersion = struct.unpack("<i", f.read(4))[0]
        self.nServices = struct.unpack("<Q", f.read(8))[0]
        self.nTime = struct.unpack("<q", f.read(8))[0]
        self.addrTo = CAddress()
        self.addrTo.deserialize(f)
        if self.nVersion >= 106:
            self.addrFrom = CAddress()
            self.addrFrom.deserialize(f)
            self.nNonce = struct.unpack("<Q", f.read(8))[0]
            self.strSubVer = deser_string(f)
            if self.nVersion >= 209:
                self.nStartingHeight = struct.unpack("<i", f.read(4))[0]

    def serialize(self) -> bytes:
        return (
            struct.pack("<i", self.nVersion)
            + struct.pack("<Q", self.nServices)
            + struct.pack("<q", self.nTime)
            + self.addrTo.serialize()
            + self.addrFrom.serialize()
            + struct.pack("<Q", self.nNonce)
            + ser_string(self.strSubVer)
            + struct.pack("<i", self.nStartingHeight)
        )

    def __repr__(self) -> str:
        return f"msg_version(nVersion={self.nVersion} nStartingHeight={self.nStartingHeight})"


class _Empty:
    """Base for parameterless messages."""

    command = ""

    def deserialize(self, f: io.BytesIO) -> None:
        pass

    def serialize(self) -> bytes:
        return b""

    def __repr__(self) -> str:
        return f"msg_{self.command}()"


class msg_verack(_Empty):
    command = "verack"


class msg_getaddr(_Empty):
    command = "getaddr"


class msg_mempool(_Empty):
    command = "mempool"


class msg_filterclear(_Empty):
    command = "filterclear"


class _InvVector:
    """Base for messages carrying a vector of CInv."""

    command = ""

    def __init__(self, inv: list[CInv] | None = None) -> None:
        self.inv = inv if inv is not None else []

    def deserialize(self, f: io.BytesIO) -> None:
        self.inv = deser_vector(f, CInv)

    def serialize(self) -> bytes:
        return ser_vector(self.inv)

    def __repr__(self) -> str:
        return f"msg_{self.command}(inv={self.inv!r})"


class msg_inv(_InvVector):
    command = "inv"


class msg_getdata(_InvVector):
    command = "getdata"


class msg_notfound(_InvVector):
    command = "notfound"


class msg_addr:
    command = "addr"

    def __init__(self) -> None:
        self.addrs: list[CAddress] = []

    def deserialize(self, f: io.BytesIO) -> None:
        # Each entry is a 4-byte nTime followed by the timeless CAddress.
        self.addrs = []
        for _ in range(_deser_compact_size(f)):
            addr = CAddress()
            addr.nTime = struct.unpack("<I", f.read(4))[0]
            addr.deserialize(f)
            self.addrs.append(addr)

    def serialize(self) -> bytes:
        r = _ser_compact_size(len(self.addrs))
        for addr in self.addrs:
            r += struct.pack("<I", addr.nTime) + addr.serialize()
        return r

    def __repr__(self) -> str:
        return f"msg_addr(addrs={self.addrs!r})"


class msg_tx:
    command = "tx"

    def __init__(self, tx: CTransaction | None = None) -> None:
        self.tx = tx if tx is not None else CTransaction()

    def deserialize(self, f: io.BytesIO) -> None:
        self.tx = CTransaction()
        self.tx.deserialize(f)

    def serialize(self) -> bytes:
        return self.tx.serialize()

    def __repr__(self) -> str:
        return f"msg_tx(tx={self.tx!r})"


class msg_block:
    command = "block"

    def __init__(self, block: CBlock | None = None) -> None:
        self.block = block if block is not None else CBlock()

    def deserialize(self, f: io.BytesIO) -> None:
        self.block = CBlock()
        self.block.deserialize(f)

    def serialize(self) -> bytes:
        return self.block.serialize()

    def __repr__(self) -> str:
        return f"msg_block(block={self.block!r})"


class _Locator:
    """Base for getblocks/getheaders (a locator plus a stop hash)."""

    command = ""

    def __init__(self) -> None:
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f: io.BytesIO) -> None:
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self) -> bytes:
        return self.locator.serialize() + ser_uint256(self.hashstop)

    def __repr__(self) -> str:
        return f"msg_{self.command}(locator={self.locator!r} hashstop={self.hashstop:064x})"


class msg_getblocks(_Locator):
    command = "getblocks"


class msg_getheaders(_Locator):
    command = "getheaders"


class msg_headers:
    command = "headers"

    def __init__(self) -> None:
        self.headers: list[CBlockHeader] = []

    def deserialize(self, f: io.BytesIO) -> None:
        self.headers = [CBlockHeader(x) for x in deser_vector(f, CBlock)]

    def serialize(self) -> bytes:
        return ser_vector([CBlock(x) for x in self.headers])

    def __repr__(self) -> str:
        return f"msg_headers(headers={self.headers!r})"


class _Nonce:
    """Base for ping/pong (an 8-byte nonce)."""

    command = ""

    def __init__(self, nonce: int = 0) -> None:
        self.nonce = nonce

    def deserialize(self, f: io.BytesIO) -> None:
        self.nonce = struct.unpack("<Q", f.read(8))[0]

    def serialize(self) -> bytes:
        return struct.pack("<Q", self.nonce)

    def __repr__(self) -> str:
        return f"msg_{self.command}(nonce={self.nonce:016x})"


class msg_ping(_Nonce):
    command = "ping"


class msg_pong(_Nonce):
    command = "pong"


class msg_reject:
    command = "reject"

    def __init__(self) -> None:
        self.message = b""
        self.code = 0
        self.reason = b""
        self.data = 0

    def deserialize(self, f: io.BytesIO) -> None:
        self.message = deser_string(f)
        self.code = struct.unpack("<B", f.read(1))[0]
        self.reason = deser_string(f)
        if self.message in (b"block", b"tx"):
            self.data = deser_uint256(f)

    def serialize(self) -> bytes:
        r = ser_string(self.message) + struct.pack("<B", self.code) + ser_string(self.reason)
        if self.message in (b"block", b"tx"):
            r += ser_uint256(self.data)
        return r

    def __repr__(self) -> str:
        return f"msg_reject(message={self.message!r} code={self.code} reason={self.reason!r})"


class msg_filteradd:
    command = "filteradd"

    def __init__(self, data: bytes = b"") -> None:
        self.data = data

    def deserialize(self, f: io.BytesIO) -> None:
        self.data = deser_string(f)

    def serialize(self) -> bytes:
        return ser_string(self.data)

    def __repr__(self) -> str:
        return f"msg_filteradd(data={self.data!r})"


# ---- connection ----------------------------------------------------------


class NodeConnCB:
    """Callback target for a NodeConn. Subclass and override on_<command>.

    The default handlers complete the handshake (reply verack to version, pong
    to ping) and request advertised inventory, mirroring a real peer.
    """

    def __init__(self) -> None:
        self.verack_received = False
        self.connection: NodeConn | None = None
        self.ping_counter = 1
        self.last_pong = msg_pong()

    def add_connection(self, conn: "NodeConn") -> None:
        self.connection = conn

    def deliver(self, conn: "NodeConn", message: Any) -> None:
        handler = getattr(self, "on_" + message.command, None)
        if handler is not None:
            handler(conn, message)

    def on_version(self, conn: "NodeConn", message: msg_version) -> None:
        if message.nVersion >= 209:
            conn.send_message(msg_verack())
        conn.ver_send = min(SPROUT_PROTO_VERSION, message.nVersion)
        if message.nVersion < 209:
            conn.ver_recv = conn.ver_send

    def on_verack(self, conn: "NodeConn", message: msg_verack) -> None:
        conn.ver_recv = conn.ver_send
        self.verack_received = True

    def on_inv(self, conn: "NodeConn", message: msg_inv) -> None:
        want = msg_getdata()
        want.inv = [i for i in message.inv if i.type != 0]
        if want.inv:
            conn.send_message(want)

    def on_ping(self, conn: "NodeConn", message: msg_ping) -> None:
        if conn.ver_send > BIP0031_VERSION:
            conn.send_message(msg_pong(message.nonce))

    def on_pong(self, conn: "NodeConn", message: msg_pong) -> None:
        self.last_pong = message

    def on_close(self, conn: "NodeConn") -> None:
        pass

    async def wait_for(self, predicate: Callable[[], bool], timeout: float = 30) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while not predicate():
            if loop.time() > deadline:
                raise AssertionError("mininode wait_for timed out")
            await asyncio.sleep(0.05)

    async def wait_for_verack(self, timeout: float = 30) -> None:
        await self.wait_for(lambda: self.verack_received, timeout)

    async def sync_with_ping(self, timeout: float = 30) -> None:
        """Round-trip a ping so all earlier messages are known to be processed."""
        assert self.connection is not None
        self.connection.send_message(msg_ping(self.ping_counter))
        await self.wait_for(lambda: self.last_pong.nonce == self.ping_counter, timeout)
        self.ping_counter += 1


class NodeConn:
    """An outbound P2P connection to a regtest node, driven over asyncio."""

    messagemap: dict[str, type] = {
        "version": msg_version,
        "verack": msg_verack,
        "addr": msg_addr,
        "inv": msg_inv,
        "getdata": msg_getdata,
        "notfound": msg_notfound,
        "getblocks": msg_getblocks,
        "tx": msg_tx,
        "block": msg_block,
        "getaddr": msg_getaddr,
        "ping": msg_ping,
        "pong": msg_pong,
        "headers": msg_headers,
        "getheaders": msg_getheaders,
        "reject": msg_reject,
        "mempool": msg_mempool,
    }
    MAGIC_BYTES = {
        "mainnet": b"\x24\xe9\x27\x64",
        "testnet3": b"\xfa\x1a\xf9\xbf",
        "regtest": b"\xaa\xe8\x3f\x5f",
    }

    def __init__(
        self,
        dstaddr: str,
        dstport: int,
        cb: NodeConnCB,
        net: str = "regtest",
        protocol_version: int = SPROUT_PROTO_VERSION,
    ) -> None:
        self.dstaddr = dstaddr
        self.dstport = dstport
        self.cb = cb
        self.network = net
        self.protocol_version = protocol_version
        self.ver_send = 209
        self.ver_recv = 209
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._recv_task: asyncio.Task | None = None
        cb.add_connection(self)

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_connection(self.dstaddr, self.dstport)
        vt = msg_version(self.protocol_version)
        vt.addrTo.ip = self.dstaddr
        vt.addrTo.port = self.dstport
        vt.addrFrom.ip = "0.0.0.0"
        vt.addrFrom.port = 0
        self.send_message(vt)
        self._recv_task = asyncio.create_task(self._recv_loop())

    def send_message(self, message: Any) -> None:
        assert self._writer is not None, "not connected"
        command: str = message.command
        data: bytes = message.serialize()
        tmsg = self.MAGIC_BYTES[self.network]
        tmsg += command.encode() + b"\x00" * (12 - len(command))
        tmsg += struct.pack("<I", len(data))
        if self.ver_send >= 209:
            tmsg += hash256(data)[:4]
        tmsg += data
        self._writer.write(tmsg)

    async def _recv_loop(self) -> None:
        assert self._reader is not None
        try:
            while True:
                magic = await self._reader.readexactly(4)
                if magic != self.MAGIC_BYTES[self.network]:
                    raise ValueError(f"got bad magic {magic!r}")
                command = (await self._reader.readexactly(12)).split(b"\x00", 1)[0].decode()
                msglen = struct.unpack("<I", await self._reader.readexactly(4))[0]
                checksum = await self._reader.readexactly(4)
                payload = await self._reader.readexactly(msglen)
                if hash256(payload)[:4] != checksum:
                    raise ValueError("got bad checksum")
                if command in self.messagemap:
                    msg = self.messagemap[command]()
                    msg.deserialize(io.BytesIO(payload))
                    self.cb.deliver(self, msg)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.CancelledError):
            pass
        finally:
            self.cb.on_close(self)

    async def disconnect_node(self) -> None:
        if self._recv_task is not None:
            self._recv_task.cancel()
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (ConnectionError, OSError):
                pass
