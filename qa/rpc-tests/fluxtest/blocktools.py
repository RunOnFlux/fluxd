"""Helpers for building regtest blocks and transactions for the P2P tests."""

from .mininode import COIN, CBlock, COutPoint, CTransaction, CTxIn, CTxOut
from .script import OP_0, OP_EQUAL, OP_HASH160, CScript, CScriptNum

# The regtest founders/dev-fund P2SH that the coinbase must pay before the first
# halving.
_REGTEST_FOUNDERS = bytes(
    [0x67, 0x08, 0xE6, 0x67, 0x0D, 0xB0, 0xB9, 0x50, 0xDA, 0xC6,
     0x80, 0x31, 0x02, 0x5C, 0xC5, 0xB6, 0x32, 0x13, 0xA4, 0x91]
)  # fmt: skip
REGTEST_HALVING_INTERVAL = 150


def create_coinbase(height: int) -> CTransaction:
    """An anyone-can-spend coinbase paying the founders reward before halving."""
    coinbase = CTransaction()
    coinbase.vin.append(
        CTxIn(COutPoint(0, 0xFFFFFFFF), CScript([CScriptNum(height), OP_0]), 0xFFFFFFFF)
    )
    reward = (150 * COIN) >> (height // REGTEST_HALVING_INTERVAL)
    miner = CTxOut(reward, CScript())
    coinbase.vout = [miner]
    if height // REGTEST_HALVING_INTERVAL == 0:
        founders_value = reward // 5
        miner.nValue = reward - founders_value
        founders = CTxOut(founders_value, CScript([OP_HASH160, _REGTEST_FOUNDERS, OP_EQUAL]))
        coinbase.vout = [miner, founders]
    coinbase.calc_sha256()
    return coinbase


def create_block(
    hashprev: int, coinbase: CTransaction, ntime: int, nbits: int = 0x200F0F0F
) -> CBlock:
    block = CBlock()
    block.nVersion = 4
    block.nTime = ntime
    block.hashPrevBlock = hashprev
    block.nBits = nbits
    block.vtx = [coinbase]
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block


def create_transaction(prevtx: CTransaction, n: int, sig: bytes, value: int) -> CTransaction:
    """A transaction spending the nth output of ``prevtx`` to an anyone-can-spend output."""
    assert prevtx.sha256 is not None
    tx = CTransaction()
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xFFFFFFFF))
    tx.vout.append(CTxOut(value, CScript()))
    tx.calc_sha256()
    return tx
