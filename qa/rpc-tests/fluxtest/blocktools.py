"""Helpers for building regtest blocks and transactions for the P2P tests."""

from .mininode import COIN, CBlock, COutPoint, CTransaction, CTxIn, CTxOut
from .script import OP_EQUAL, OP_HASH160, CScript, CScriptNum, script_for_address

# The regtest founders/dev-fund P2SH that the coinbase pays before the first
# halving.
_REGTEST_FOUNDERS = bytes(
    [0x67, 0x08, 0xE6, 0x67, 0x0D, 0xB0, 0xB9, 0x50, 0xDA, 0xC6,
     0x80, 0x31, 0x02, 0x5C, 0xC5, 0xB6, 0x32, 0x13, 0xA4, 0x91]
)  # fmt: skip
REGTEST_HALVING_INTERVAL = 150

# Regtest one-time exchange and foundation funding, both required in the coinbase
# at exactly this height.
_REGTEST_FUNDING_HEIGHT = 10
_REGTEST_EXCHANGE = ("tmRucHD85zgSigtA4sJJBDbPkMUJDcw5XDE", 3000000 * COIN)
_REGTEST_FOUNDATION = ("t2DFGpj2tciojsGKKrGVwQ92hUwAxWQQgJ9", 2500000 * COIN)

# Regtest swap-pool funding, required in the coinbase at heights 10, 20, 30, 40, 50.
_REGTEST_SWAPPOOL = ("t2Dsexh4v5g2dpL2LLCsR1p9TshMm63jSBM", 2100000 * COIN)
_REGTEST_SWAPPOOL_START = 10
_REGTEST_SWAPPOOL_INTERVAL = 10
_REGTEST_SWAPPOOL_MAX_TIMES = 5


def _is_swappool_height(height: int) -> bool:
    start, interval, times = (
        _REGTEST_SWAPPOOL_START,
        _REGTEST_SWAPPOOL_INTERVAL,
        _REGTEST_SWAPPOOL_MAX_TIMES,
    )
    if not start <= height <= start + interval * times:
        return False
    return any(height == start + interval * i for i in range(times))


def create_coinbase(height: int, extra: int = 0) -> CTransaction:
    """An anyone-can-spend coinbase paying the founders reward before halving.

    ``extra`` distinguishes otherwise-identical coinbases (e.g. competing blocks
    at the same height) without disturbing the BIP34 height that leads the input
    script.
    """
    coinbase = CTransaction()
    coinbase.vin.append(
        CTxIn(
            COutPoint(0, 0xFFFFFFFF),
            CScript([CScriptNum(height), CScriptNum(extra)]),
            0xFFFFFFFF,
        )
    )
    reward = (150 * COIN) >> (height // REGTEST_HALVING_INTERVAL)
    miner = CTxOut(reward, CScript())
    coinbase.vout = [miner]
    if height // REGTEST_HALVING_INTERVAL == 0:
        founders_value = reward // 5
        miner.nValue = reward - founders_value
        founders = CTxOut(founders_value, CScript([OP_HASH160, _REGTEST_FOUNDERS, OP_EQUAL]))
        coinbase.vout.append(founders)
    if height == _REGTEST_FUNDING_HEIGHT:
        for address, amount in (_REGTEST_EXCHANGE, _REGTEST_FOUNDATION):
            coinbase.vout.append(CTxOut(amount, script_for_address(address)))
    if _is_swappool_height(height):
        address, amount = _REGTEST_SWAPPOOL
        coinbase.vout.append(CTxOut(amount, script_for_address(address)))
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
