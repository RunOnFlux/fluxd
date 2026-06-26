"""The regtest proof-of-work difficulty rule, distilled from src/pow.cpp.

A mininode that builds its own chain must stamp each block with exactly the nBits
the daemon's GetNextWorkRequired would compute, or the block is rejected
"bad-diffbits". Regtest's parameters collapse that function to three cases:

  * heights 1..70 are always powLimit -- below height 10 the LWMA averaging
    window is not yet full and short chains return powLimit, and heights 10..70
    sit in the post-fork difficulty-reset window;

  * heights 71..73 sit in the ZelHash ramp window. With every upgrade set to
    NO_ACTIVATION_HEIGHT (-1) the ramp's scale factor (eh_epoch_2_end + 61 -
    height) goes negative and wraps through a 32-bit arith_uint256 multiply,
    overflowing modulo 2**256. The result no longer depends on the block times,
    so each of the three heights has a single fixed nBits (verified identical
    across 60s/241s/500s block spacing);

  * every other height returns powLimit whenever the block is spaced more than
    twice the 120s target past its parent (the regtest min-difficulty rule).

Spacing test blocks beyond 240s therefore keeps the whole chain at powLimit
except for the three ramp heights, whose constants are baked in below. (A block
spaced within 240s past height 73 would instead need the full Lwma3 retarget,
which these tests never require.) Regtest CheckProofOfWork ignores the
hash/target relation, so a block only needs nBits to match this value and a
valid equihash solution.
"""

POW_LIMIT_BITS = 0x200F0F0F  # GetCompact(regtest powLimit); also the genesis nBits
GENESIS_TIME = 1296688602
_MIN_DIFFICULTY_SPACING = 2 * 120  # > nPowTargetSpacing*2 -> min-difficulty (powLimit)
_RESET_WINDOW_END = 70  # last height of the post-fork powLimit reset window

# The ZelHash ramp window: three heights whose difficulty is a fixed, time-
# independent consequence of the ramp multiplier overflowing modulo 2**256.
_RAMP_BITS = {
    71: 0x200268CF,
    72: 0x20019058,
    73: 0x200232FB,
}


def next_bits(height: int, parent_time: int, block_time: int) -> int:
    """The nBits the daemon requires for a regtest block at ``height``.

    ``parent_time``/``block_time`` are the timestamps of the parent and of the
    block being built; a gap beyond twice the target makes the block
    min-difficulty (powLimit). Heights outside the reset and ramp windows must be
    spaced beyond 240s, which every caller here does.
    """
    if height in _RAMP_BITS:
        return _RAMP_BITS[height]
    if height <= _RESET_WINDOW_END:
        return POW_LIMIT_BITS
    if block_time > parent_time + _MIN_DIFFICULTY_SPACING:
        return POW_LIMIT_BITS
    raise ValueError(
        f"height {height} spaced {block_time - parent_time}s (<= {_MIN_DIFFICULTY_SPACING}s) "
        "would need the full Lwma3 retarget, which is not ported; space test blocks further apart"
    )
