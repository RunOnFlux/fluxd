"""Pure-python Equihash solver and verifier (Wagner's basic algorithm).

Ported to python3 from the legacy test-framework module. Regtest uses the small
n=48, k=5 parameters, whose personalization is "ZcashPoW" (the larger ZelHash
144,5 parameters use "ZelProof"), so the personalization here matches the daemon
for regtest. Only used to solve regtest blocks in the P2P tests.
"""

import struct
from functools import reduce
from operator import itemgetter

WORD_SIZE = 32
WORD_MASK = (1 << WORD_SIZE) - 1


def expand_array(inp: bytearray, out_len: int, bit_len: int, byte_pad: int = 0) -> bytearray:
    assert bit_len >= 8 and WORD_SIZE >= 7 + bit_len
    out_width = (bit_len + 7) // 8 + byte_pad
    assert out_len == 8 * out_width * len(inp) // bit_len
    out = bytearray(out_len)
    bit_len_mask = (1 << bit_len) - 1

    acc_bits = 0
    acc_value = 0
    j = 0
    for i in range(len(inp)):
        acc_value = ((acc_value << 8) & WORD_MASK) | inp[i]
        acc_bits += 8
        if acc_bits >= bit_len:
            acc_bits -= bit_len
            for x in range(byte_pad, out_width):
                out[j + x] = (acc_value >> (acc_bits + (8 * (out_width - x - 1)))) & (
                    (bit_len_mask >> (8 * (out_width - x - 1))) & 0xFF
                )
            j += out_width
    return out


def compress_array(inp: bytearray, out_len: int, bit_len: int, byte_pad: int = 0) -> bytearray:
    assert bit_len >= 8 and WORD_SIZE >= 7 + bit_len
    in_width = (bit_len + 7) // 8 + byte_pad
    assert out_len == bit_len * len(inp) // (8 * in_width)
    out = bytearray(out_len)
    bit_len_mask = (1 << bit_len) - 1

    acc_bits = 0
    acc_value = 0
    j = 0
    for i in range(out_len):
        if acc_bits < 8:
            acc_value = ((acc_value << bit_len) & WORD_MASK) | inp[j]
            for x in range(byte_pad, in_width):
                acc_value = acc_value | (
                    (inp[j + x] & ((bit_len_mask >> (8 * (in_width - x - 1))) & 0xFF))
                    << (8 * (in_width - x - 1))
                )
            j += in_width
            acc_bits += bit_len
        acc_bits -= 8
        out[i] = (acc_value >> acc_bits) & 0xFF
    return out


def get_indices_from_minimal(minimal: bytes, bit_len: int) -> list[int]:
    eh_index_size = 4
    assert (bit_len + 7) // 8 <= eh_index_size
    len_indices = 8 * eh_index_size * len(minimal) // bit_len
    byte_pad = eh_index_size - (bit_len + 7) // 8
    expanded = expand_array(bytearray(minimal), len_indices, bit_len, byte_pad)
    return [
        struct.unpack(">I", expanded[i : i + 4])[0] for i in range(0, len_indices, eh_index_size)
    ]


def get_minimal_from_indices(indices: list[int], bit_len: int) -> bytearray:
    eh_index_size = 4
    assert (bit_len + 7) // 8 <= eh_index_size
    len_indices = len(indices) * eh_index_size
    min_len = bit_len * len_indices // (8 * eh_index_size)
    byte_pad = eh_index_size - (bit_len + 7) // 8
    byte_indices = bytearray(b"".join(struct.pack(">I", i) for i in indices))
    return compress_array(byte_indices, min_len, bit_len, byte_pad)


def hash_nonce(digest, nonce: int) -> None:
    for i in range(8):
        digest.update(struct.pack("<I", (nonce >> (32 * i)) & 0xFFFFFFFF))


def hash_xi(digest, xi: int):
    digest.update(struct.pack("<I", xi))
    return digest


def count_zeroes(h: bytearray) -> int:
    return ("".join(f"{x:08b}" for x in h) + "1").index("1")


def has_collision(ha: bytearray, hb: bytearray, i: int, length: int) -> bool:
    return reduce(
        lambda x, y: x and y,
        [ha[j] == hb[j] for j in range((i - 1) * length // 8, i * length // 8)],
    )


def distinct_indices(a, b) -> bool:
    return not (set(a) & set(b))


def xor(ha: bytearray, hb: bytearray) -> bytearray:
    return bytearray(a ^ b for a, b in zip(ha, hb))


def gbp_basic(digest, n: int, k: int) -> list[bytearray]:
    """Basic Wagner's algorithm for the generalized birthday problem."""
    validate_params(n, k)
    collision_length = n // (k + 1)
    hash_length = (k + 1) * ((collision_length + 7) // 8)
    indices_per_hash_output = 512 // n

    # Generate the first list.
    X = []
    tmp_hash = b""
    for i in range(2 ** (collision_length + 1)):
        r = i % indices_per_hash_output
        if r == 0:
            curr_digest = digest.copy()
            hash_xi(curr_digest, i // indices_per_hash_output)
            tmp_hash = curr_digest.digest()
        X.append(
            (
                expand_array(
                    bytearray(tmp_hash[r * n // 8 : (r + 1) * n // 8]),
                    hash_length,
                    collision_length,
                ),
                (i,),
            )
        )

    for i in range(1, k):
        X.sort(key=itemgetter(0))
        Xc = []
        while len(X) > 0:
            j = 1
            while j < len(X):
                if not has_collision(X[-1][0], X[-1 - j][0], i, collision_length):
                    break
                j += 1
            for ll in range(j - 1):
                for m in range(ll + 1, j):
                    if distinct_indices(X[-1 - ll][1], X[-1 - m][1]):
                        if X[-1 - ll][1][0] < X[-1 - m][1][0]:
                            concat = X[-1 - ll][1] + X[-1 - m][1]
                        else:
                            concat = X[-1 - m][1] + X[-1 - ll][1]
                        Xc.append((xor(X[-1 - ll][0], X[-1 - m][0]), concat))
            while j > 0:
                X.pop(-1)
                j -= 1
        X = Xc

    # Find a collision on the last 2n/(k+1) bits.
    X.sort(key=itemgetter(0))
    solns = []
    while len(X) > 0:
        j = 1
        while j < len(X):
            if not (
                has_collision(X[-1][0], X[-1 - j][0], k, collision_length)
                and has_collision(X[-1][0], X[-1 - j][0], k + 1, collision_length)
            ):
                break
            j += 1
        for ll in range(j - 1):
            for m in range(ll + 1, j):
                res = xor(X[-1 - ll][0], X[-1 - m][0])
                if count_zeroes(res) == 8 * hash_length and distinct_indices(
                    X[-1 - ll][1], X[-1 - m][1]
                ):
                    if X[-1 - ll][1][0] < X[-1 - m][1][0]:
                        solns.append(list(X[-1 - ll][1] + X[-1 - m][1]))
                    else:
                        solns.append(list(X[-1 - m][1] + X[-1 - ll][1]))
        while j > 0:
            X.pop(-1)
            j -= 1
    return [get_minimal_from_indices(soln, collision_length + 1) for soln in solns]


def gbp_validate(digest, minimal: bytes, n: int, k: int) -> bool:
    validate_params(n, k)
    collision_length = n // (k + 1)
    hash_length = (k + 1) * ((collision_length + 7) // 8)
    indices_per_hash_output = 512 // n
    solution_width = (1 << k) * (collision_length + 1) // 8

    if len(minimal) != solution_width:
        return False

    X = []
    for i in get_indices_from_minimal(minimal, collision_length + 1):
        r = i % indices_per_hash_output
        curr_digest = digest.copy()
        hash_xi(curr_digest, i // indices_per_hash_output)
        tmp_hash = curr_digest.digest()
        X.append(
            (
                expand_array(
                    bytearray(tmp_hash[r * n // 8 : (r + 1) * n // 8]),
                    hash_length,
                    collision_length,
                ),
                (i,),
            )
        )

    for r in range(1, k + 1):
        Xc = []
        for i in range(0, len(X), 2):
            if not has_collision(X[i][0], X[i + 1][0], r, collision_length):
                return False
            if X[i + 1][1][0] < X[i][1][0]:
                return False
            if not distinct_indices(X[i][1], X[i + 1][1]):
                return False
            Xc.append((xor(X[i][0], X[i + 1][0]), X[i][1] + X[i + 1][1]))
        X = Xc

    if len(X) != 1:
        return False
    return count_zeroes(X[0][0]) == 8 * hash_length


def zelcash_person(n: int, k: int) -> bytes:
    return b"ZcashPoW" + struct.pack("<II", n, k)


def validate_params(n: int, k: int) -> None:
    if k >= n:
        raise ValueError("n must be larger than k")
    if ((n // (k + 1)) + 1) >= 32:
        raise ValueError("Parameters must satisfy n/(k+1)+1 < 32")
