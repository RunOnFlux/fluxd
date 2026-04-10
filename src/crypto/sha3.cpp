// Copyright (c) 2020-present The Bitcoin Core developers
// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Based on https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
// by Markku-Juhani O. Saarinen <mjos@iki.fi>

#include "crypto/sha3.h"
#include "crypto/common.h"

#include <algorithm>
#include <assert.h>
#include <iterator>
#include <string.h>

namespace {
inline uint64_t Rotl64(uint64_t x, int n)
{
    return (x << n) | (x >> (64 - n));
}
} // namespace

void KeccakF(uint64_t (&st)[25])
{
    static const uint64_t RNDC[24] = {
        0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
        0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
        0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
        0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
        0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
        0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
    };
    static const int ROUNDS = 24;

    for (int round = 0; round < ROUNDS; ++round) {
        uint64_t bc0, bc1, bc2, bc3, bc4, t;

        // Theta
        bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
        bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
        bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
        bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
        bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];
        t = bc4 ^ Rotl64(bc1, 1); st[0] ^= t; st[5] ^= t; st[10] ^= t; st[15] ^= t; st[20] ^= t;
        t = bc0 ^ Rotl64(bc2, 1); st[1] ^= t; st[6] ^= t; st[11] ^= t; st[16] ^= t; st[21] ^= t;
        t = bc1 ^ Rotl64(bc3, 1); st[2] ^= t; st[7] ^= t; st[12] ^= t; st[17] ^= t; st[22] ^= t;
        t = bc2 ^ Rotl64(bc4, 1); st[3] ^= t; st[8] ^= t; st[13] ^= t; st[18] ^= t; st[23] ^= t;
        t = bc3 ^ Rotl64(bc0, 1); st[4] ^= t; st[9] ^= t; st[14] ^= t; st[19] ^= t; st[24] ^= t;

        // Rho Pi
        t = st[1];
        bc0 = st[10]; st[10] = Rotl64(t, 1); t = bc0;
        bc0 = st[7]; st[7] = Rotl64(t, 3); t = bc0;
        bc0 = st[11]; st[11] = Rotl64(t, 6); t = bc0;
        bc0 = st[17]; st[17] = Rotl64(t, 10); t = bc0;
        bc0 = st[18]; st[18] = Rotl64(t, 15); t = bc0;
        bc0 = st[3]; st[3] = Rotl64(t, 21); t = bc0;
        bc0 = st[5]; st[5] = Rotl64(t, 28); t = bc0;
        bc0 = st[16]; st[16] = Rotl64(t, 36); t = bc0;
        bc0 = st[8]; st[8] = Rotl64(t, 45); t = bc0;
        bc0 = st[21]; st[21] = Rotl64(t, 55); t = bc0;
        bc0 = st[24]; st[24] = Rotl64(t, 2); t = bc0;
        bc0 = st[4]; st[4] = Rotl64(t, 14); t = bc0;
        bc0 = st[15]; st[15] = Rotl64(t, 27); t = bc0;
        bc0 = st[23]; st[23] = Rotl64(t, 41); t = bc0;
        bc0 = st[19]; st[19] = Rotl64(t, 56); t = bc0;
        bc0 = st[13]; st[13] = Rotl64(t, 8); t = bc0;
        bc0 = st[12]; st[12] = Rotl64(t, 25); t = bc0;
        bc0 = st[2]; st[2] = Rotl64(t, 43); t = bc0;
        bc0 = st[20]; st[20] = Rotl64(t, 62); t = bc0;
        bc0 = st[14]; st[14] = Rotl64(t, 18); t = bc0;
        bc0 = st[22]; st[22] = Rotl64(t, 39); t = bc0;
        bc0 = st[9]; st[9] = Rotl64(t, 61); t = bc0;
        bc0 = st[6]; st[6] = Rotl64(t, 20); t = bc0;
        st[1] = Rotl64(t, 44);

        // Chi Iota
        bc0 = st[0]; bc1 = st[1]; bc2 = st[2]; bc3 = st[3]; bc4 = st[4];
        st[0] = bc0 ^ (~bc1 & bc2) ^ RNDC[round];
        st[1] = bc1 ^ (~bc2 & bc3);
        st[2] = bc2 ^ (~bc3 & bc4);
        st[3] = bc3 ^ (~bc4 & bc0);
        st[4] = bc4 ^ (~bc0 & bc1);
        bc0 = st[5]; bc1 = st[6]; bc2 = st[7]; bc3 = st[8]; bc4 = st[9];
        st[5] = bc0 ^ (~bc1 & bc2);
        st[6] = bc1 ^ (~bc2 & bc3);
        st[7] = bc2 ^ (~bc3 & bc4);
        st[8] = bc3 ^ (~bc4 & bc0);
        st[9] = bc4 ^ (~bc0 & bc1);
        bc0 = st[10]; bc1 = st[11]; bc2 = st[12]; bc3 = st[13]; bc4 = st[14];
        st[10] = bc0 ^ (~bc1 & bc2);
        st[11] = bc1 ^ (~bc2 & bc3);
        st[12] = bc2 ^ (~bc3 & bc4);
        st[13] = bc3 ^ (~bc4 & bc0);
        st[14] = bc4 ^ (~bc0 & bc1);
        bc0 = st[15]; bc1 = st[16]; bc2 = st[17]; bc3 = st[18]; bc4 = st[19];
        st[15] = bc0 ^ (~bc1 & bc2);
        st[16] = bc1 ^ (~bc2 & bc3);
        st[17] = bc2 ^ (~bc3 & bc4);
        st[18] = bc3 ^ (~bc4 & bc0);
        st[19] = bc4 ^ (~bc0 & bc1);
        bc0 = st[20]; bc1 = st[21]; bc2 = st[22]; bc3 = st[23]; bc4 = st[24];
        st[20] = bc0 ^ (~bc1 & bc2);
        st[21] = bc1 ^ (~bc2 & bc3);
        st[22] = bc2 ^ (~bc3 & bc4);
        st[23] = bc3 ^ (~bc4 & bc0);
        st[24] = bc4 ^ (~bc0 & bc1);
    }
}

SHA3_256::SHA3_256() : m_bufsize(0), m_pos(0)
{
    std::fill(std::begin(m_state), std::end(m_state), 0);
    std::fill(std::begin(m_buffer), std::end(m_buffer), 0);
}

SHA3_256& SHA3_256::Write(const unsigned char* data, size_t size)
{
    if (m_bufsize && size >= sizeof(m_buffer) - m_bufsize) {
        // Fill the buffer and process it.
        memcpy(m_buffer + m_bufsize, data, sizeof(m_buffer) - m_bufsize);
        data += sizeof(m_buffer) - m_bufsize;
        size -= sizeof(m_buffer) - m_bufsize;
        m_state[m_pos++] ^= ReadLE64(m_buffer);
        m_bufsize = 0;
        if (m_pos == RATE_BUFFERS) {
            KeccakF(m_state);
            m_pos = 0;
        }
    }
    while (size >= sizeof(m_buffer)) {
        // Process chunks directly from the input.
        m_state[m_pos++] ^= ReadLE64(data);
        data += 8;
        size -= 8;
        if (m_pos == RATE_BUFFERS) {
            KeccakF(m_state);
            m_pos = 0;
        }
    }
    if (size) {
        // Keep the remainder in the buffer.
        memcpy(m_buffer + m_bufsize, data, size);
        m_bufsize += size;
    }
    return *this;
}

SHA3_256& SHA3_256::Finalize(unsigned char output[OUTPUT_SIZE])
{
    std::fill(m_buffer + m_bufsize, m_buffer + sizeof(m_buffer), 0);
    m_buffer[m_bufsize] ^= 0x06;
    m_state[m_pos] ^= ReadLE64(m_buffer);
    m_state[RATE_BUFFERS - 1] ^= 0x8000000000000000ULL;
    KeccakF(m_state);
    for (unsigned i = 0; i < 4; ++i) {
        WriteLE64(output + 8 * i, m_state[i]);
    }
    return *this;
}

SHA3_256& SHA3_256::Reset()
{
    m_bufsize = 0;
    m_pos = 0;
    std::fill(std::begin(m_state), std::end(m_state), 0);
    return *this;
}
