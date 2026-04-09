// Copyright (c) 2020-present The Bitcoin Core developers
// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA3_H
#define BITCOIN_CRYPTO_SHA3_H

#include <stdint.h>
#include <stdlib.h>

//! The Keccak-f[1600] transform.
void KeccakF(uint64_t (&st)[25]);

/** A hasher class for SHA3-256. */
class SHA3_256
{
private:
    uint64_t m_state[25];
    unsigned char m_buffer[8];
    unsigned m_bufsize;
    unsigned m_pos;

    //! Sponge rate in bits.
    static const unsigned RATE_BITS = 1088;

    //! Sponge rate expressed as a multiple of the buffer size.
    static const unsigned RATE_BUFFERS = RATE_BITS / (8 * sizeof(uint64_t));

public:
    static const size_t OUTPUT_SIZE = 32;

    SHA3_256();
    SHA3_256& Write(const unsigned char* data, size_t size);
    SHA3_256& Finalize(unsigned char output[OUTPUT_SIZE]);
    SHA3_256& Reset();
};

#endif // BITCOIN_CRYPTO_SHA3_H
