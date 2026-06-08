// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#include "crypto/ecvrf.h"

#include <secp256k1.h>
#include <secp256k1_vrf.h>

#include <cstring>

namespace {
// Verify-only context, sufficient for pubkey parse/serialize used below.
// secp256k1_vrf_prove/verify themselves are context-free. C++11 guarantees
// thread-safe initialisation of this function-local static.
secp256k1_context* VrfContext()
{
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    return ctx;
}
} // namespace

bool ECVRF_Prove(const CKey& sk, const CPubKey& pk, const uint256& seed,
                 std::vector<unsigned char>& proofOut, uint256& outputOut)
{
    if (sk.size() != 32) return false;

    secp256k1_pubkey parsed;
    if (!secp256k1_ec_pubkey_parse(VrfContext(), &parsed, pk.begin(), pk.size())) return false;

    unsigned char proof[81];
    if (!secp256k1_vrf_prove(proof, sk.begin(), &parsed, seed.begin(), 32)) return false;

    unsigned char beta[32];
    if (!secp256k1_vrf_proof_to_hash(beta, proof)) return false;

    proofOut.assign(proof, proof + 81);
    std::memcpy(outputOut.begin(), beta, 32);
    return true;
}

bool ECVRF_Verify(const CPubKey& pk, const uint256& seed,
                  const std::vector<unsigned char>& proof, uint256& outputOut)
{
    if (proof.size() != 81) return false;

    // The verify API takes a 33-byte compressed pubkey.
    unsigned char pk33[33];
    if (pk.size() == 33) {
        std::memcpy(pk33, pk.begin(), 33);
    } else {
        secp256k1_pubkey parsed;
        size_t len = 33;
        if (!secp256k1_ec_pubkey_parse(VrfContext(), &parsed, pk.begin(), pk.size())) return false;
        if (!secp256k1_ec_pubkey_serialize(VrfContext(), pk33, &len, &parsed, SECP256K1_EC_COMPRESSED)) return false;
    }

    unsigned char beta[32];
    if (!secp256k1_vrf_verify(beta, proof.data(), pk33, seed.begin(), 32)) return false;

    std::memcpy(outputOut.begin(), beta, 32);
    return true;
}
