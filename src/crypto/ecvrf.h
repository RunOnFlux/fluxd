// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_CRYPTO_ECVRF_H
#define BITCOIN_CRYPTO_ECVRF_H

#include "key.h"
#include "pubkey.h"
#include "uint256.h"

#include <vector>

// ECVRF-SECP256K1-SHA256-TAI (CFRG VRF draft-05, suite 0xFE), keyed to the fluxnode
// operator key. Backed by the vendored secp256k1 VRF module (src/secp256k1/src/modules/vrf).
//   proof  : 81 bytes (Gamma || c || s), to be carried in the block header
//   output : 32-byte VRF value (beta), compared against the PON target for eligibility
//
// The output is unforgeable and not grindable: it is determined by the operator secret key
// and `seed` (an epoch seed the proposer does not author), so the producer cannot bias it.

/** Prove: compute (proof, output) for operator key (sk,pk) over `seed`. Returns false on error. */
bool ECVRF_Prove(const CKey& sk, const CPubKey& pk, const uint256& seed,
                 std::vector<unsigned char>& proofOut, uint256& outputOut);

/** Verify: check `proof` for `pk` over `seed`; on success fills `outputOut` (beta). */
bool ECVRF_Verify(const CPubKey& pk, const uint256& seed,
                  const std::vector<unsigned char>& proof, uint256& outputOut);

#endif // BITCOIN_CRYPTO_ECVRF_H
