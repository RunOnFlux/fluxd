#ifndef SECP256K1_VRF_H
#define SECP256K1_VRF_H
#include "secp256k1.h"
#ifdef __cplusplus
extern "C" {
#endif
/* ECVRF-SECP256K1-SHA256-TAI (draft-05, suite 0xFE). proof=81B, output=32B. */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_vrf_prove(
    unsigned char proof[81], const unsigned char *seckey, secp256k1_pubkey* pubkey,
    const void *msg, const unsigned int msglen) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_vrf_verify(
    unsigned char output[32], const unsigned char proof[81], const unsigned char pk[33],
    const void *msg, const unsigned int msglen) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_vrf_proof_to_hash(
    unsigned char output[32], const unsigned char proof[81]) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);
#ifdef __cplusplus
}
#endif
#endif
