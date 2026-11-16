// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PON_CLAIM_H
#define BITCOIN_PON_CLAIM_H

#include "arith_uint256.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <set>
#include <stdint.h>
#include <utility>
#include <vector>

/** Claims a node keeps, and passes on, for one slot. */
static const size_t PON_VRF_CLAIMS_KEPT = 6;
/** Seconds a node gives a better claim to mint before it mints itself. */
static const uint32_t PON_VRF_CLAIM_WAIT_SECONDS = 4;

/**
 * A node's announcement, as a slot begins, of its draw for it. Nothing in consensus reads a
 * claim: it tells the other eligible nodes of the slot which of them is to mint first.
 */
class CPonClaim
{
public:
    uint32_t slot;
    COutPoint collateral;
    uint256 output;
    std::vector<unsigned char> proof;

    CPonClaim() : slot(0) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(slot);
        READWRITE(collateral);
        READWRITE(output);
        READWRITE(proof);
    }
};

/**
 * The best claims of each slot a node has heard, its own among them. It holds outputs only:
 * a claim is offered once its proof is verified.
 */
class CPonClaimPool
{
public:
    /**
     * Offer a verified claim. True when it is new and among the best PON_VRF_CLAIMS_KEPT of
     * its slot, which is when it is kept and passed on.
     */
    bool Add(uint32_t slot, const COutPoint& collateral, const arith_uint256& output);

    /** Whether a claim of this collateral is held for the slot. */
    bool Have(uint32_t slot, const COutPoint& collateral) const;

    /** The outputs of the claims held for the slot that are better than output, best first. */
    std::vector<arith_uint256> BetterThan(uint32_t slot, const arith_uint256& output) const;

    /** Drop the claims of every slot before this one. */
    void Forget(uint32_t slotCurrent);

private:
    typedef std::set<std::pair<arith_uint256, COutPoint> > SlotClaims;

    mutable CCriticalSection cs;
    std::map<uint32_t, SlotClaims> mapSlots;
};

extern CPonClaimPool g_ponClaims;

/**
 * The second of its slot at which a node with a draw of turn nOwnTurn mints, given the turns
 * of the better claims it has heard, best first: each is given PON_VRF_CLAIM_WAIT_SECONDS
 * after its own turn, or after the one before it, to mint.
 */
uint32_t PonVrfMintSecond(uint32_t nOwnTurn, const std::vector<uint32_t>& vBetterTurns);

#endif // BITCOIN_PON_CLAIM_H
