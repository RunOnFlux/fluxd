// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PON_CLAIM_H
#define BITCOIN_PON_CLAIM_H

#include "arith_uint256.h"
#include "consensus/params.h"
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
/** Claims a node reads from one peer in one slot; the rest are dropped unread. */
static const unsigned int PON_VRF_CLAIMS_PER_PEER = 100;
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

class CBlockIndex;

/** What became of a claim. */
enum class PonClaimResult {
    KEPT,               //!< among the best of its slot: kept, and to be passed on
    BAD_PROOF_SIZE,
    WRONG_SLOT,         //!< not the slot the clock is in, nor the next within the clock bound
    HELD,               //!< this collateral's claim for the slot is held already
    NOT_ACTIVE,         //!< the next block is not at a PON-VRF height
    UNCONFIRMED,        //!< the collateral is not a confirmed fluxnode
    BAD_PROOF,          //!< the proof does not give the output under that node's key
    NOT_ELIGIBLE,       //!< the output is over the target
    NOT_AMONG_BEST,
};

/** A word for a PonClaimResult, for the log. */
const char* PonClaimResultName(PonClaimResult result);

/**
 * Check a claim against the tip and offer it to the pool, cheapest check first. A claim is
 * verified on the receiver's own tip: one made on another tip, or across a change of seed,
 * fails here and its node mints at its own turn. nNow is the system clock.
 */
PonClaimResult AcceptPonClaim(const CPonClaim& claim, const CBlockIndex* pindexTip, int64_t nNow,
                              const Consensus::Params& params, CPonClaimPool& pool);

/**
 * The second of its slot at which a node with a draw of turn nOwnTurn mints, given the turns
 * of the better claims it has heard, best first: each is given PON_VRF_CLAIM_WAIT_SECONDS
 * after its own turn, or after the one before it, to mint.
 */
uint32_t PonVrfMintSecond(uint32_t nOwnTurn, const std::vector<uint32_t>& vBetterTurns);

/** What a node waiting to mint in a slot does next. */
enum class PonMinterStep {
    WAIT,
    MINT,       //!< the time to mint has come
    TIP_MOVED,  //!< the tip drawn on is no longer the tip: the slot is filled, or is drawn again
    STOP,       //!< the minter is stopping: nothing is minted
};

/**
 * The step of a node waiting to mint at nMintTime, at the time nNow. A minter that is stopping
 * mints nothing, whatever the time. A node whose time has come mints even when the tip has
 * moved under it: the caller decides, under cs_main, whether the slot is still open.
 */
PonMinterStep PonVrfMinterStep(int64_t nNow, int64_t nMintTime, bool fTipMoved, bool fStopping);

#endif // BITCOIN_PON_CLAIM_H
