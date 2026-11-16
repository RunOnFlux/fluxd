// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pon-claim.h"

#include "pon.h"
#include "pon-fork.h"
#include "../chain.h"
#include "../chainparams.h"
#include "../crypto/ecvrf.h"
#include "../fluxnode/fluxnode.h"
#include "../pubkey.h"

#include <algorithm>

CPonClaimPool g_ponClaims;

bool CPonClaimPool::Add(uint32_t slot, const COutPoint& collateral, const arith_uint256& output)
{
    LOCK(cs);
    SlotClaims& claims = mapSlots[slot];
    for (const auto& claim : claims) {
        if (claim.second == collateral) return false;
    }
    if (claims.size() >= PON_VRF_CLAIMS_KEPT) {
        const auto worst = std::prev(claims.end());
        if (!(std::make_pair(output, collateral) < *worst)) return false;
        claims.erase(worst);
    }
    claims.insert(std::make_pair(output, collateral));
    return true;
}

bool CPonClaimPool::Have(uint32_t slot, const COutPoint& collateral) const
{
    LOCK(cs);
    const auto it = mapSlots.find(slot);
    if (it == mapSlots.end()) return false;
    for (const auto& claim : it->second) {
        if (claim.second == collateral) return true;
    }
    return false;
}

std::vector<arith_uint256> CPonClaimPool::BetterThan(uint32_t slot, const arith_uint256& output) const
{
    LOCK(cs);
    std::vector<arith_uint256> better;
    const auto it = mapSlots.find(slot);
    if (it == mapSlots.end()) return better;
    for (const auto& claim : it->second) {
        if (!(claim.first < output)) break;
        better.push_back(claim.first);
    }
    return better;
}

void CPonClaimPool::Forget(uint32_t slotCurrent)
{
    LOCK(cs);
    mapSlots.erase(mapSlots.begin(), mapSlots.lower_bound(slotCurrent));
}

const char* PonClaimResultName(PonClaimResult result)
{
    switch (result) {
    case PonClaimResult::KEPT:            return "kept";
    case PonClaimResult::BAD_PROOF_SIZE:  return "bad proof size";
    case PonClaimResult::WRONG_SLOT:      return "wrong slot";
    case PonClaimResult::HELD:            return "held already";
    case PonClaimResult::NOT_ACTIVE:      return "not active";
    case PonClaimResult::UNCONFIRMED:     return "unconfirmed";
    case PonClaimResult::BAD_PROOF:       return "bad proof";
    case PonClaimResult::NOT_ELIGIBLE:    return "not eligible";
    case PonClaimResult::NOT_AMONG_BEST:  return "not among the best";
    }
    return "unknown";
}

PonClaimResult AcceptPonClaim(const CPonClaim& claim, const CBlockIndex* pindexTip, int64_t nNow,
                              const Consensus::Params& params, CPonClaimPool& pool)
{
    if (claim.proof.size() != 81) {
        return PonClaimResult::BAD_PROOF_SIZE;
    }

    const uint32_t slotNow = GetSlotNumber(nNow, Params().GenesisBlock().nTime, params);
    const bool fNextSlotIsNear = GetPonSlotStart(slotNow + 1, params) - nNow <= PON_VRF_MAX_AHEAD_SECONDS;
    if (claim.slot != slotNow && !(claim.slot == slotNow + 1 && fNextSlotIsNear)) {
        return PonClaimResult::WRONG_SLOT;
    }

    if (pool.Have(claim.slot, claim.collateral)) {
        return PonClaimResult::HELD;
    }

    if (!pindexTip || !IsPONVRFActive(pindexTip->nHeight + 1)) {
        return PonClaimResult::NOT_ACTIVE;
    }

    CPubKey pubKey;
    {
        LOCK(g_fluxnodeCache.cs);
        const auto it = g_fluxnodeCache.mapConfirmedFluxnodeData.find(claim.collateral);
        if (it == g_fluxnodeCache.mapConfirmedFluxnodeData.end()) {
            return PonClaimResult::UNCONFIRMED;
        }
        pubKey = it->second.pubKey;
    }

    const uint256 seed = GetPonVrfMessage(pindexTip, claim.slot, claim.collateral, params);
    uint256 output;
    if (!ECVRF_Verify(pubKey, seed, claim.proof, output) || output != claim.output) {
        return PonClaimResult::BAD_PROOF;
    }

    const unsigned int nBits = GetPonVrfNextBits(pindexTip, GetPonSlotStart(claim.slot, params), params);
    if (!CheckPonVrfDraw(claim.output, nBits)) {
        return PonClaimResult::NOT_ELIGIBLE;
    }

    return pool.Add(claim.slot, claim.collateral, UintToArith256(claim.output))
               ? PonClaimResult::KEPT
               : PonClaimResult::NOT_AMONG_BEST;
}

uint32_t PonVrfMintSecond(uint32_t nOwnTurn, const std::vector<uint32_t>& vBetterTurns)
{
    uint32_t nDue = 0;
    for (uint32_t nTurn : vBetterTurns) {
        nDue = std::max(nTurn, nDue) + PON_VRF_CLAIM_WAIT_SECONDS;
    }
    return std::max(nOwnTurn, nDue);
}
