// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pon-claim.h"

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

uint32_t PonVrfMintSecond(uint32_t nOwnTurn, const std::vector<uint32_t>& vBetterTurns)
{
    uint32_t nDue = 0;
    for (uint32_t nTurn : vBetterTurns) {
        nDue = std::max(nTurn, nDue) + PON_VRF_CLAIM_WAIT_SECONDS;
    }
    return std::max(nOwnTurn, nDue);
}
