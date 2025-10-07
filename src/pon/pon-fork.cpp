// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pon-fork.h"
#include "../chain.h"
#include "../chainparams.h"
#include "../consensus/validation.h"
#include "../pow.h"
#include "../util.h"
#include "../main.h"

bool IsPONActive(int nHeight)
{
    int ponActivationHeight = GetPONActivationHeight();
    
    // PON is active if we're at or past the activation height
    // and activation height is set (not NO_ACTIVATION_HEIGHT)
    return nHeight >= ponActivationHeight;
}

unsigned int GetNextWorkRequiredByFork(const CBlockIndex* pindexLast,
                                       const CBlockHeader* pblock,
                                       const Consensus::Params& params)
{
    if (!pindexLast) {
        // Genesis block
        return UintToArith256(params.powLimit).GetCompact();
    }
    
    int nHeight = pindexLast->nHeight + 1;
    
    if (IsPONActive(nHeight)) {
        // Use PON difficulty adjustment
        LogPrintf("GetNextWorkRequiredByFork: Using PON difficulty for height %d\n", nHeight);
        return GetNextPONWorkRequired(pindexLast);
    } else {
        // Use POW difficulty adjustment
        LogPrintf("GetNextWorkRequiredByFork: Using POW difficulty for height %d\n", nHeight);
        return GetNextWorkRequired(pindexLast, pblock, params);
    }
}

// Get PON activation height
int GetPONActivationHeight() {
    return Params().GetConsensus().vUpgrades[Consensus::UPGRADE_PON].nActivationHeight;
}