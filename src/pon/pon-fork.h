// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PON_FORK_H
#define BITCOIN_PON_FORK_H

#include "consensus/params.h"
#include "primitives/block.h"
#include "pon.h"
#include <stdint.h>

class CBlockIndex;
class CChainParams;
class CValidationState;

// Check if PON is activated at a given height (hard cutoff)
bool IsPONActive(int nHeight);

// Get the next work required based on POW or PON (switches at activation)
unsigned int GetNextWorkRequiredByFork(const CBlockIndex* pindexLast, 
                                       const CBlockHeader* pblock,
                                       const Consensus::Params& params);

// Check if block version indicates PON
inline bool IsPONBlock(const CBlockHeader& block) {
    return block.IsPON();
}

// Check if block version indicates POW
inline bool IsPOWBlock(const CBlockHeader& block) {
    return block.IsPOW();
}

// Get PON activation height
int GetPONActivationHeight();

#endif // BITCOIN_PON_FORK_H