// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PON_H
#define BITCOIN_PON_H

#include "consensus/params.h"
#include "primitives/transaction.h"
#include "uint256.h"
#include "arith_uint256.h"

#include <stdint.h>

class CBlockIndex;
class CBlockHeader;
class CBlock;

// Check is hash meetings target
bool CheckProofOfNode(const uint256& hash, unsigned int nBits, const Consensus::Params& params, int nHeightToCheckWith = 0);

// Calculate the pon hash
uint256 GetPONHash(const CBlockHeader& blockHeader);
uint256 GetPONHash(const COutPoint& collateral, const uint256& prevBlockHash, uint32_t slot);

// Calculate the slot number for a given timestamp relative to genesis
uint32_t GetSlotNumber(int64_t timestamp, int64_t genesisTimestamp, const Consensus::Params& params);

// Get next PON work required (difficulty adjustment)
unsigned int GetNextPONWorkRequired(const CBlockIndex* pindexLast);

// Validate PON block header (using only header data - for headers-first sync)
// This validates:
// 1. Block version indicates PON
// 2. Timestamp aligns with slot
// 3. Stake hash meets difficulty target
bool CheckPONBlockHeader(const CBlockHeader& block, const CBlockIndex* pindexPrev,
                            const Consensus::Params& params);

// Full PON block header validation (requires chain state - for blocks near tip)
// This additionally validates:
// 1. Signature matches collateral owner
// 2. Fluxnode is active in the network
bool ContextualCheckPONBlockHeader(const CBlockHeader& pblock, const CBlockIndex* pindexPrev,
                     const Consensus::Params& params, bool fCheckSignature = true);

// Log PON eligibility for all confirmed fluxnodes at a given slot offset
// This is called automatically after each block connection for monitoring
void LogPONEligibility(const CBlockIndex* pindexPrev, int slotOffset = 1);

// Structure to hold eligible node info
struct EligibleNodeInfo {
    COutPoint collateral;
    uint256 ponHash;

    // Sort by PON hash (ascending - lowest hash has best priority)
    bool operator<(const EligibleNodeInfo& other) const {
        return ponHash < other.ponHash;
    }
};

// Get all eligible nodes for a given slot, sorted by PON hash (best hash first)
std::vector<EligibleNodeInfo> GetEligibleNodes(const CBlockIndex* pindexPrev, uint32_t slot, unsigned int nBits);

// Get the rank of a specific node in the eligible nodes list (1-indexed, 1 = best)
// Returns -1 if node is not in the eligible list
int GetNodeRank(const std::vector<EligibleNodeInfo>& eligibleNodes, const COutPoint& myCollateral);

#endif // BITCOIN_PON_H