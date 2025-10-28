// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pon.h"
#include "pon-fork.h"
#include "../arith_uint256.h"
#include "../chain.h"
#include "../chainparams.h"
#include "../emergencyblock.h"
#include "../fluxnode/fluxnode.h"
#include "../hash.h"
#include "../primitives/block.h"
#include "../streams.h"
#include "../uint256.h"
#include "../util.h"

#include <algorithm>

// Forward declarations to avoid circular dependency with main.h
extern CChain chainActive;

// This must match the declaration in main.cpp.
bool IsInitialBlockDownload(const CChainParams& chainParams);

bool CheckProofOfNode(const uint256& hash, unsigned int nBits, const Consensus::Params& params, int nHeightToCheckWith)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 target;
    
    target.SetCompact(nBits, &fNegative, &fOverflow);

    if (Params().NetworkID() == CBaseChainParams::REGTEST) {
        return true;
    }

    arith_uint256 maximumTargetAllowed;
    if (nHeightToCheckWith) {
        if (nHeightToCheckWith >= params.vUpgrades[Consensus::UPGRADE_PON].nActivationHeight + params.nPonDifficultyWindow) {
            maximumTargetAllowed = UintToArith256(params.ponLimit);
        } else {
            maximumTargetAllowed = UintToArith256(params.ponStartLimit);
        }
    } else {
        maximumTargetAllowed = UintToArith256(params.ponLimit) < UintToArith256(params.ponStartLimit) ? UintToArith256(params.ponStartLimit) : UintToArith256(params.ponLimit);
    }

    // Check range - similar to CheckProofOfWork but using ponLimit
    if (fNegative || target == 0 || fOverflow || target > maximumTargetAllowed) {
        return error("CheckProofOfNode(): nBits below minimum work (work is too easy) or invalid");
    }

    // Convert hash to arith_uint256 for comparison
    arith_uint256 hashValue = UintToArith256(hash);

    // Check if the hash meets the target difficulty
    // Lower hash values mean higher difficulty met
    return hashValue <= target;
}


uint256 GetPONHash(const CBlockHeader& blockHeader)
{
    int64_t genesisTimestamp = Params().GenesisBlock().nTime;
    uint32_t slot = GetSlotNumber(blockHeader.nTime, genesisTimestamp, Params().GetConsensus());
    return GetPONHash(blockHeader.nodesCollateral, blockHeader.hashPrevBlock, slot);
}

uint256 GetPONHash(const COutPoint& collateral, const uint256& prevBlockHash, uint32_t slot)
{
    // Create a deterministic hash from the three inputs
    // This ensures that the same fluxnode will always get the same hash for the same slot
    CHashWriter ss(SER_GETHASH, 0);

    // Add collateral outpoint (txid + vout index)
    ss << collateral;

    // Add previous block hash for unpredictability
    ss << prevBlockHash;

    // Add slot number to ensure different hash for each slot
    ss << slot;

    return ss.GetHash();
}

uint32_t GetSlotNumber(int64_t timestamp, int64_t genesisTimestamp, const Consensus::Params& params)
{
    // Calculate slot number based on time elapsed since genesis
    int64_t timeSinceGenesis = timestamp - genesisTimestamp;
    return static_cast<uint32_t>(timeSinceGenesis / params.nPonTargetSpacing);
}

unsigned int GetNextPONWorkRequired(const CBlockIndex* pindexLast)
{
    const Consensus::Params& params = Params().GetConsensus();
    const arith_uint256 ponLimit = UintToArith256(params.ponLimit);
    const arith_uint256 ponStartLimit = UintToArith256(params.ponStartLimit);

    unsigned int nProofOfNodeLimit = ponLimit.GetCompact();
    unsigned int nProofOfNodeStartLimit = ponStartLimit.GetCompact();

    // Genesis block or nullptr
    if (pindexLast == nullptr) {
        return nProofOfNodeStartLimit;
    }

    int ponActivationHeight = GetPONActivationHeight();
    int nextHeight = pindexLast->nHeight + 1;
    int lookbackWindow = params.nPonDifficultyWindow;

    // Before PON activation, use existing difficulty
    if (nextHeight < ponActivationHeight) {
        return pindexLast->nBits;
    }

    // For the first few blocks after PON activation, use start limit
    // Need at least lookbackWindow blocks to calculate difficulty
    if (nextHeight < (ponActivationHeight + lookbackWindow)) {
        return nProofOfNodeStartLimit;
    }

    // Now adjust difficulty every block based on the lookback window
    // Find the first block in the lookback window
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < lookbackWindow - 1; i++) {
        pindexFirst = pindexFirst->pprev;
        if (!pindexFirst || pindexFirst->nHeight < ponActivationHeight) {
            // Not enough PON blocks yet, shouldn't happen due to check above
            return nProofOfNodeStartLimit;
        }
    }

    // Calculate actual timespan over the window
    int64_t actualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    // Target timespan = (window - 1) * target spacing (because we're measuring intervals)
    int64_t targetTimespan = (lookbackWindow - 1) * params.nPonTargetSpacing;

    LogPrintf("PON: Adjustment at height %d: first=%d, last=%d, actualTimespan=%d, targetTimespan=%d\n",
              nextHeight, pindexFirst->nHeight, pindexLast->nHeight, actualTimespan, targetTimespan);

    // Sanity check
    if (targetTimespan <= 0) {
        LogPrintf("PON: Invalid target timespan %d\n", targetTimespan);
        return nProofOfNodeLimit;
    }

    // Limit adjustment to prevent large swings (1.25x max)
    // 4/5 = 0.8 for harder difficulty (blocks too fast)
    // 5/4 = 1.25 for easier difficulty (blocks too slow)
    if (actualTimespan < targetTimespan * 4 / 5) {
        actualTimespan = targetTimespan * 4 / 5;
    }
    if (actualTimespan > targetTimespan * 5 / 4) {
        actualTimespan = targetTimespan * 5 / 4;
    }

    // Calculate new target based on the last block's difficulty
    // Use Digishield-style calculation to avoid overflow
    arith_uint256 newTarget;
    bool fNegative;
    bool fOverflow;
    newTarget.SetCompact(pindexLast->nBits, &fNegative, &fOverflow);

    // Check for invalid compact representation
    if (fNegative || fOverflow || newTarget == 0) {
        LogPrintf("PON: Invalid previous target, using ponLimit\n");
        return nProofOfNodeLimit;
    }

    // Adjust the target based on actual vs target timespan
    // Use Digishield approach: divide first, then multiply to avoid overflow
    // newTarget = oldTarget * actualTimespan / targetTimespan
    newTarget /= targetTimespan;
    newTarget *= actualTimespan;

    // Don't allow target to exceed maximum (easiest difficulty)
    if (newTarget > ponLimit) {
        newTarget = ponLimit;
    }

    // Ensure target is not zero (would cause CheckProofOfNode to reject the block)
    // This should never happen since actualTimespan is clamped to targetTimespan/2 minimum
    if (newTarget == 0) {
        LogPrintf("PON: ERROR - calculated target was 0, using ponLimit as failsafe\n");
        newTarget = ponLimit;  // Use easiest difficulty as failsafe
    }

    LogPrintf("PON difficulty adjustment: height=%d, actualTimespan=%d, targetTimespan=%d, before=%08x, after=%08x\n",
              pindexLast->nHeight + 1, actualTimespan, targetTimespan,
              pindexLast->nBits, newTarget.GetCompact());

    return newTarget.GetCompact();
}

bool CheckPONBlockHeader(const CBlockHeader& block, const CBlockIndex* pindexPrev,
                            const Consensus::Params& params)
{
    // 1. Verify this is a PON block
    if (!block.IsPON()) {
        return error("CheckPONBlockHeader: Block version %d is not PON", block.nVersion);
    }

    if (IsEmergencyBlock(block)) {
        return true;
    }

    int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;

    if (!CheckProofOfNode(GetPONHash(block), block.nBits, Params().GetConsensus(), nHeight)) {
        int64_t genesisTimestamp = Params().GenesisBlock().nTime;
        uint32_t slot = GetSlotNumber(block.nTime, genesisTimestamp, Params().GetConsensus());
        return error("CheckPONBlockHeader: stake hash doesn't meet target for slot %d", slot);
    }

    int64_t genesisTimestamp = Params().GenesisBlock().nTime;
    uint32_t slot = GetSlotNumber(block.nTime, genesisTimestamp, Params().GetConsensus());
    LogPrint("pon", "CheckPONBlockHeader: Valid PON header for slot %d\n", slot);
    return true;
}

bool ContextualCheckPONBlockHeader(const CBlockHeader& block, const CBlockIndex* pindexPrev,
                     const Consensus::Params& params, bool fCheckSignature)
{
    // First do all header validations
    if (!CheckPONBlockHeader(block, pindexPrev, params)) {
        return false;
    }

    // Now do additional validation that requires chain state

    // Check if this is an emergency block first
    if (IsEmergencyBlock(block)) {
        if (!ValidateEmergencyBlockSignatures(block)) {
            return error("ContextualCheckPONBlockHeader: Emergency block signature validation failed");
        }

        // Check if emergency blocks are allowed at this height/time
        int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
        if (!IsEmergencyBlockAllowed(nHeight, block.nTime)) {
            return error("ContextualCheckPONBlockHeader: Emergency block not allowed at height %d, time %d",
                        nHeight, block.nTime);
        }

        LogPrint("pon", "ContextualCheckPONBlockHeader: Emergency block validated successfully\n");
        return true;
    }

    // Special testnet/regtest collateral for PON for development
    bool isTestnet = (Params().NetworkIDString() == "test");
    bool isRegtest = (Params().NetworkIDString() == "regtest");

    if (isTestnet || isRegtest) {
        // Allow a special collateral that doesn't need to be a confirmed node
        // This is the hash of "TESTPON" - recognizable but unlikely to collide
        static const uint256 TEST_BYPASS_HASH = uint256S("0x544553544e4f4400000000000000000000000000000000000000000000000000");
        if (block.nodesCollateral.hash == TEST_BYPASS_HASH && block.nodesCollateral.n == 0) {
            LogPrint("pon", "ContextualCheckPONBlockHeader: Using testnet/regtest bypass for development\n");
            return true;  // Skip signature verification for test collateral
        }
    }

    // 1. Verify the signature matches the collateral owner
    if (fCheckSignature) {
        FluxnodeCacheData data = g_fluxnodeCache.GetFluxnodeData(block.nodesCollateral);

        if (data.IsNull()) {
            // Try to refresh cache if we're validating a recent block
            int currentHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
            bool isRecentBlock = (chainActive.Height() - currentHeight) < 10;

            if (isRecentBlock) {
                LogPrint("pon", "FluxNode not found in cache, attempting refresh for %s (height=%d)\n",
                        block.nodesCollateral.ToString(), currentHeight);

                // Small delay to allow cache sync
                MilliSleep(100);

                // Retry cache lookup
                data = g_fluxnodeCache.GetFluxnodeData(block.nodesCollateral);
            }

            if (data.IsNull()) {
                return error("ContextualCheckPONBlockHeader: FluxNode %s not found in cache for block %s (height=%d, recent=%s)",
                            block.nodesCollateral.ToString(), block.GetHash().GetHex(),
                            currentHeight, isRecentBlock ? "yes" : "no");
            }
        }

        // Create the message that was signed (block hash)
        uint256 hashToSign = block.GetHash();

        // Verify the block signature matches the fluxnode's public key
        if (!data.pubKey.Verify(hashToSign, block.vchBlockSig)) {
            return error("ContextualCheckPONBlockHeader: Block signature verification failed for fluxnode %s (block=%s, pubkey=%s)",
                        block.nodesCollateral.ToString(), block.GetHash().GetHex(),
                        HexStr(data.pubKey.begin(), data.pubKey.end()));
        }

        LogPrint("pon", "ContextualCheckPONBlockHeader: Signature verified for fluxnode %s (tier=%d)\n",
             block.nodesCollateral.ToString(), data.nTier);
    }

    LogPrint("pon", "ContextualCheckPONBlockHeader: Full validation passed for block %s\n", block.GetHash().GetHex());
    return true;
}

void LogPONEligibility(const CBlockIndex* pindexPrev, int slotOffset)
{
    // Check if PON is active
    int ponActivationHeight = GetPONActivationHeight();
    if (!pindexPrev || pindexPrev->nHeight < ponActivationHeight) {
        return; // PON not active yet
    }

    // Start timing
    int64_t nTimeStart = GetTimeMicros();

    const Consensus::Params& consensusParams = Params().GetConsensus();
    int64_t genesisTime = Params().GenesisBlock().nTime;

    // Calculate current slot
    int64_t currentTime = GetAdjustedTime();
    uint32_t currentSlot = GetSlotNumber(currentTime, genesisTime, consensusParams);

    // Get the difficulty for the next block
    unsigned int nBits = GetNextPONWorkRequired(pindexPrev);

    // Get the previous block hash (which will be used for PON hash calculation)
    uint256 prevBlockHash = pindexPrev->GetBlockHash();

    LOCK(g_fluxnodeCache.cs);
    int totalNodes = g_fluxnodeCache.mapConfirmedFluxnodeData.size();

    // Keep checking slots until we find one with eligible nodes (max 100 slots ahead)
    int maxSlotsToCheck = 100;
    for (int offset = slotOffset; offset <= maxSlotsToCheck; offset++) {
        uint32_t checkedSlot = currentSlot + offset;
        int eligibleNodes = 0;

        // Iterate through all confirmed fluxnodes
        for (const auto& pair : g_fluxnodeCache.mapConfirmedFluxnodeData) {
            const COutPoint& collateral = pair.first;

            // Calculate PON hash for this node at the checked slot
            uint256 ponHash = GetPONHash(collateral, prevBlockHash, checkedSlot);

            // Check if this hash meets the difficulty requirement
            if (CheckProofOfNode(ponHash, nBits, consensusParams, pindexPrev->nHeight + 1)) {
                eligibleNodes++;

                // Log each eligible node (use full collateral: txhash:index)
                LogPrint("pon", "PON Eligibility: Node %s:%d eligible for slot %d (hash: %s)\n",
                         collateral.hash.ToString().c_str(), collateral.n, checkedSlot, ponHash.ToString().c_str());
            }
        }

        // Calculate timing
        int64_t nTimeEnd = GetTimeMicros();
        double nTimeElapsed = (nTimeEnd - nTimeStart) * 0.001; // Convert to milliseconds

        // Calculate eligibility rate
        double eligibilityRate = (totalNodes > 0) ? (100.0 * eligibleNodes / totalNodes) : 0.0;

        // Log summary with timing (only when -debug=pon is enabled)
        LogPrint("pon", "PON Eligibility Check: Block %d, Slot %d - %d of %d nodes eligible (%.2f%%), difficulty=%08x, time=%.2fms\n",
                 pindexPrev->nHeight + 1, checkedSlot, eligibleNodes, totalNodes, eligibilityRate, nBits, nTimeElapsed);

        // If we found eligible nodes, stop checking
        if (eligibleNodes > 0) {
            break;
        }

        // If no nodes eligible, continue to next slot
        LogPrint("pon", "PON Eligibility: No eligible nodes for slot %d, checking next slot...\n", checkedSlot);
    }
}

std::vector<EligibleNodeInfo> GetEligibleNodes(const CBlockIndex* pindexPrev, uint32_t slot, unsigned int nBits)
{
    std::vector<EligibleNodeInfo> eligibleNodes;

    if (!pindexPrev) {
        return eligibleNodes;
    }

    const Consensus::Params& consensusParams = Params().GetConsensus();
    uint256 prevBlockHash = pindexPrev->GetBlockHash();

    LOCK(g_fluxnodeCache.cs);

    // Check all confirmed fluxnodes
    for (const auto& pair : g_fluxnodeCache.mapConfirmedFluxnodeData) {
        const COutPoint& collateral = pair.first;

        // Calculate PON hash for this node at the slot
        uint256 ponHash = GetPONHash(collateral, prevBlockHash, slot);

        // Check if this hash meets the difficulty requirement
        if (CheckProofOfNode(ponHash, nBits, consensusParams, pindexPrev->nHeight + 1)) {
            EligibleNodeInfo info;
            info.collateral = collateral;
            info.ponHash = ponHash;
            eligibleNodes.push_back(info);
        }
    }

    // Sort by PON hash (lowest hash first = best priority)
    std::sort(eligibleNodes.begin(), eligibleNodes.end());

    return eligibleNodes;
}

int GetNodeRank(const std::vector<EligibleNodeInfo>& eligibleNodes, const COutPoint& myCollateral)
{
    for (size_t i = 0; i < eligibleNodes.size(); i++) {
        if (eligibleNodes[i].collateral == myCollateral) {
            return i + 1; // Rank is 1-indexed (1 = best)
        }
    }
    return -1; // Not found in eligible list
}