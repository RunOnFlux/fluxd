// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pon.h"
#include "pon-fork.h"
#include "../arith_uint256.h"
#include "../chain.h"
#include "../chainparams.h"
#include "../fluxnode/fluxnode.h"
#include "../hash.h"
#include "../primitives/block.h"
#include "../streams.h"
#include "../uint256.h"
#include "../util.h"

#include <algorithm>

// Forward declarations to avoid circular dependency with main.h
extern CChain chainActive;

// This must watch the declaration in main.cpp.
bool IsInitialBlockDownload(const CChainParams& chainParams);

bool CheckProofOfNode(const uint256& hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 target;
    
    target.SetCompact(nBits, &fNegative, &fOverflow);

    if (Params().NetworkID() == CBaseChainParams::REGTEST) {
        return true;
    }
    
    // Check range - similar to CheckProofOfWork but using ponLimit
    if (fNegative || target == 0 || fOverflow || target > UintToArith256(params.ponLimit)) {
        return error("CheckProofOfNode(): nBits below minimum work or invalid");
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
    if (nextHeight < ponActivationHeight + lookbackWindow) {
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
    
    // Limit adjustment to prevent large swings (2x max)
    if (actualTimespan < targetTimespan / 2) {
        actualTimespan = targetTimespan / 2;
    }
    if (actualTimespan > targetTimespan * 2) {
        actualTimespan = targetTimespan * 2;
    }
    
    // Calculate new target based on the last block's difficulty
    // (Could average over the window like POW does, but keeping it simple for now)
    arith_uint256 newTarget;
    bool fNegative;
    bool fOverflow;
    newTarget.SetCompact(pindexLast->nBits, &fNegative, &fOverflow);
    
    // Check for invalid compact representation
    if (fNegative || fOverflow || newTarget == 0) {
        LogPrintf("PON: Invalid previous target, using start limit\n");
        return nProofOfNodeStartLimit;
    }
    
    // Adjust the target based on actual vs target timespan
    // newTarget = oldTarget * actualTimespan / targetTimespan
    newTarget = newTarget * actualTimespan / targetTimespan;
    
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

bool CheckPONBlockHeader(const CBlockHeader* pblock, const CBlockIndex* pindexPrev,
                            const Consensus::Params& params)
{
    // 1. Verify this is a PON block
    if (!pblock->IsPON()) {
        return error("CheckPONBlockHeader: Block version %d is not PON", pblock->nVersion);
    }

    if (!CheckProofOfNode(GetPONHash(*pblock), pblock->nBits, Params().GetConsensus())) {
        int64_t genesisTimestamp = Params().GenesisBlock().nTime;
        uint32_t slot = GetSlotNumber(pblock->nTime, genesisTimestamp, Params().GetConsensus());
        return error("CheckPONBlockHeader: stake hash doesn't meet target for slot %d", slot);
    }

    int64_t genesisTimestamp = Params().GenesisBlock().nTime;
    uint32_t slot = GetSlotNumber(pblock->nTime, genesisTimestamp, Params().GetConsensus());
    LogPrint("pon", "CheckPONBlockHeader: Valid PON header for slot %d\n", slot);
    return true;
}

bool ContextualCheckPONBlockHeader(const CBlockHeader* pblock, const CBlockIndex* pindexPrev,
                     const Consensus::Params& params, bool fCheckSignature)
{
    // First do all header validations
    if (!CheckPONBlockHeader(pblock, pindexPrev, params)) {
        return false;
    }
    
    // Now do additional validation that requires chain state
    
    // Special testnet/regtest bypass for development
    bool isTestnet = (Params().NetworkIDString() == "test");
    bool isRegtest = (Params().NetworkIDString() == "regtest");
    
    if (isTestnet || isRegtest) {
        // Allow a special collateral that doesn't need to be a confirmed node
        // This is the hash of "TESTPON" - recognizable but unlikely to collide
        static const uint256 TEST_BYPASS_HASH = uint256S("0x544553544e4f4400000000000000000000000000000000000000000000000000");
        if (pblock->nodesCollateral.hash == TEST_BYPASS_HASH && pblock->nodesCollateral.n == 0) {
            LogPrint("pon", "ContextualCheckPONBlockHeader: Using testnet/regtest bypass for development\n");
            return true;  // Skip signature verification for test collateral
        }
    }
    
    // 1. Verify the signature matches the collateral owner
    if (fCheckSignature) {
        FluxnodeCacheData data = g_fluxnodeCache.GetFluxnodeData(pblock->nodesCollateral);
        if (data.IsNull()) {
            // This is a recent block and we should have the fluxnode data
            return error("ContextualCheckPONBlockHeader: Fluxnode %s not found when signature required for block %s",
                         pblock->nodesCollateral.ToString(), pblock->GetHash().GetHex());
        }
        // Create the message that was signed (block hash)
        uint256 hashToSign = pblock->GetHash();

        // Verify the block signature matches the fluxnode's public key
        if (!data.pubKey.Verify(hashToSign, pblock->vchBlockSig)) {
            return error("ContextualCheckPONBlockHeader: Block signature verification failed for fluxnode %s",
                         pblock->nodesCollateral.ToString());
        }

        LogPrint("pon", "ContextualCheckPONBlockHeader: Signature verified for fluxnode %s\n",
                 pblock->nodesCollateral.ToString());
    }

    LogPrint("pon", "ContextualCheckPONBlockHeader: Full validation passed for block %s\n", pblock->GetHash().GetHex());
    return true;
}