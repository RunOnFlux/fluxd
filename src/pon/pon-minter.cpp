// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pon-minter.h"
#include "../arith_uint256.h"
#include "../miner.h"
#include "pon.h"
#include "pon-fork.h"
#include "../main.h"
#include "../chainparams.h"
#include "../fluxnode/activefluxnode.h"
#include "../fluxnode/fluxnode.h"
#include "../fluxnode/fluxnodecachedb.h"
#include "../key.h"
#include "../wallet/wallet.h"
#include "../util.h"
#include "../utiltime.h"
#include "../validationinterface.h"
#include "../consensus/validation.h"
#include "../key_io.h"

#include <boost/thread.hpp>

static boost::thread* ponMinterThread = nullptr;
static bool fPONMinter = false;

bool SignPONBlock(CBlock& block, const COutPoint& collateral)
{
    CKey key;
    CPubKey pubkey;
    string errorMessage;

    if (!obfuScationSigner.SetKey(strFluxnodePrivKey, errorMessage, key, pubkey)) {
        LogPrintf("PON: No valid fluxnode private key available\n");
        return false;
    }

    // Sign the block hash (which includes all fields except signature)
    uint256 blockHash = block.GetHash();

    if (!key.Sign(blockHash, block.vchBlockSig)) {
        LogPrintf("PON: Failed to sign block hash\n");
        return false;
    }

    LogPrintf("PON: Successfully signed block for slot at height %d\n",
             chainActive.Height() + 1);
    return true;
}

bool ProcessPONBlock(CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("PON: Generated block %s\n", pblock->GetHash().ToString());

    // Check if we're still on the same chain
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash()) {
            LogPrintf("PON: Generated block is stale\n");
            return false;
        }
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash());

    // Process this block
    CValidationState state;
    if (!ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL)) {
        return error("PON: ProcessNewBlock failed: %s", state.GetRejectReason());
    }

    return true;
}

/**
 * PON Minter Main Loop
 *
 * This function continuously monitors for block production opportunities using a rank-based
 * coordination system to minimize orphans and optimize difficulty adjustment.
 *
 * Timing Strategy:
 * - Slots are 30 seconds long (nPonTargetSpacing)
 * - Poll every 1 second to detect new slots quickly
 * - 5-second burst guard prevents stampedes after recent blocks
 * - Rank-based delays (4s intervals): Rank 1=4s, Rank 2=8s, Rank 3=12s, ..., Rank 7=28s
 * - Fresh timestamps calculated after delays for natural distribution
 *
 * Orphan Prevention:
 * - 4-second rank spacing exceeds typical propagation time (2-5s)
 * - Lower-ranked nodes see higher-ranked blocks before attempting
 * - Slot expiration check prevents late block creation
 * - Tip change detection skips if another node mined during wait
 *
 * Example Timeline (Slot starts at T=0):
 * - T+0-1s:   Nodes detect new slot
 * - T+1-5s:   5-second guard (if previous block was recent)
 * - T+4-6s:   Rank 1 creates block
 * - T+6-8s:   Block propagates
 * - T+8s:     Rank 2 checks tip, sees Rank 1's block, skips
 * - Result:   Only Rank 1 produces block, zero orphans
 */
void PONMinter(const CChainParams& chainparams)
{
    LogPrintf("PON Minter started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("pon-minter");

    // Cache genesis time and consensus parameters for slot calculations
    const int64_t genesisTime = chainparams.GenesisBlock().nTime;
    const Consensus::Params& consensusParams = chainparams.GetConsensus();

    // Track last slot we attempted to avoid retrying the same slot
    uint32_t lastAttemptedSlot = 0;

    try {
        while (fPONMinter) {
            boost::this_thread::interruption_point();

            if (chainparams.MiningRequiresPeers()) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                do {
                    bool fvNodesEmpty;
                    {
                        LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty();
                    }
                    if (!fvNodesEmpty && !IsInitialBlockDownload(chainparams))
                        break;
                    MilliSleep(30000);
                } while (true);
            }

            // Check if we're an active fluxnode (on mainnet)
            bool isMainnet = (chainparams.NetworkIDString() == "main");

            if (!g_fluxnodeCache.CheckIfConfirmed(activeFluxnode.deterministicOutPoint)) {
                // For testnet/regtest, allow bypass mode
                if (isMainnet) {
                    MilliSleep(10000);
                    continue;
                }
                // Continue with bypass mode for testnet/regtest
                LogPrint("pon", "PON: Running in testnet/regtest bypass mode\n");
            }

            // Check if PON is active
            int nHeight;
            {
                LOCK(cs_main);
                if (!chainActive.Tip()) {
                    MilliSleep(getrand(30000,60000));
                    continue;
                }
                nHeight = chainActive.Height() + 1;
            }

            if (!IsPONActive(nHeight)) {
                MilliSleep(getrand(10000,30000)); // Check every 10-30 seconds until PON activates
                continue;
            }

            // Calculate current slot using system time
            // Using GetTime() instead of GetAdjustedTime() helps nodes agree on slot number
            // GetAdjustedTime can vary between nodes based on different peer time offsets
            int64_t now = GetTime();
            uint32_t currentSlot = GetSlotNumber(now, genesisTime, consensusParams);

            // Skip if we already tried this slot
            if (currentSlot <= lastAttemptedSlot) {
                MilliSleep(1000); // Check every 1 second for better coordination
                continue;
            }

            // Get our collateral
            COutPoint collateral = activeFluxnode.deterministicOutPoint;

            if (collateral.IsNull() && !isMainnet) {
                // Use test bypass collateral
                collateral.hash = uint256S("0x544553544e4f4400000000000000000000000000000000000000000000000000");
                collateral.n = 0;
                LogPrintf("PON: Using testnet/regtest bypass collateral for development\n");
            } else if (collateral.IsNull()) {
                LogPrintf("PON: No valid collateral available\n");
                MilliSleep(10000);
                continue;
            }

            // Check if we're eligible for this slot
            CBlockIndex* pindexPrev;
            {
                LOCK(cs_main);
                pindexPrev = chainActive.Tip();
            }

            // Don't mint if last block is very recent (< 5 seconds old)
            // This covers block propagation time without artificially slowing difficulty adjustments
            // The rank-based system provides the main coordination
            int64_t timeSinceLastBlock = now - pindexPrev->nTime;
            if (timeSinceLastBlock < 5) {
                MilliSleep(1000);
                continue;
            }

            // Get current difficulty target for this block height
            unsigned int nBits = GetNextPONWorkRequired(pindexPrev);

            // Calculate eligibility and rank for all nodes in this slot
            // Each node computes: Hash(collateral, prevBlockHash, slotNumber)
            // If hash < difficulty target, the node is eligible
            // All eligible nodes are then ranked by hash value (lowest = best = Rank 1)
            //
            // IMPORTANT: This ranking is for COORDINATION only, NOT consensus!
            // - Consensus accepts the first valid block received (based on chain work)
            // - Ranking simply helps nodes agree on who should try first
            // - Lower-ranked nodes wait longer, see higher-ranked blocks, and skip
            // - This dramatically reduces orphan blocks and network waste
            std::vector<EligibleNodeInfo> eligibleNodes = GetEligibleNodes(pindexPrev, currentSlot, nBits);

            // Find our rank in the eligible list
            int myRank = GetNodeRank(eligibleNodes, collateral);

            if (myRank == -1) {
                // Not eligible for this slot
                arith_uint256 target;
                target.SetCompact(nBits);
                uint256 ponHash = GetPONHash(collateral, pindexPrev->GetBlockHash(), currentSlot);
                LogPrint("pon", "PON: Not eligible for slot %d - hash=%s target=%s (nBits=%08x)\n",
                         currentSlot, ponHash.GetHex(), target.GetHex(), nBits);
                lastAttemptedSlot = currentSlot;
                continue;
            }

            // Log eligibility with rank information
            int totalEligible = eligibleNodes.size();
            uint256 myHash = eligibleNodes[myRank - 1].ponHash;
            LogPrintf("PON: Eligible for slot %d - Rank %d of %d eligible nodes (hash: %s)\n",
                     currentSlot, myRank, totalEligible, myHash.GetHex());

            // Rank-based delay to coordinate block production across 30-second slot window
            // Account for block propagation time (typically 2-5 seconds)
            // Rank 1 waits 4s to allow any late blocks from previous slot to propagate
            // Each subsequent rank waits 4 more seconds, giving time for higher-ranked blocks to propagate
            // Example: Rank 1 = 4s, Rank 2 = 8s, Rank 3 = 12s, Rank 4 = 16s, Rank 5 = 20s, Rank 6 = 24s, Rank 7 = 28s
            // With 4s intervals, we fit 7 ranks in a 30s slot window
            int rankDelayMs = myRank * 4000; // 4 second intervals

            LogPrintf("PON: Rank %d of %d eligible - waiting %dms (%.1fs) before minting\n",
                     myRank, totalEligible, rankDelayMs, rankDelayMs / 1000.0);
            MilliSleep(rankDelayMs);

            // Get fresh timestamp after rank delay completes
            // This ensures block timestamps reflect when they were actually created,
            // not when the slot started, giving natural distribution across the slot window
            int64_t nowAfterWait = GetTime();

            // Perform safety checks before block creation:
            // 1. Verify we haven't moved to the next slot during our wait
            // 2. Check if another node already produced a block while we waited
            {
                LOCK(cs_main);

                // Check if we're still in the same slot
                uint32_t slotAfterWait = GetSlotNumber(nowAfterWait, genesisTime, consensusParams);

                if (slotAfterWait != currentSlot) {
                    LogPrintf("PON: Slot %d expired during wait (now in slot %d), skipping\n",
                             currentSlot, slotAfterWait);
                    lastAttemptedSlot = currentSlot;
                    continue;
                }

                CBlockIndex* pNewTip = chainActive.Tip();
                if (pNewTip->GetBlockHash() != pindexPrev->GetBlockHash()) {
                    LogPrintf("PON: Slot %d already filled by another node during wait (likely rank %d or better), skipping\n",
                             currentSlot, myRank - 1);
                    lastAttemptedSlot = currentSlot;
                    continue;
                }
                // Update pindexPrev to latest tip
                pindexPrev = pNewTip;
            }

            // Setup block reward payout script
            CScript scriptPubKey;
            {
                // Get the dev fund address for block rewards
                CTxDestination dest = DecodeDestination(Params().GetDevFundAddress());
                if (!IsValidDestination(dest)) {
                    LogPrintf("PON: Invalid Dev Fund Address\n");
                    lastAttemptedSlot = currentSlot;
                    continue;
                }

                scriptPubKey = GetScriptForDestination(dest);

                if (scriptPubKey.empty()) {
                    LogPrintf("PON: No valid payout script available\n");
                    lastAttemptedSlot = currentSlot;
                    continue;
                }
            }

            // Create the block template
            // Uses fresh timestamp (nowAfterWait) calculated after rank delay, giving each
            // rank a naturally distributed timestamp within the slot window
            // (Rank 1 ~T+4s, Rank 2 ~T+8s, Rank 3 ~T+12s, etc.)
            std::unique_ptr<CBlockTemplate> pblocktemplate(
                CreateNewBlock(chainparams, scriptPubKey, false, collateral, nowAfterWait)
            );

            if (!pblocktemplate) {
                LogPrintf("PON: CreateNewBlock failed\n");
                lastAttemptedSlot = currentSlot;
                continue;
            }

            CBlock* pblock = &pblocktemplate->block;

            // Sign the block with our fluxnode private key
            // Block signature proves we control the collateral used for PON eligibility
            if (!SignPONBlock(*pblock, collateral)) {
                LogPrintf("PON: Failed to sign block\n");
                lastAttemptedSlot = currentSlot;
                continue;
            }

            // Submit the block to the network
            // This validates and adds the block to our chain, then broadcasts to peers
            if (ProcessPONBlock(pblock, chainparams)) {
                LogPrintf("PON: Successfully created block at height %d for slot %d\n",
                         nHeight, currentSlot);
            }

            // Mark this slot as attempted (success or failure) to avoid retrying
            lastAttemptedSlot = currentSlot;
        }
    }
    catch (const boost::thread_interrupted&) {
        LogPrintf("PON Minter terminated\n");
        throw;
    }
    catch (const std::runtime_error &e) {
        LogPrintf("PON Minter runtime error: %s\n", e.what());
        return;
    }
}

void StartPONMinter(const CChainParams& chainparams)
{
    if (ponMinterThread != nullptr) {
        return; // Already running
    }
    
    fPONMinter = true;
    ponMinterThread = new boost::thread(boost::bind(&PONMinter, boost::cref(chainparams)));
    LogPrintf("PON Minter thread started\n");
}

void StopPONMinter()
{
    if (ponMinterThread == nullptr) {
        return; // Not running
    }
    
    LogPrintf("Stopping PON Minter...\n");
    fPONMinter = false;
    
    ponMinterThread->interrupt();
    ponMinterThread->join();
    delete ponMinterThread;
    ponMinterThread = nullptr;
    
    LogPrintf("PON Minter stopped\n");
}

bool IsPONMinterRunning()
{
    return ponMinterThread != nullptr && fPONMinter;
}