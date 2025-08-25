// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pon-minter.h"
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

void PONMinter(const CChainParams& chainparams)
{
    LogPrintf("PON Minter started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("pon-minter");
    
    // Cache some values
    const int64_t genesisTime = chainparams.GenesisBlock().nTime;
    const Consensus::Params& consensusParams = chainparams.GetConsensus();
    
    // Track last slot we tried to avoid retrying same slot
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
                    MilliSleep(30000); // Check every 30 seconds
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
                    MilliSleep(1000);
                    continue;
                }
                nHeight = chainActive.Height() + 1;
            }
            
            if (!IsPONActive(nHeight)) {
                MilliSleep(10000); // Check every 10 seconds until PON activates
                continue;
            }
            
            // Calculate current slot
            int64_t now = GetAdjustedTime();
            uint32_t currentSlot = GetSlotNumber(now, genesisTime, consensusParams);
            
            // Skip if we already tried this slot
            if (currentSlot <= lastAttemptedSlot) {
                MilliSleep(1000);
                continue;
            }

            // CHeck is slot changes in the next 10 seconds, if it does. lets wait
            uint32_t nextSlotIn10 = GetSlotNumber(now+10, genesisTime, consensusParams);
            // Don't try if we're within 10 seconds of the next slot
            if (currentSlot != nextSlotIn10) {
                lastAttemptedSlot = currentSlot;
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
                MilliSleep(30000);
                continue;
            }
            
            // Check if we're eligible for this slot
            CBlockIndex* pindexPrev;
            {
                LOCK(cs_main);
                pindexPrev = chainActive.Tip();
            }

            uint256 ponHash = GetPONHash(collateral, pindexPrev->GetBlockHash(), currentSlot);
            unsigned int nBits = GetNextPONWorkRequired(pindexPrev);
            if (!CheckProofOfNode(ponHash, nBits, Params().GetConsensus())) {
                LogPrint("pon", "PON: Not eligible for slot %d\n", currentSlot);
                lastAttemptedSlot = currentSlot;
                MilliSleep(1000);
                continue;
            }

            LogPrintf("PON: Eligible for slot %d, creating block...\n", currentSlot);

            CScript scriptPubKey;
            {

                // Try to get the fluxnode payout address
                CTxDestination dest = DecodeDestination(Params().GetDevFundAddress());
                if (!IsValidDestination(dest)) {
                    LogPrintf("PON: Invalid Dev Fund Address\n");
                    lastAttemptedSlot = currentSlot;
                    MilliSleep(5000);
                    continue;
                }

                scriptPubKey = GetScriptForDestination(dest);
                
                if (scriptPubKey.empty()) {
                    LogPrintf("PON: No valid payout script available\n");
                    lastAttemptedSlot = currentSlot;
                    MilliSleep(5000);
                    continue;
                }
            }
            
            // Create the block with enforced slot time
            std::unique_ptr<CBlockTemplate> pblocktemplate(
                CreateNewBlock(chainparams, scriptPubKey, collateral, now)
            );
            
            if (!pblocktemplate) {
                LogPrintf("PON: CreateNewBlock failed\n");
                lastAttemptedSlot = currentSlot;
                MilliSleep(1000);
                continue;
            }
            
            CBlock* pblock = &pblocktemplate->block;
            
            // Sign the block
            if (!SignPONBlock(*pblock, collateral)) {
                LogPrintf("PON: Failed to sign block\n");
                lastAttemptedSlot = currentSlot;
                continue;
            }
            
            // Process the block
            if (ProcessPONBlock(pblock, chainparams)) {
                LogPrintf("PON: Successfully created block at height %d for slot %d\n", 
                         nHeight, currentSlot);
            }
            
            lastAttemptedSlot = currentSlot;
            
            // Wait a bit before checking next slot
            MilliSleep(5000);
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