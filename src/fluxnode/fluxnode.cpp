// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <undo.h>
#include <utilmoneystr.h>
#include "fluxnode/fluxnode.h"
#include "addrman.h"
#include "fluxnode/obfuscation.h"
#include "sync.h"
#include "util.h"
#include "key_io.h"
#include "fluxnode/activefluxnode.h"
#include "fluxnode/fluxnodecachedb.h"
#include "primitives/transaction.h"
#include "pon/pon-fork.h"

FluxnodeCache g_fluxnodeCache;

// Keep track of the active Fluxnode
ActiveFluxnode activeFluxnode;

COutPoint fluxnodeOutPoint;

std::string TierToString(int tier)
{
    std::string strStatus = "NONE";

    if (tier == CUMULUS) strStatus = "CUMULUS";
    if (tier == NIMBUS) strStatus = "NIMBUS";
    if (tier == STRATUS) strStatus = "STRATUS";

    if (strStatus == "NONE" && tier != 0) strStatus = "UNKNOWN TIER (" + std::to_string(tier) + ")";

    return strStatus;
}

bool IsMigrationCollateralAmount(const CAmount& amount)
{
    return amount == V2_FLUXNODE_COLLAT_CUMULUS * COIN || amount == V2_FLUXNODE_COLLAT_NIMBUS * COIN || amount == V2_FLUXNODE_COLLAT_STRATUS * COIN;
}

bool CheckFluxnodeTxSignatures(const CTransaction&  transaction)
{
    if (transaction.nType == FLUXNODE_START_TX_TYPE) {
        // We need to sign the mutable transaction

        std::string errorMessage;
        std::string strMessage = transaction.GetHash().GetHex();

        bool fAllowDelegatesToSign = false;
        if (transaction.IsSigningAsDelegate()) {
            fAllowDelegatesToSign = true;
        }

        // Double check permissions on update delegates. Signature will fail, causing tx to fail.
        if (transaction.IsUpdatingDelegate()) {
            fAllowDelegatesToSign = false;
        }

        if (fAllowDelegatesToSign) {
            // Checking if delegates signed this start transaction
            CFluxnodeDelegates storedDelegates;

            // Using existing delegates - check if signer is authorized (cache-aware)
            if (g_fluxnodeCache.GetDelegates(transaction.collateralIn, storedDelegates)) {
                for (const auto& delegateKey : storedDelegates.delegateStartingKeys) {
                    if (obfuScationSigner.VerifyMessage(delegateKey, transaction.sig, strMessage, errorMessage)) {
                        return true;
                    }
                }
            }
            // If fIsVerifying we are verifying from the database, meaning we might not have the delegate data
            // Assume if we saved a transaction to the database this was already verified
            if (!fIsVerifying) {
                return error("fluxnode-tx-signing-as-delegate-failed-to-verify");
            }
        }

        /**
         * P2SH NODES CORE CHECK 3
         * We must verify the signature of the transaction.
         * This check along with Check 1 & 2 will allow us to know that the signature was signed by a key that is
         * a part of th redeemscript
         * Check 1 & 2 are preformed in the ContextualCheckTransaction function
         */
        if (transaction.IsFluxnodeUpgradedP2SHTx()) {
            // We need to loop through all pubkeys and see if they verify the message.

            vector<CPubKey> pubkeys;
            if (!ListPubKeysFromMultiSigScript(transaction.P2SHRedeemScript, pubkeys)) {
                return error("fluxnode-tx-p2shnodes-listpubkeys-failed-to-list-keys");
            }

            for (const auto& pubkey: pubkeys) {
                if (obfuScationSigner.VerifyMessage(pubkey, transaction.sig, strMessage, errorMessage)) {
                    return true;
                }
            }

            return error("%s - P2SHNODES - Signature invalid on START Tx - %s", __func__, transaction.GetHash().GetHex());
        }

        // If the transaction collateral pubkey matches the chainparams for paytoscripthash signing
        // Verify the signature against it.
        std::string public_key = GetP2SHFluxNodePublicKey(transaction);
        CPubKey pubkey(ParseHex(public_key));
        if (transaction.collateralPubkey == pubkey) {
            if (!obfuScationSigner.VerifyMessage(transaction.collateralPubkey, transaction.sig, strMessage, errorMessage))
                return error("%s - Foundation P2SH - START Error: %s", __func__, errorMessage);
        } else {
            if (!obfuScationSigner.VerifyMessage(transaction.collateralPubkey, transaction.sig, strMessage,errorMessage))
                return error("%s - NORMAL START Error: %s", __func__, errorMessage);
        }

        return true;
    } else if (transaction.nType == FLUXNODE_CONFIRM_TX_TYPE) {

        auto data = g_fluxnodeCache.GetFluxnodeData(transaction.collateralIn);
        std::string errorMessage;

        std::string strMessage = transaction.collateralIn.ToString() + std::to_string(transaction.collateralIn.n) + std::to_string(transaction.nUpdateType) + std::to_string(transaction.sigTime);

        // Someone a node can be kicked on the list. So when we are verifying from the db transaction. we dont have the data.pubKey
        if (!data.IsNull()) {
            if (!obfuScationSigner.VerifyMessage(data.pubKey, transaction.sig, strMessage, errorMessage)) {
                if (!fIsVerifying)
                    return error("%s - CONFIRM Error: %s", __func__, errorMessage);
            }
        }

        if (!CheckBenchmarkSignature(transaction)) {
            return error("%s - Error: invalid benchmarking signatures %s,", __func__, errorMessage);
        }

        return true;
    }

    return false;
}

bool CheckBenchmarkSignature(const CTransaction& transaction)
{
    // TESTNET ONLY
    if (IsTestnetBenchmarkBypassActive()) {
        LogPrintf("Testnet - Bypass Benchmark Signature requirment\n");
        return true;
    }

    std::string public_key = GetFluxnodeBenchmarkPublicKey(transaction);
    CPubKey pubkey(ParseHex(public_key));
    std::string errorMessage = "";
    std::string strMessage = std::string(transaction.sig.begin(), transaction.sig.end()) + std::to_string(transaction.benchmarkTier) + std::to_string(transaction.benchmarkSigTime) + transaction.ip;

    if (!obfuScationSigner.VerifyMessage(pubkey, transaction.benchmarkSig, strMessage, errorMessage))
        return error("%s - Error: %s", __func__, errorMessage);

    return true;
}

void GetUndoDataForExpiredFluxnodeDosScores(CFluxnodeTxBlockUndo& p_fluxnodeTxUndoData, const int& p_nHeight)
{
    LOCK(g_fluxnodeCache.cs);

    bool fPONActive = NetworkUpgradeActive(p_nHeight, Params().GetConsensus(), Consensus::UPGRADE_PON);
    int nUndoHeight = p_nHeight - FLUXNODE_DOS_REMOVE_AMOUNT;

    if (fPONActive) {
        nUndoHeight = p_nHeight - FLUXNODE_DOS_REMOVE_AMOUNT_V2;
    }

    for (const auto& item: g_fluxnodeCache.mapStartTxDOSTracker) {
        if (fPONActive) {
            // If there are nodes in DOSTracker with heights less than our new nUndoHeight
            // Include these by using less than or equal.
            if (item.second.nAddedBlockHeight <= nUndoHeight) {
                p_fluxnodeTxUndoData.vecExpiredDosData.emplace_back(item.second);
            }
        } else {
            if (item.second.nAddedBlockHeight == nUndoHeight) {
                p_fluxnodeTxUndoData.vecExpiredDosData.emplace_back(item.second);
            }
        }
    }
}

void GetUndoDataForExpiredConfirmFluxnodes(CFluxnodeTxBlockUndo& p_fluxnodeTxUndoData, const int& p_nHeight, const std::set<COutPoint> setSpentOuts)
{
    LOCK(g_fluxnodeCache.cs);
    int nExpirationCount = GetFluxnodeExpirationCount(p_nHeight);
    int nHeightToExpire = p_nHeight - nExpirationCount;

    // Get set of enforced tiers
    set<Tier> enforceTiers;
    if (p_nHeight >= Params().GetCumulusEndTransitionHeight()) {
        enforceTiers.insert(CUMULUS);
    }

    if (p_nHeight >= Params().GetNimbusEndTransitionHeight()) {
        enforceTiers.insert(NIMBUS);
    }

    if (p_nHeight >= Params().GetStratusEndTransitionHeight()) {
        enforceTiers.insert(STRATUS);
    }

    // Get set of valid collateral amounts
    set<CAmount> validAmounts;
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
        set<CAmount> tempAmount = GetCoinAmountsByTier(p_nHeight, currentTier);
        validAmounts.insert(tempAmount.begin(), tempAmount.end());
    }

    for (const auto& item : g_fluxnodeCache.mapConfirmedFluxnodeData) {
        // We only need to enforce new collaterals until all tiers have been enforced.
        // Stratus is our last tier to enforce so, once it has ended the transition, we shouldn't need to do this anymore.
        if (p_nHeight >= Params().GetCumulusStartTransitionHeight() && p_nHeight < Params().GetStratusEndTransitionHeight() + 10) {
            // Enforce new collateral amounts
            if (enforceTiers.count((Tier) item.second.nTier)) {
                if (!validAmounts.count(item.second.nCollateral)) {
                    LogPrintf(
                            "%s : expiring output because collateral isn't valid output: %s, current collateral: %s, block height: %d\n",
                            __func__, item.second.collateralIn.ToFullString(), FormatMoney(item.second.nCollateral),
                            p_nHeight);
                    p_fluxnodeTxUndoData.vecExpiredConfirmedData.emplace_back(item.second);
                    continue;
                }
            }
        }

        // The p_fluxnodeTxUndoData has a map of all new confirms that have been updated this block. So if it is in there don't expire it. They made it barely in time
        if (p_fluxnodeTxUndoData.mapUpdateLastConfirmHeight.count(item.first)) {
            continue;
        }

        if (item.second.nLastConfirmedBlockHeight < nHeightToExpire) {
            p_fluxnodeTxUndoData.vecExpiredConfirmedData.emplace_back(item.second);
        }
    }

    for (const auto& out : setSpentOuts) {
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(out)) {
            LogPrint("dfluxnode","%s : expiring spent output: %s\n", __func__, out.ToString());
            p_fluxnodeTxUndoData.vecExpiredConfirmedData.emplace_back(g_fluxnodeCache.mapConfirmedFluxnodeData.at(out));
        }
    }
}

void GetUndoDataForPaidFluxnodes(CFluxnodeTxBlockUndo& fluxnodeTxBlockUndo, FluxnodeCache& p_localCache)
{
    LOCK2(p_localCache.cs, g_fluxnodeCache.cs);

    for (const auto& item : p_localCache.mapPaidNodes) {
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item.second.second)) {
            fluxnodeTxBlockUndo.mapLastPaidHeights[item.second.second] = g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.second.second).nLastPaidHeight;
        }
    }
}

void FluxnodeCache::AddNewStart(const CTransaction& p_transaction, const int p_nHeight, int nTier, const CAmount nCollateral)
{
    FluxnodeCacheData data;
    if (p_transaction.nVersion == FLUXNODE_TX_UPGRADEABLE_VERSION) {

        /**
         * With the new Upgraded Transaction Version we have to modify the types
         * If nType is now the new FLUXNODE_TX_TYPE_UPGRADED version. We will have the ability to use new variables
         * nFluxTxVersion is now set to the nFluxTxVersion of the Transaction
         * nTransactionType is now set to FLUXNODE_START_TX_TYPE. This used to be what nType was sent to
         * P2SHRedeemScript is now available from the transaction
         * nCollateral is now always a part of the Cache
         */
        data.nType = FLUXNODE_TX_TYPE_UPGRADED;
        data.nFluxTxVersion = p_transaction.nFluxTxVersion;
        data.nTransactionType = FLUXNODE_START_TX_TYPE;
        data.P2SHRedeemScript = p_transaction.P2SHRedeemScript;

        data.nStatus = FLUXNODE_TX_STARTED;
        data.collateralIn = p_transaction.collateralIn;
        data.collateralPubkey = p_transaction.collateralPubkey;
        data.pubKey = p_transaction.pubKey;
        data.ip = p_transaction.ip;
        data.nLastPaidHeight = 0;
        data.nAddedBlockHeight = p_nHeight;
        data.nTier = nTier;
        data.nCollateral = nCollateral;
    } else {
        data.nStatus = FLUXNODE_TX_STARTED;
        data.nType = FLUXNODE_START_TX_TYPE;
        data.collateralIn = p_transaction.collateralIn;
        data.collateralPubkey = p_transaction.collateralPubkey;
        data.pubKey = p_transaction.pubKey;
        data.ip = p_transaction.ip;
        data.nLastPaidHeight = 0;
        data.nAddedBlockHeight = p_nHeight;
        data.nTier = nTier;
        data.nCollateral = nCollateral;

        if (data.nCollateral > 0) {
            data.nType = FLUXNODE_HAS_COLLATERAL;
        }
    }

    LOCK(cs);
    mapStartTxTracker[p_transaction.collateralIn] = data;
    setDirtyOutPoint.insert(p_transaction.collateralIn);
}

void FluxnodeCache::UndoNewStart(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    setUndoStartTx.insert(p_transaction.collateralIn);
}

void FluxnodeCache::AddNewConfirm(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    mapAddToConfirm[p_transaction.collateralIn] = p_transaction.ip;
    setAddToConfirmHeight = p_nHeight;
}

void FluxnodeCache::UndoNewConfirm(const CTransaction& p_transaction)
{
    LOCK(cs);
    setUndoAddToConfirm.insert(p_transaction.collateralIn);
}

void FluxnodeCache::AddUpdateConfirm(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    mapAddToUpdateConfirm[p_transaction.collateralIn] = p_transaction.ip;
    setAddToUpdateConfirmHeight = p_nHeight;
}

bool FluxnodeCache::CheckIfStarted(const COutPoint& out)
{
    LOCK(cs);
    if (mapStartTxTracker.count(out)) {
        return true;
    }

    LogPrint("dfluxnode", "%s :  Initial Confirm tx, fail because outpoint %s is not in the mapStartTxTracker\n", __func__, out.ToString());
    return false;
}

bool FluxnodeCache::CheckIfConfirmed(const COutPoint& out)
{
    LOCK(cs);
    // We use the map here because the set contains list data that might have expired. the map doesn't
    if (mapConfirmedFluxnodeData.count(out)) {
        return true;
    }

    return false;
}

bool FluxnodeCache::GetPubkeyIfConfirmed(const COutPoint& out, CPubKey& pubKey)
{
    LOCK(cs);
    if (mapConfirmedFluxnodeData.count(out)) {
        pubKey = mapConfirmedFluxnodeData.at(out).pubKey;
        return true;
    }

    return false;
}

bool FluxnodeCache::CheckUpdateHeight(const CTransaction& p_transaction, const int p_nHeight, bool fFromMempool)
{
    int nCurrentHeight;
    if (p_nHeight)
        nCurrentHeight = p_nHeight;
    else
        nCurrentHeight = chainActive.Height();

    COutPoint out = p_transaction.collateralIn;
    if (!p_transaction.IsFluxnodeTx()) {
        return false;
    }

    // This function should only be called on UPDATE_CONFIRM tx types
    if (p_transaction.nUpdateType != FluxnodeUpdateType::UPDATE_CONFIRM) {
        return false;
    }

    LOCK(cs);
    // Check the confirm set before contining
    if (!CheckListSet(out)) {
        return false;
    }

    if (!CheckConfirmationHeights(nCurrentHeight, out, p_transaction.ip, fFromMempool)) {
        return false;
    }

    return true;
}

bool FluxnodeCache::CheckNewStartTx(const COutPoint& out, int nHeight, bool fFromMempool)
{
    LOCK(cs);
    if (mapStartTxTracker.count(out)) {
        // For mempool validation, always reject duplicates
        if (fFromMempool) {
            LogPrint("mempool", "MEMPOOL REJECTION: START_FLUX already in tracker - %s\n", out.ToString());
            return false;
        }

        // For block validation, check if it's at the same height (competing blocks)
        int nAddedHeight = mapStartTxTracker.at(out).nAddedBlockHeight;

        // CONSENSUS FIX: Allow START_FLUX at exact same height to enable competing blocks
        // This allows blocks with better difficulty to compete even if they contain
        // START_FLUX transactions for nodes already added by a competing block
        if (nHeight > 0 && nAddedHeight == nHeight) {
            LogPrintf("EXACT HEIGHT: Allowing START_FLUX at same height - %s: blockHeight=%d, addedHeight=%d\n",
                      out.ToString(), nHeight, nAddedHeight);
            return true;
        }

        LogPrint("dfluxnode", "%s :  Failed because it is in the mapStartTxTracker: %s\n", __func__, out.ToString());
        return false;
    }

    if (mapStartTxDOSTracker.count(out)) {
        LogPrint("dfluxnode", "%s :  Failed because it is in the mapStartTxDOSTracker: %s\n", __func__, out.ToString());
        return false;
    }

    return true;
}

void FluxnodeCache::CheckForExpiredStartTx(const int& p_nHeight)
{
    LOCK2(cs, g_fluxnodeCache.cs);
    int removalHeight = p_nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT;

    if (IsPONActive(p_nHeight)) {
        removalHeight = p_nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT_V2;
    }

    std::vector<COutPoint> vecOutPoints;
    std::set<COutPoint> setNewDosHeights;
    for (const auto& object: g_fluxnodeCache.mapStartTxTracker) {
        if (object.second.nAddedBlockHeight == removalHeight) {
            // The start transaction might have been confirmed in this block. If it was the outpoint would be in the mapAddToConfirm. Skip it
            if (mapAddToConfirm.count(object.first))
                continue;

            FluxnodeCacheData data = object.second;
            data.nStatus = FLUXNODE_TX_DOS_PROTECTION;
            mapStartTxDOSTracker[object.first] = data;
        }
    }

    LogPrint("dfluxnode", "%s : Size of mapStartTxTracker: %s\n", __func__, g_fluxnodeCache.mapStartTxTracker.size());
    LogPrint("dfluxnode", "%s : Size of mapStartTxDOSTracker: %s\n", __func__, g_fluxnodeCache.mapStartTxDOSTracker.size());
    LogPrint("dfluxnode", "%s : Size of mapConfirmedFluxnodeData: %s\n", __func__, g_fluxnodeCache.mapConfirmedFluxnodeData.size());
}

void FluxnodeCache::CheckForUndoExpiredStartTx(const int& p_nHeight)
{
    LOCK2(cs, g_fluxnodeCache.cs);
    int removalHeight = p_nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT;

    if (IsPONActive(p_nHeight)) {
        removalHeight = p_nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT_V2;
    }

    for (const auto& item : g_fluxnodeCache.mapStartTxDOSTracker) {
        if (item.second.nAddedBlockHeight == removalHeight) {
            mapStartTxTracker[item.first] = item.second;
            mapStartTxTracker[item.first].nStatus = FLUXNODE_TX_STARTED;

            mapDOSToUndo[removalHeight].insert(item.first);
        }
    }

    LogPrint("dfluxnode", "%s : Size of mapStartTxTracker: %s\n", __func__, g_fluxnodeCache.mapStartTxTracker.size());
    LogPrint("dfluxnode", "%s : Size of mapStartTxDOSTracker: %s\n", __func__, g_fluxnodeCache.mapStartTxDOSTracker.size());
    LogPrint("dfluxnode","%s : Size of mapConfirmedFluxnodeData: %s\n", __func__, g_fluxnodeCache.mapConfirmedFluxnodeData.size());
}


bool FluxnodeCache::CheckConfirmationHeights(const int nCurrentHeight, const COutPoint& out, const std::string& ip, bool fFromMempool) {
    LOCK(cs); // Protect access to mapConfirmedFluxnodeData from concurrent modification

    if (!mapConfirmedFluxnodeData.count(out)) {
        return false;
    }

    auto data = g_fluxnodeCache.GetFluxnodeData(out);
    if (data.IsNull()) {
        return false;
    }

    bool fFluxActive = NetworkUpgradeActive(nCurrentHeight, Params().GetConsensus(), Consensus::UPGRADE_FLUX);
    // Allow ip address changes at a different interval
    if (fFluxActive) {
        if (ip != data.ip) {
            if (nCurrentHeight - data.nLastConfirmedBlockHeight >= FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1) {
                return true;
            }
        }
    }

    bool fHalvingActive = NetworkUpgradeActive(nCurrentHeight, Params().GetConsensus(), Consensus::UPGRADE_HALVING);
    bool fPONActive = NetworkUpgradeActive(nCurrentHeight, Params().GetConsensus(), Consensus::UPGRADE_PON);

    int nDistanceToCheck = FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V1; // Default - Legacy
    if (fPONActive) {
        nDistanceToCheck = FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V3;
    } else if (fHalvingActive) {
        nDistanceToCheck = FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V2;
    }

    int nConfirmationDistance = nCurrentHeight - data.nLastConfirmedBlockHeight;

    if (nConfirmationDistance <= nDistanceToCheck) {

        if (fFromMempool) {
            LogPrint("mempool", "VALIDATION: Mempool rejection - %s: currentHeight=%d, lastConfirmed=%d, distance=%d\n",
                     out.ToString(), nCurrentHeight, data.nLastConfirmedBlockHeight, nConfirmationDistance);
            return false;
        }

        // CONSENSUS FIX: Allow UPDATE_CONFIRM at exact same height to enable competing blocks
        // This fixes two issues:
        // 1. Allows blocks with better work to compete at same height (PON consensus)
        // 2. Handles reorg edge case where lastConfirmed wasn't rolled back
        // Without this, first block at a height locks out all competitors regardless of difficulty
        if (nConfirmationDistance == 0) {
            LogPrintf("EXACT HEIGHT: Allowing UPDATE_CONFIRM at same height - %s: currentHeight=%d, lastConfirmed=%d\n",
                      out.ToString(), nCurrentHeight, data.nLastConfirmedBlockHeight);
            return true;
        }

        LogPrintf("VALIDATION FAILURE: Block rejection - %s: currentHeight=%d, lastConfirmed=%d, distance=%d, threshold=%d\n",
                  out.ToString(), nCurrentHeight, data.nLastConfirmedBlockHeight, nConfirmationDistance, nDistanceToCheck);
        error("%s - %d - Confirmation to soon - %s -> Current Height: %d, lastConfirmed: %d\n", __func__,
              __LINE__,
              out.ToFullString(), nCurrentHeight, data.nLastConfirmedBlockHeight);
        return false;
    }

    return true;
}

bool FluxnodeCache::InStartTracker(const COutPoint& out)
{
    LOCK(cs);
    return mapStartTxTracker.count(out);
}

bool FluxnodeCache::InDoSTracker(const COutPoint& out)
{
    LOCK(cs);
    return mapStartTxDOSTracker.count(out);
}

bool FluxnodeCache::InConfirmTracker(const COutPoint& out)
{
    LOCK(cs);
    return mapConfirmedFluxnodeData.count(out);
}

bool FluxnodeCache::CheckIfNeedsNextConfirm(const COutPoint& out, const int& p_nHeight)
{
    LOCK(cs);

    bool fHalvingActive = NetworkUpgradeActive(p_nHeight, Params().GetConsensus(), Consensus::UPGRADE_HALVING);
    bool fPONActive = NetworkUpgradeActive(p_nHeight, Params().GetConsensus(), Consensus::UPGRADE_PON);

    if (mapConfirmedFluxnodeData.count(out)) {
        if (fPONActive) {
            return p_nHeight - mapConfirmedFluxnodeData.at(out).nLastConfirmedBlockHeight > FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V3;
        }
        else if (fHalvingActive) {
            return p_nHeight - mapConfirmedFluxnodeData.at(out).nLastConfirmedBlockHeight > FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V2;
        } else {
            return p_nHeight - mapConfirmedFluxnodeData.at(out).nLastConfirmedBlockHeight > FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V1;
        }
    }

    return false;
}

FluxnodeCacheData FluxnodeCache::GetFluxnodeData(const CTransaction& tx)
{
    return GetFluxnodeData(tx.collateralIn);
}

FluxnodeCacheData FluxnodeCache::GetFluxnodeData(const COutPoint& out, int* nNeedLocation)
{
    LOCK(cs);
    if (mapStartTxTracker.count(out)) {
        if (nNeedLocation) *nNeedLocation = FLUXNODE_TX_STARTED;
        return mapStartTxTracker.at(out);
    } else if (mapStartTxDOSTracker.count(out)) {
        if (nNeedLocation) *nNeedLocation = FLUXNODE_TX_DOS_PROTECTION;
        return mapStartTxDOSTracker.at(out);
    } else if (mapConfirmedFluxnodeData.count(out)) {
        if (nNeedLocation) *nNeedLocation = FLUXNODE_TX_CONFIRMED;
        return mapConfirmedFluxnodeData.at(out);
    }

    FluxnodeCacheData data;
    return data;
}

bool FluxnodeCache::GetNextPayment(CTxDestination& dest, const int nTier, COutPoint& p_fluxnodeOut, bool fFluxnodeDBRebuild)
{
    if (nTier == NONE || nTier == LAST) {
        return false;
    }

    LOCK(cs);
    if (mapFluxnodeList.count((Tier)nTier)) {
        auto& tierList = mapFluxnodeList.at((Tier) nTier);
        // Use while loop instead of for loop to properly handle iterator after pop_front()
        // This prevents skipping entries when removing stale nodes
        while (!tierList.listConfirmedFluxnodes.empty()) {
            p_fluxnodeOut = tierList.listConfirmedFluxnodes.front().out;
            if (mapConfirmedFluxnodeData.count(p_fluxnodeOut)) {


                // We can get the destination from the Hash of the RedeemScript.
                if (IsFluxTxP2SHType(mapConfirmedFluxnodeData.at(p_fluxnodeOut).nFluxTxVersion, true)) {
                   CScriptID inner(mapConfirmedFluxnodeData.at(p_fluxnodeOut).P2SHRedeemScript);
                   dest = inner;
                   return true;
                }

                if (IsAP2SHFluxNodePublicKey(mapConfirmedFluxnodeData.at(p_fluxnodeOut).collateralPubkey)) {
                    CTxDestination payment_destination;
                    if (GetFluxNodeP2SHDestination(pcoinsTip, p_fluxnodeOut, payment_destination)) {
                        dest = payment_destination;
                        return true;
                    } else {
                        // Only in a very specific scenario should this happen. while rebuildfluxnodedb rpc is running
                        // Because we are only rebuilding the fluxnode db, we are still on the tip of the chian where a utxo could be marked as spent.
                        // Becase we aren't using the destination address while rebuilding the database this check can be bypassed.
                        if(fFluxnodeDBRebuild) {
                            LogPrintf("%s: Rebuilding Fluxnode Database: P2SH node outpoint %s was spent. So we can't get the address\n", __func__, p_fluxnodeOut.ToString());
                            return true;
                        }
                        /**
                         * This shouldn't ever happen. As the only scenario this fails at is if the coin is spent.
                         * If the coin is spent in the block previous to the block where this fluxnode is next
                         * on the list to get a payment. It will be removed from the confirmed list just as
                         * any other node would be. See -> func (GetUndoDataForExpiredConfirmFluxnodes)
                         * If this coin is spent in the same block that it would receive a payout
                         * the coin would be found in the pcoinsTip Cache and the correct destination would be found
                         * Only after the block is connected would the pcoinTip cache be updated spending the coin"
                         * Making it so we could no longer find the coins scriptPubKey in func ( GetFluxNodeP2SHDestination )
                      */
                        error("Failed to get p2sh destination %s", p_fluxnodeOut.ToFullString());
                        return false;
                    }
                } else {
                    dest = mapConfirmedFluxnodeData.at(p_fluxnodeOut).collateralPubkey.GetID();
                    return true;
                }
            } else {
                // The front of the list, wasn't in the confirmed fluxnode data. These means it expired
                // Remove and continue checking (while loop will check new front element)
                tierList.listConfirmedFluxnodes.pop_front();
                tierList.setConfirmedTxInList.erase(p_fluxnodeOut);
            }
        }
    } else {
        error("Map::at -> mapFluxnodeList didn't have tier=%d", nTier);
    }

    return false;
}

struct FluxnodePayoutInfo {
    CTxDestination dest;
    COutPoint outpoint;
    CScript script;
    CAmount amount;
    bool approvedpayout = false;
    bool foundpayout = false;
};

bool FluxnodeCache::CheckFluxnodePayout(const CTransaction& coinbase, const int p_Height, FluxnodeCache* p_fluxnodeCache)
{
    LOCK(cs);

    // REORG BUGFIX: Proactively clean up stale entries from payment lists before determining payouts
    // This prevents list corruption during reorgs where nodes may have been moved back to START
    // state or expired but remain in the list due to lazy cleanup. Without this, payment validation
    // can fail because the expected payee is not at the front of the list.
    // This is fork-safe because it implements the same cleanup logic that GetNextPayment() already
    // does (line 634-635), just more thoroughly and earlier.
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
        if (mapFluxnodeList.count((Tier)currentTier)) {
            auto& tierList = mapFluxnodeList.at((Tier)currentTier);

            // Remove stale entries from front of list
            while (!tierList.listConfirmedFluxnodes.empty()) {
                COutPoint frontOutpoint = tierList.listConfirmedFluxnodes.front().out;

                // Check if this node is still in the confirmed map
                if (!mapConfirmedFluxnodeData.count(frontOutpoint)) {
                    // Entry is stale, remove it from both list and set
                    LogPrint("fluxnode", "%s: Removing stale entry from %s payment list: %s\n",
                             __func__, TierToString((Tier)currentTier), frontOutpoint.ToString());
                    tierList.listConfirmedFluxnodes.pop_front();
                    tierList.setConfirmedTxInList.erase(frontOutpoint);
                } else {
                    // Front entry is valid, stop cleaning
                    break;
                }
            }
        }
    }

    CAmount blockValue = GetBlockSubsidy(p_Height, Params().GetConsensus());
    CAmount nRemainerLeft = blockValue;
    std::map<Tier, FluxnodePayoutInfo> mapFluxnodePayouts;

    // Gather all correct payout data
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++ ) {
        FluxnodePayoutInfo info;
        if (GetNextPayment(info.dest, currentTier, info.outpoint)) {
            info.script = GetScriptForDestination(info.dest);
            info.amount = GetFluxnodeSubsidy(p_Height, blockValue, currentTier);
            mapFluxnodePayouts[(Tier)currentTier] = info;
            nRemainerLeft -= info.amount; // Deduce remainer
        }
    }

    // Dev fund checking, we we are already going through the coinbase vouts
    bool fDevFundPaid = false;
    bool fCheckDevFundPayment = IsPONActive(p_Height);
    CScript devFundScript = GetScriptForDestination(DecodeDestination(Params().GetDevFundAddress()));

    // Track which outputs have been used for fluxnode payments to prevent double-counting
    std::set<size_t> setUsedOutputs;

    // Compare it to what is in the block
    // Loop through Tx to make sure they all got paid
    for (size_t i = 0; i < coinbase.vout.size(); i++) {
        const auto& out = coinbase.vout[i];
        for (auto& payout : mapFluxnodePayouts) {
            if (!payout.second.approvedpayout) {
                if (out.scriptPubKey == payout.second.script) {
                    if (out.nValue == payout.second.amount) {
                        payout.second.approvedpayout = true;
                        setUsedOutputs.insert(i); // Mark this output as used for fluxnode payment
                        break;
                    }
                }
            }
        }

        // Check Dev Fund Payment (Strict) - but only if this output hasn't been used for fluxnode payment
        if (fCheckDevFundPayment && !fDevFundPaid && !setUsedOutputs.count(i)) {
            if (out.scriptPubKey == devFundScript) {
                if (out.nValue >= nRemainerLeft) {
                    fDevFundPaid = true;
                }
            }
        }
    }
 
    // Check for failed payouts and add the paid nodes if approved
    if (fCheckDevFundPayment && !fDevFundPaid) {
        error("Invalid block dev fund payment. Should be paying : %s -> %u", Params().GetDevFundAddress(), nRemainerLeft);
        return false;
    }

    bool fFail = false;
    for (const auto payout : mapFluxnodePayouts) {
        if (!payout.second.approvedpayout) {
            fFail = true;
            error("Invalid block fluxnode payee list: Invalid %s payee. Should be paying : %s -> %u", TierToString(payout.first), EncodeDestination(payout.second.dest), payout.second.amount);
        } else {
            if (p_fluxnodeCache) {
                p_fluxnodeCache->AddPaidNode(payout.first, payout.second.outpoint, p_Height);
            }
        }
    }

    return !fFail;
}

void FillBlockPayeeWithDeterministicPayouts(CMutableTransaction& txNew, CAmount nFees, std::map<int, std::pair<CScript, CAmount>>* payments)
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    std::map<Tier, FluxnodePayoutInfo> mapFluxnodePayouts;
    CAmount blockValue = GetBlockSubsidy(pindexPrev->nHeight + 1, Params().GetConsensus());
    int nTotalPayouts = 0;

    // Gather next payout information
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++ ) {
        nTotalPayouts++;
        FluxnodePayoutInfo info;
        if (g_fluxnodeCache.GetNextPayment(info.dest, currentTier, info.outpoint)) {
            info.amount = GetFluxnodeSubsidy(pindexPrev->nHeight + 1, blockValue, currentTier);
            info.foundpayout = true;
        } else {
            info.foundpayout = false;
            nTotalPayouts--;
        }
        mapFluxnodePayouts[(Tier)currentTier] = info;
    }

    // Resize tx to correct payout sizing
    if (nTotalPayouts > 0) {
        txNew.vout.resize(nTotalPayouts + 1);
    }

    // Build tx with payout information
    CAmount nMinerReward = blockValue;
    int currentIndex = 1;
    for (const auto& payout : mapFluxnodePayouts) {
        if (payout.second.foundpayout) {
            txNew.vout[currentIndex].scriptPubKey = GetScriptForDestination(payout.second.dest);
            txNew.vout[currentIndex].nValue = payout.second.amount;
            nMinerReward -= payout.second.amount;
            currentIndex++;

            if (payments)
                payments->insert(std::make_pair(payout.first,
                                                std::make_pair(GetScriptForDestination(payout.second.dest),
                                                               payout.second.amount)));
            LogPrint("dfluxnode","Fluxnode %s payment of %s to %s\n", TierToString(payout.first), FormatMoney(payout.second.amount).c_str(), EncodeDestination(payout.second.dest).c_str());
        }
    }

    txNew.vout[0].nValue = nMinerReward;
}


void FluxnodeCache::AddExpiredDosTx(const CFluxnodeTxBlockUndo& p_undoData, const int p_nHeight)
{
    LOCK(cs);
    std::set<COutPoint> setOutPoint;
    for (const auto& item : p_undoData.vecExpiredDosData) {
        setOutPoint.insert(item.collateralIn);
    }
    mapDosExpiredToRemove[p_nHeight] = setOutPoint;
}

void FluxnodeCache::AddExpiredConfirmTx(const CFluxnodeTxBlockUndo& p_undoData)
{
    LOCK(cs);
    for (const auto& item : p_undoData.vecExpiredConfirmedData) {
        setExpireConfirmOutPoints.insert(item.collateralIn);
    }
}

void FluxnodeCache::AddPaidNode(const int& tier, const COutPoint& out, const int p_Height)
{
    LOCK(cs); // Lock local cache
    mapPaidNodes[tier] = std::make_pair(p_Height, out);
}

void FluxnodeCache::AddBackUndoData(const CFluxnodeTxBlockUndo& p_undoData)
{
    // Locking local cache (p_fluxnodecache)
    LOCK(cs);

    int nHeight = 0;

    // Undo the expired dos outpoints
    for (const auto& item : p_undoData.vecExpiredDosData) {
        nHeight = item.nAddedBlockHeight;
        mapStartTxDOSTracker[item.collateralIn] = item;
    }

    // Undo the Confirm Update transactions back to the old LastConfirmHeight
    for (const auto& item : p_undoData.mapUpdateLastConfirmHeight) {
        LOCK(g_fluxnodeCache.cs);
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item.first)) {
            int oldValueInGlobal = g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first).nLastConfirmedBlockHeight;

            // FIX: Only copy from global if this outpoint is NOT already in the local cache
            // If it's already in local cache, it means we've already prepared undo for it in this batch
            // and we should preserve those changes rather than overwriting with current global state
            if (!mapConfirmedFluxnodeData.count(item.first)) {
                mapConfirmedFluxnodeData[item.first] = g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first);
            }

            // Now set the confirmation height to the undo value
            mapConfirmedFluxnodeData[item.first].nLastConfirmedBlockHeight = item.second;
            LogPrintf("UNDO PREPARE: Copying to local cache for %s: globalValue=%d, willRestoreTo=%d\n",
                      item.first.ToString(), oldValueInGlobal, item.second);
        } else {
            if (!fIsVerifying)
                error("%s : This should never happen. When undo an update confirm nLastConfirmedBlockHeight . FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n",
                  __func__, item.first.hash.GetHex());
        }
    }

    // Undo the Confirm Update transaction back to the old ipAddresses
    for (const auto& item : p_undoData.mapLastIpAddress) {
        LOCK(g_fluxnodeCache.cs);
        // Because we might have already retrieved the fluxnode global data above when adding back the nLastConfirmedBlockHeight
        // We don't want to override the nLastConfirmedBlockHeight change above
        if (mapConfirmedFluxnodeData.count(item.first)) {
            mapConfirmedFluxnodeData.at(item.first).ip = item.second;
        } else if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item.first)) {
            mapConfirmedFluxnodeData[item.first] = g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first);
            mapConfirmedFluxnodeData.at(item.first).ip = item.second;
        } else {
            if (!fIsVerifying)
                error("%s : This should never happen. When undo an update confirm ip address. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n",
                      __func__, item.first.hash.GetHex());
        }
    }

    // Undo the Confirms that were Expired
    for (const auto& item : p_undoData.vecExpiredConfirmedData) {
        setUndoExpireConfirm.insert(item);
    }

    for (const auto& item : p_undoData.mapLastPaidHeights) {
        mapUndoPaidNodes[item.first] = item.second;
    }
}

bool FluxnodeCache::Flush()
{
    std::set<COutPoint> setRemoveFromList;

    std::vector<FluxnodeCacheData> vecNodesToAdd;

    LOCK2(cs, g_fluxnodeCache.cs);
    /**
     * When a new start node transaction is mined, we need to do the following:
     * 1. Add the nodes transaction data into the start transaction map
     * 2. Add the nodes collateral into the map that tracks all collaterals added at its height
     * 3. Mark the collateral as dirty so it can be databased when the daemon shutdowns.
     */
    for (const auto& item : mapStartTxTracker) {
        g_fluxnodeCache.mapStartTxTracker[item.first] = item.second;
        g_fluxnodeCache.setDirtyOutPoint.insert(item.first);
    }

    /**
     * When a start node transaction isn't confirmed in time, we need to do the following:
     * 1. Add the node into the DOS tracker
     * 2. Remove the node from the start tracker
     * 3. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     */
    for (const auto& item : mapStartTxDOSTracker) {
        g_fluxnodeCache.mapStartTxDOSTracker[item.first] = item.second;
        g_fluxnodeCache.mapStartTxTracker.erase(item.first);
        g_fluxnodeCache.setDirtyOutPoint.insert(item.first);
    }

    /**
     * When a node has been on the DOS list for the required threshold, we need to do the following:
     * 1. Remove the node from the DOS Tracker.
     * 2. Mark the removed nodes as dirty so they can be databased when the node shutdowns
     * 3. Remove all entries from the DOS heights tracker at the height they were added at
     */
    for (const auto& item : mapDosExpiredToRemove) {
        for (const auto& data : item.second) {
            g_fluxnodeCache.mapStartTxDOSTracker.erase(data);
            g_fluxnodeCache.setDirtyOutPoint.insert(data);
        }
    }

    /**
     * If we are undoing a block, and this block contained a start transaction that never
     * was confirmed that means the node was added to the DOS list. We need to perform the following steps:
     * 1. Remove all nodes from the DOS tracker map
     * 2. Remove all entries from the DOS heights tracker at the height they were added at
     */
    for (const auto& item : mapDOSToUndo) {
        // Loop through all COutPoints and remove them from the DOS Tracker.
        for (const auto& out : item.second) {
            g_fluxnodeCache.mapStartTxDOSTracker.erase(out);
            g_fluxnodeCache.setDirtyOutPoint.insert(out);
        }
    }

    /**
     * If we are undoing a block, and this block contained an UPDATE confirmation transaction. We need to do the following:
     * 1. Set the confirmed nodes last confirmation height back to the original.
     * 2. Set the confirmed nodes ip address back to the original
     * 3. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     */
    for (const auto& item : mapConfirmedFluxnodeData) {
        int currentValueInGlobal = g_fluxnodeCache.mapConfirmedFluxnodeData[item.first].nLastConfirmedBlockHeight;
        int restoredValue = item.second.nLastConfirmedBlockHeight;

        g_fluxnodeCache.mapConfirmedFluxnodeData[item.first].nLastConfirmedBlockHeight = item.second.nLastConfirmedBlockHeight;
        g_fluxnodeCache.mapConfirmedFluxnodeData[item.first].ip = item.second.ip;
        g_fluxnodeCache.setDirtyOutPoint.insert(item.first);

        LogPrintf("FLUSH BACKWARD: Applying UNDO for %s: currentInGlobal=%d -> restoredValue=%d\n",
                  item.first.ToString(), currentValueInGlobal, restoredValue);
    }

    set<Tier> removedTiers;
    set<Tier> undoExpiredTiers;
    bool fUndoExpiredAddedToList = false;

    /**
     * If we are undoing a block, and this block triggered a confirmed node to expire, We need to do the following:
     * 1. Add the confirmed node back into the confirmed node map
     * 2. Mark the collateral as dirty so it can be databased when the node shutdowns
     * 3. Check the node sorted list, if the node isn't in the list, add the node into the list
     * 4. Update the tier list that was added to, as this list will now need to be sorted.
     */
    for (const auto& item : setUndoExpireConfirm) {
        g_fluxnodeCache.mapConfirmedFluxnodeData[item.collateralIn] = item;
        g_fluxnodeCache.setDirtyOutPoint.insert(item.collateralIn);

        if (g_fluxnodeCache.CheckListHas(item)) {
            // already in set, and therefor list. Skip it
            continue;
        } else {
            vecNodesToAdd.emplace_back(item);
            undoExpiredTiers.insert((Tier)item.nTier);
        }
    }

    /**
     * If we are undoing a block, and this block contained a start node transaction, We need to do the following:
     * 1. Remove the node from the start tracker
     * 2. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     */
    for (const auto& item : setUndoStartTx) {
        g_fluxnodeCache.mapStartTxTracker.erase(item);
        g_fluxnodeCache.setDirtyOutPoint.insert(item);
    }

    /**
     * If we are adding a block, and this block contained a START confirmation transaction, We need to do the following:
     * 1. Fetch the nodes data from the start tx tracker
     * 2. Remove the node from the start tx tracker
     * 3. Remove the node from the start tx heights tracker
     * 4. Update the nodes data to status of confirmed
     * 5. Add the node into the confirmed node tracker
     * 6. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     */
    for (const auto& item : mapAddToConfirm) {
        // Take the fluxnodedata from the mapStartTxTracker and move it to the mapConfirm
        if (g_fluxnodeCache.mapStartTxTracker.count(item.first)) {
            FluxnodeCacheData data = g_fluxnodeCache.mapStartTxTracker.at(item.first);
            // Remove from Start Tracking
            g_fluxnodeCache.mapStartTxTracker.erase(item.first);

            // Update the data (STARTED --> CONFIRM)
            data.nStatus = FLUXNODE_TX_CONFIRMED;
            data.nConfirmedBlockHeight = setAddToConfirmHeight;
            data.nLastConfirmedBlockHeight = setAddToConfirmHeight;

            data.nLastPaidHeight = 0;
            data.ip = item.second;

            // Add the data to the confirm trackers
            g_fluxnodeCache.mapConfirmedFluxnodeData[data.collateralIn] = data;

            // Because we don't automatically remove nodes that have expired from the list, to help not sort it as often
            // If this node is already in the list. We wont add it let. We need to wait for the node to be removed from the list.
            // Then we can add it to the list
            if (!g_fluxnodeCache.mapFluxnodeList.count((Tier)data.nTier)) {
                error("%s - %d , Found map:at error", __func__, __LINE__);
            }
            if (g_fluxnodeCache.mapFluxnodeList.at((Tier)data.nTier).setConfirmedTxInList.count(data.collateralIn)) {
                setRemoveFromList.insert(data.collateralIn);
                removedTiers.insert(Tier(data.nTier));
            }

            // TODO, once we are running smoothly. We should be able to place into a list, sort the list. Add add the nodes in order that is is sorted.
            // TODO, if we do this, we should be able to not sort the list, if we only add new confirmed nodes to it.
            vecNodesToAdd.emplace_back(data);
            undoExpiredTiers.insert((Tier)data.nTier);

            g_fluxnodeCache.setDirtyOutPoint.insert(item.first);
        } else {
            error("%s : This should never happen. When moving from start map to confirm map. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__,  item.first.hash.GetHex());
        }
    }


    /**
     * If we are undoing a block, and this block contained a confirmation transaction for a node, we need to do the following:
     * 1. Fetch the nodes data from the confirmed node tracker
     * 2. Erase the node from the confirmed node tracker
     * 3. Remove the outpoint from the node payment list if it is in the list
     * 4. Update the nodes data to STARTED status
     * 5. Add the node into the start tx tracker
     * 6. Add the node into the start tx heights tracker
     * 7. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     */
    for (const auto& item : setUndoAddToConfirm) {
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item)) {
            FluxnodeCacheData data = g_fluxnodeCache.mapConfirmedFluxnodeData.at(item);

            // Remove from Confirm Tracking
            g_fluxnodeCache.mapConfirmedFluxnodeData.erase(item);

            // adding it to this set, means that it will go and remove the outpoint from the list, and the set if it is in there
            setRemoveFromList.insert(data.collateralIn);
            removedTiers.insert(Tier(data.nTier));

            // Update the data (CONFIRM --> STARTED)
            data.nStatus = FLUXNODE_TX_STARTED;
            data.nConfirmedBlockHeight = 0;
            data.nLastConfirmedBlockHeight = 0;
            data.nLastPaidHeight = 0;
            data.ip = "";

            // Add the data back into the Start tracker
            g_fluxnodeCache.mapStartTxTracker[item] = data;

            g_fluxnodeCache.setDirtyOutPoint.insert(item);

            // IMPORTANT: We don't update the list of fluxnodes. Because if we wanted to, we would have to scan through the list until we found the OutPoint that matches
            // Instead we leave the list untouched, and when seeing who to pay next. We check the setConfirmedTxInList to verify they are still confirmed
            // If they aren't confirmed, we will just keep poping the top of the list until we find one that is

        } else {
            error("%s : This should never happen. When moving from confirm map to start map. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.hash.GetHex());
        }
    }

    /**
     * If we are adding a block, and this block contained an UPDATE confirmation transaction, we need to do the following:
     * 1. Update the latest confirmation block height to the new confirmation height
     * 2. Update the IP address if it was changed in the UPDATE confirmation transaction
     * 3. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     */
    for (const auto& item : mapAddToUpdateConfirm) {
        // Take the fluxnodedata from the mapStartTxTracker and move it to the mapConfirm
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item.first)) {

            int oldValue = g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first).nLastConfirmedBlockHeight;

            // Update the nLastConfirmedBlockHeight
            g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first).nLastConfirmedBlockHeight = setAddToUpdateConfirmHeight;

            LogPrintf("FLUSH FORWARD: Applying UPDATE_CONFIRM for %s: oldLastConfirmed=%d -> newLastConfirmed=%d\n",
                      item.first.ToString(), oldValue, setAddToUpdateConfirmHeight);

            // Update IP address
            g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first).ip = item.second;

            g_fluxnodeCache.setDirtyOutPoint.insert(item.first);
        } else {
            error("%s : This should never happen. When updating a fluxnode from the confirm map. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.first.hash.GetHex());
        }
    }

    /**
     * If we are adding a block, and this block triggered a confirmed node to expire, we need to do the following:
     * 1. Remove the nodes data from the confirmed node tracker
     * 2. We do not remove the node from the payment list, because we don't want to have to sort the list everytime this happens.
     * 3. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     */
    for (const auto& item : setExpireConfirmOutPoints) {
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item)) {

            // Erase the data from the map and set
            g_fluxnodeCache.mapConfirmedFluxnodeData.erase(item);

            // IMPORTANT:: the item stays in the list and the set. This is because we don't want to have to resort the list everytime something expires.
            // Only when new added is added to the list.

            // Add the OutPoint to the dirty set, so it will be erased on database write
            g_fluxnodeCache.setDirtyOutPoint.insert(item);
        } else {
            error("%s : This should never happen. When expiring a fluxnode from the confirm map. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.hash.GetHex());
        }
    }

    /**
     * If we are adding a block, and this block paid out nodes, we need to do the following:
     * 1. Update the confirmed nodes data last paid height
     * 2. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     * 3. Update the payment list by removing the node that was just paid and putting them back in the list at the bottom.
     */
    for (const auto& item : mapPaidNodes) {
        Tier currentTier = (Tier)item.first;
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item.second.second)) {

            // Set the new last paid height
            g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.second.second).nLastPaidHeight = item.second.first;
            g_fluxnodeCache.setDirtyOutPoint.insert(item.second.second);

            if (!g_fluxnodeCache.mapFluxnodeList.count(currentTier)) {
                error("%s - %d , Found map:at error", __func__, __LINE__);
            }

            if (g_fluxnodeCache.mapFluxnodeList.at(currentTier).setConfirmedTxInList.count(item.second.second)) {
                if (g_fluxnodeCache.mapFluxnodeList.at(currentTier).listConfirmedFluxnodes.front().out == item.second.second) {
                    g_fluxnodeCache.mapFluxnodeList.at(currentTier).listConfirmedFluxnodes.pop_front();
                    FluxnodeListData newListData(g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.second.second));

                    // Put
                    g_fluxnodeCache.mapFluxnodeList.at(currentTier).listConfirmedFluxnodes.emplace_back(newListData);
                } else {
                    error("%s : This should never happen. When checking the list of a paid node. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.second.second.hash.GetHex());
                }
            } else {
                error("%s : This should never happen. When adding a paid node. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.second.second.hash.GetHex());
            }
        }
    }

    /**
     * If we are undoing a block, and this block paid out nodes, we need to do the following:
     * 1. Set the last paid height back to the previous value
     * 2. Mark the collateral as dirty so it can be databased when the daemon shutdowns
     * 3. Revert the payment list back so that the nodes that were paid are back at the top of the list and not the bottom.
     * We make sure to remove the node in a way that the list doesn't need to be sorted by default.
     */
    for (const auto& item : mapUndoPaidNodes) {
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item.first)) {
            // Set the height back to the last value
            g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first).nLastPaidHeight = item.second;
            g_fluxnodeCache.setDirtyOutPoint.insert(item.first);

            Tier tier = (Tier)g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first).nTier;

            bool fFoundIt = false;
            if (!g_fluxnodeCache.mapFluxnodeList.count(tier)) {
                error("%s - %d , Found map:at error", __func__, __LINE__);
            }
            if (g_fluxnodeCache.mapFluxnodeList.at(tier).setConfirmedTxInList.count(item.first)) {

                // BUGFIX: Search from end backwards, but INCLUDE the first element
                // Original code stopped at begin() without checking it, causing failures
                // when the paid node ended up at the front of the list
                auto it = g_fluxnodeCache.mapFluxnodeList.at(tier).listConfirmedFluxnodes.end();
                auto begin_it = g_fluxnodeCache.mapFluxnodeList.at(tier).listConfirmedFluxnodes.begin();

                while (it != begin_it) {
                    --it;
                    if (it->out == item.first) {
                        // The node that we are undoing the paid height on, should always be near the last node in the list. So, we need
                        // to get the data. Remove the entry from near the back of the list, and put it at the front.
                        // This allows us to not have to sort() the list afterwards. If this was the only change
                        FluxnodeListData old_data = *it;
                        g_fluxnodeCache.mapFluxnodeList.at(tier).listConfirmedFluxnodes.erase(it);
                        old_data.nLastPaidHeight = item.second;
                        g_fluxnodeCache.mapFluxnodeList.at(tier).listConfirmedFluxnodes.emplace_front(old_data);
                        fFoundIt = true;
                        break;
                    }
                }
            }

                if (!fFoundIt)
                    error("%s : This should never happen. When undoing a paid node. The back most item in the list isn't the correct outpoint. Report this to the dev team to figure out what is happening: %s\n",
                          __func__, item.first.hash.GetHex());
            } else {
                error("%s : This should never happen. When undoing a paid node. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n",
                      __func__, item.first.hash.GetHex());
            }
    }

    /**
     * Handle delegate cache operations
     * Move delegate changes from local cache to global cache
     */
    for (const auto& item : mapDelegateToWrite) {
        // Add/update delegate to dirty writes map
        g_fluxnodeCache.mapDirtyDelegateWrites[item.first] = item.second;
        // Remove from erase set if it was there
        g_fluxnodeCache.setDirtyDelegateErases.erase(item.first);
    }

    for (const auto& outpoint : setDelegateToErase) {
        // Add to dirty erase set
        g_fluxnodeCache.setDirtyDelegateErases.insert(outpoint);
        // Remove from writes map if it was there
        g_fluxnodeCache.mapDirtyDelegateWrites.erase(outpoint);
    }

    //! DO ALL REMOVAL FROM THE ITEMS IN THE LIST HERE (using iterators so we can remove items while going over the list a single time
    // Currently only have to do this when moving from CONFIRM->START (undo blocks only)
    if (setRemoveFromList.size()) {

        for (const Tier& tier : removedTiers)
            g_fluxnodeCache.EraseFromList(setRemoveFromList, tier);
    }

    //! DO ALL ADDS TO THE LIST HERE
    if (vecNodesToAdd.size()) {
        // Add the list data to the sort fluxnode list
        for (const auto& item : vecNodesToAdd)
            g_fluxnodeCache.InsertIntoList(item);
    }

    //! ALWAYS THE LAST CALL IN THE FLUSH COMMAND
    // Always the last thing to do in the Flush. Sort the list if any data was added to it
    if (mapAddToConfirm.size() || undoExpiredTiers.size() || removedTiers.size() || setRemoveFromList.size() || mapPaidNodes.size()) {

        for (int currentTier = CUMULUS; currentTier != LAST; currentTier++ )
        {
            if (removedTiers.count((Tier)currentTier) || undoExpiredTiers.count((Tier)currentTier) || mapPaidNodes.count((Tier)currentTier))
                g_fluxnodeCache.SortList(currentTier);
        }
    }

    

    return true;
}

// Needs to be protected by locking cs before calling
bool FluxnodeCache::LoadData(FluxnodeCacheData& data)
{

    switch(data.nStatus) {
        case FLUXNODE_TX_STARTED:
            mapStartTxTracker[data.collateralIn] = data;
            break;
        case FLUXNODE_TX_DOS_PROTECTION:
            mapStartTxDOSTracker[data.collateralIn] = data;
            break;
        case FLUXNODE_TX_CONFIRMED:
            mapConfirmedFluxnodeData[data.collateralIn] = data;
            InsertIntoList(data);
        default: return true;
    }
    return true;
}

// Needs to be protected by locking cs before calling
void FluxnodeCache::SortList(const int& nTier)
{
    if (IsTierValid(nTier)) {
        if (mapFluxnodeList.count((Tier) nTier)) {
            mapFluxnodeList.at((Tier) nTier).listConfirmedFluxnodes.sort();
        }
    }

}

// Needs to be protected by locking cs before calling
bool FluxnodeCache::CheckListHas(const FluxnodeCacheData& p_fluxnodeData)
{
    if (IsTierValid(p_fluxnodeData.nTier)) {
        if (mapFluxnodeList.count((Tier) p_fluxnodeData.nTier)) {
            return mapFluxnodeList.at((Tier) p_fluxnodeData.nTier).setConfirmedTxInList.count(p_fluxnodeData.collateralIn);
        }
    }

    return false;
}

// Needs to be protected by locking cs before calling
bool FluxnodeCache::CheckListSet(const COutPoint& p_OutPoint)
{
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
        if (mapFluxnodeList.count((Tier) currentTier)) {
            if (mapFluxnodeList.at((Tier) currentTier).setConfirmedTxInList.count(p_OutPoint)) {
                return true;
            }
        }
    }

    return false;
}

void FluxnodeCache::InsertIntoList(const FluxnodeCacheData& p_fluxnodeData)
{
    if (IsTierValid(p_fluxnodeData.nTier)) {
        FluxnodeListData listData(p_fluxnodeData);
        if (mapFluxnodeList.count((Tier) p_fluxnodeData.nTier)) {
            mapFluxnodeList[(Tier) p_fluxnodeData.nTier].setConfirmedTxInList.insert(p_fluxnodeData.collateralIn);
            mapFluxnodeList[(Tier) p_fluxnodeData.nTier].listConfirmedFluxnodes.emplace_front(listData);
        }
    }
}

void FluxnodeCache::EraseFromListSet(const COutPoint& p_OutPoint)
{
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
        if (mapFluxnodeList.count((Tier) currentTier)) {
            if (mapFluxnodeList[(Tier) currentTier].setConfirmedTxInList.count(p_OutPoint)) {
                mapFluxnodeList[(Tier) currentTier].setConfirmedTxInList.erase(p_OutPoint);
                return;
            }
        }
    }
}

void FluxnodeCache::EraseFromList(const std::set<COutPoint>& setToRemove, const Tier nTier)
{
    if (mapFluxnodeList.count(nTier)) {
        std::list<FluxnodeListData>::iterator i = mapFluxnodeList.at(nTier).listConfirmedFluxnodes.begin();
        while (i != mapFluxnodeList.at(nTier).listConfirmedFluxnodes.end()) {
            bool isDataToRemove = setToRemove.count((*i).out);
            if (isDataToRemove) {
                mapFluxnodeList.at(nTier).setConfirmedTxInList.erase((*i).out);
                mapFluxnodeList.at(nTier).listConfirmedFluxnodes.erase(i++);  // alternatively, i = items.erase(i);
            } else {
                ++i;
            }
        }
    }
}

bool FluxnodeCache::GetDelegates(const COutPoint& outpoint, CFluxnodeDelegates& delegates)
{
    LOCK(cs);

    // First check if it's marked for erasure
    if (setDirtyDelegateErases.count(outpoint)) {
        return false; // Delegates have been erased
    }

    // Check if we have a pending write for this outpoint
    if (mapDirtyDelegateWrites.count(outpoint)) {
        delegates = mapDirtyDelegateWrites.at(outpoint);
        return true;
    }

    // Not in cache, read from database
    if (pFluxnodeDB) {
        return pFluxnodeDB->ReadFluxnodeDelegates(outpoint, delegates);
    }

    return false;
}

void FluxnodeCache::DumpFluxnodeCache()
{
    LOCK(cs);
    bool found = false;
    for (auto item : setDirtyOutPoint) {
        found = false;
        if (mapStartTxTracker.count(item)) {
            found = true;
            pFluxnodeDB->WriteFluxnodeCacheData(mapStartTxTracker.at(item));
        } else if (mapStartTxDOSTracker.count(item)) {
            found = true;
            pFluxnodeDB->WriteFluxnodeCacheData(mapStartTxDOSTracker.at(item));
        } else if (mapConfirmedFluxnodeData.count(item)) {
            found = true;
            pFluxnodeDB->WriteFluxnodeCacheData(mapConfirmedFluxnodeData.at(item));
        }

        if (!found) {
            pFluxnodeDB->EraseFluxnodeCacheData(item);
        }
    }

    // Write dirty delegates to database
    for (const auto& item : mapDirtyDelegateWrites) {
        pFluxnodeDB->WriteFluxnodeDelegates(item.first, item.second);
    }

    for (const auto& outpoint : setDirtyDelegateErases) {
        pFluxnodeDB->EraseFluxnodeDelegate(outpoint);
    }
}

bool IsFluxnodeTransactionsActive()
{
    return chainActive.Height() >= Params().GetConsensus().vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight;
}

std::string FluxnodeLocationToString(int nLocation) {
    if (nLocation == FLUXNODE_TX_ERROR) {
        return "OFFLINE";
    } else if (nLocation == FLUXNODE_TX_STARTED) {
        return "STARTED";
    } else if (nLocation == FLUXNODE_TX_DOS_PROTECTION) {
        return "DOS";
    } else if (nLocation == FLUXNODE_TX_CONFIRMED) {
        return "CONFIRMED";
    } else {
        return "OFFLINE";
    }
}

void FluxnodeCache::CountNetworks(int& ipv4, int& ipv6, int& onion, std::vector<int>& vNodeCount) {
    for (const auto& entry : mapConfirmedFluxnodeData) {
        std::string strHost = entry.second.ip;
        CNetAddr node = CNetAddr(strHost, false);
        int nNetwork = node.GetNetwork();
        switch (nNetwork) {
            case 1 :
                ipv4++;
                break;
            case 2 :
                ipv6++;
                break;
            case 3 :
                onion++;
                break;
        }

        for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
            if (mapFluxnodeList.count((Tier) currentTier)) {
                if (mapFluxnodeList.at((Tier) currentTier).setConfirmedTxInList.count(entry.first)) {
                    vNodeCount[currentTier - 1]++;
                    break;
                }
            }
        }
    }
}

void FluxnodeCache::CountMigration(int& nOldTotal, int& nNewTotal, std::vector<int>& vOldNodeCount, std::vector<int>& vNewNodeCount) {
    for (const auto& entry : mapConfirmedFluxnodeData) {
        if (IsMigrationCollateralAmount(entry.second.nCollateral)) {
            vNewNodeCount[entry.second.nTier - 1]++;
            nNewTotal++;
        } else {
            vOldNodeCount[entry.second.nTier - 1]++;
            nOldTotal++;
        }
    }
}

int GetFluxnodeExpirationCount(const int& p_nHeight)
{
    // Get the status on if Fluxnode params1 is activated
    bool fFluxActive = NetworkUpgradeActive(p_nHeight, Params().GetConsensus(), Consensus::UPGRADE_FLUX);
    bool fHalvingActive = NetworkUpgradeActive(p_nHeight, Params().GetConsensus(), Consensus::UPGRADE_HALVING);
    bool fPONActive = NetworkUpgradeActive(p_nHeight, Params().GetConsensus(), Consensus::UPGRADE_PON);

    if (fPONActive) {
        return FLUXNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V4;
    } else if (fHalvingActive) {
        return FLUXNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V3;
    } else if (fFluxActive) {
        return FLUXNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V2;
    } else {
        return FLUXNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V1;
    }
}

std::string GetFluxnodeBenchmarkPublicKey(const CTransaction& tx)
{
    // Get the public keys and timestamps from the chainparams
    std::vector< std::pair<std::string, uint32_t> > vectorPublicKeys = Params().BenchmarkingPublicKeys();

    // If only have one public key return it
    if (vectorPublicKeys.size() == 1) {
        return vectorPublicKeys[0].first;
    }

    // Get the last index in the array
    int nLast = vectorPublicKeys.size() - 1;

    // Loop backwards until we find the correct public key
    for (int i = nLast; i >= 0; i--) {
        if (tx.benchmarkSigTime >= vectorPublicKeys[i].second) {
            return vectorPublicKeys[i].first;
        }
    }

    // Only reason this should happen is if there is a problem with the chainparams
    return vectorPublicKeys[0].first;
}

std::string GetP2SHFluxNodePublicKey(const uint32_t& nSigTime)
{
    // Get the public keys and timestamps from the chainparams
    std::vector< std::pair<std::string, uint32_t> > vectorPublicKeys = Params().GetP2SHFluxnodePublicKeys();

    // If only have one public key return it
    if (vectorPublicKeys.size() == 1) {
        return vectorPublicKeys[0].first;
    }

    // Get the last index in the array
    int nLast = vectorPublicKeys.size() - 1;

    // Loop backwards until we find the correct public key
    for (int i = nLast; i >= 0; i--) {
        if (nSigTime >= vectorPublicKeys[i].second) {
            return vectorPublicKeys[i].first;
        }
    }

    // Only reason this should happen is if there is a problem with the chainparams
    return vectorPublicKeys[0].first;
}


std::string GetP2SHFluxNodePublicKey(const CTransaction& tx)
{
    return GetP2SHFluxNodePublicKey(tx.sigTime);
}

bool GetKeysForP2SHFluxNode(CPubKey& pubKeyRet, CKey& keyRet)
{
    std::string p2shprivkey = GetArg("-fluxnodep2shprivkey", "");
    CKey key;
    key = DecodeSecret(p2shprivkey);

    if (!key.IsValid()) {
        LogPrintf("%s -- Invalid P2SH priv key\n", __func__);
        return false;
    }

    keyRet = key;
    pubKeyRet = keyRet.GetPubKey();
    return true;
}

/** Fluxnode Tier functions
 */
bool IsTierValid(const int& nTier)
{
    return nTier > NONE && nTier < LAST;
}

int GetNumberOfTiers()
{
    return LAST - 1;
}

void FluxnodeCache::LogDebugData(const int& nHeight, const uint256& blockhash, bool fFromDisconnect)
{
    LOCK(cs);
    std::string printme = "{ \n";
    for (const auto &printitem: mapStartTxTracker) {
        printme = printme + printitem.first.ToFullString() + "," + printitem.second.ToFullString() + ",\n";
    }
    printme = printme + "}";

    std::string printme3 = "{ \n";
    for (const auto &printitem: g_fluxnodeCache.mapStartTxDOSTracker) {
        printme3 = printme3 + printitem.first.ToFullString() + "," + printitem.second.ToFullString() + ",\n";
    }
    printme3 = printme3 + "}";

    if (fFromDisconnect) {
        LogPrintf("Disconnecting - printing after block=%d, hash=%s\n, mapStart=%s\n\n, mapStartTxDOSTracker=%s\n\n",
                  nHeight, blockhash.GetHex(), printme, printme3);
    } else {
        LogPrintf("printing after block=%d, hash=%s\n, mapStart=%s\n\n, mapStartTxDOSTracker=%s\n\n",
                  nHeight, blockhash.GetHex(), printme, printme3);
    }

}
/** Fluxnode Tier code end **/

bool IsTestnetBenchmarkBypassActive() {
    bool fTestNet = GetBoolArg("-testnet", false);
    bool fBenchCheckBypass = GetBoolArg("-testnetbenchbypass", false);
    return fTestNet && fBenchCheckBypass;
}
