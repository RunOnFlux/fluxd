// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include <undo.h>
#include <utilmoneystr.h>
#include "zelnode/zelnode.h"
#include "addrman.h"
#include "zelnode/obfuscation.h"
#include "sync.h"
#include "util.h"
#include "key_io.h"
#include "zelnode/activezelnode.h"

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
    if (transaction.nType & FLUXNODE_START_TX_TYPE) {
        // We need to sign the mutable transaction

        std::string errorMessage;

        std::string strMessage = transaction.GetHash().GetHex();

        // If the transaction collateral pubkey matches the chainparams for paytoscripthash signing
        // Verify the signature against it.
        std::string public_key = GetP2SHFluxNodePublicKey(transaction);
        CPubKey pubkey(ParseHex(public_key));
        if (transaction.collateralPubkey == pubkey) {
            if (!obfuScationSigner.VerifyMessage(transaction.collateralPubkey, transaction.sig, strMessage, errorMessage))
                return error("%s - P2SH - START Error: %s", __func__, errorMessage);
        } else {
            if (!obfuScationSigner.VerifyMessage(transaction.collateralPubkey, transaction.sig, strMessage,errorMessage))
                return error("%s - NORMAL START Error: %s", __func__, errorMessage);
        }

        return true;
    } else if (transaction.nType & FLUXNODE_CONFIRM_TX_TYPE) {

        auto data = g_fluxnodeCache.GetFluxnodeData(transaction.collateralOut);
        std::string errorMessage;

        std::string strMessage = transaction.collateralOut.ToString() + std::to_string(transaction.collateralOut.n) + std::to_string(transaction.nUpdateType) + std::to_string(transaction.sigTime);

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
    int nUndoHeight = p_nHeight - FLUXNODE_DOS_REMOVE_AMOUNT;

    if (g_fluxnodeCache.mapStartTxDosHeights.count(nUndoHeight)) {
        for (const auto& item : g_fluxnodeCache.mapStartTxDosHeights.at(nUndoHeight)) {
            if (g_fluxnodeCache.mapStartTxDosTracker.count(item)) {
                p_fluxnodeTxUndoData.vecExpiredDosData.emplace_back(g_fluxnodeCache.mapStartTxDosTracker.at(item));
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
    data.nStatus = FLUXNODE_TX_STARTED;
    data.nType = FLUXNODE_START_TX_TYPE;
    data.collateralIn = p_transaction.collateralOut;
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

    LOCK(cs);
    mapStartTxTracker.insert(std::make_pair(p_transaction.collateralOut, data));
    setDirtyOutPoint.insert(p_transaction.collateralOut);
}

void FluxnodeCache::UndoNewStart(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    setUndoStartTx.insert(p_transaction.collateralOut);
    setUndoStartTxHeight = p_nHeight;
}

void FluxnodeCache::AddNewConfirm(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    setAddToConfirm.insert(std::make_pair(p_transaction.collateralOut, p_transaction.ip));
    setAddToConfirmHeight = p_nHeight;
}

void FluxnodeCache::UndoNewConfirm(const CTransaction& p_transaction)
{
    LOCK(cs);
    setUndoAddToConfirm.insert(p_transaction.collateralOut);
}

void FluxnodeCache::AddUpdateConfirm(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    setAddToUpdateConfirm.insert(std::make_pair(p_transaction.collateralOut, p_transaction.ip));
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

bool FluxnodeCache::CheckUpdateHeight(const CTransaction& p_transaction, const int p_nHeight)
{
    int nCurrentHeight;
    if (p_nHeight)
        nCurrentHeight = p_nHeight;
    else
        nCurrentHeight = chainActive.Height();

    COutPoint out = p_transaction.collateralOut;
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

    if (!CheckConfirmationHeights(nCurrentHeight, out, p_transaction.ip)) {
        return false;
    }

    return true;
}

bool FluxnodeCache::CheckNewStartTx(const COutPoint& out)
{
    LOCK(cs);
    if (mapStartTxTracker.count(out)) {
        LogPrint("dfluxnode", "%s :  Failed because it is in the mapStartTxTracker: %s\n", __func__, out.ToString());
        return false;
    }

    if (mapStartTxDosTracker.count(out)) {
        LogPrint("dfluxnode", "%s :  Failed because it is in the mapStartTxDosTracker: %s\n", __func__, out.ToString());
        return false;
    }

    return true;
}

void FluxnodeCache::CheckForExpiredStartTx(const int& p_nHeight)
{
    LOCK2(cs, g_fluxnodeCache.cs);
    int removalHeight = p_nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT;

    std::vector<COutPoint> vecOutPoints;
    std::set<COutPoint> setNewDosHeights;
    if (g_fluxnodeCache.mapStartTxHeights.count(removalHeight)) {
        for (const auto& item: g_fluxnodeCache.mapStartTxHeights.at(removalHeight)) {
            // The start transaction might have been confirmed in this block. If it was the outpoint would be in the setAddToConfirm. Skip it
            if (setAddToConfirm.count(item))
                continue;

            // If the item isn't in the mapStartTxTracker. Logs the errors and shutdown for the safety of the node
            if (!g_fluxnodeCache.mapStartTxTracker.count(item)) {
                error("Map:at -> Map Start Tx Tracker doesn't have item: %s", item.ToFullString());
                if (g_fluxnodeCache.mapStartTxDosTracker.count(item)) {
                    error("Map::at error would of occured. pIndexHeight=%d, itemHeight=%d\n", p_nHeight, g_fluxnodeCache.mapStartTxDosTracker.at(item).nAddedBlockHeight);
                } else {
                    error("Map Start Tx Tracker doesn't have item - and mapStartTxDostracker didn't have item. %s", item.ToFullString());
                }
                StartShutdown();
            }

            FluxnodeCacheData data = g_fluxnodeCache.mapStartTxTracker.at(item);
            data.nStatus = FLUXNODE_TX_DOS_PROTECTION;
            mapStartTxDosTracker[item] = data;

            setNewDosHeights.insert(item);
        }

        if (setNewDosHeights.size())
            mapStartTxDosHeights[removalHeight] = setNewDosHeights;
    }

    LogPrint("dfluxnode", "%s : Size of mapStartTxTracker: %s\n", __func__, g_fluxnodeCache.mapStartTxTracker.size());
    LogPrint("dfluxnode", "%s : Size of mapStartTxDosTracker: %s\n", __func__, g_fluxnodeCache.mapStartTxDosTracker.size());
    LogPrint("dfluxnode", "%s : Size of mapConfirmedFluxnodeData: %s\n", __func__, g_fluxnodeCache.mapConfirmedFluxnodeData.size());
}

void FluxnodeCache::CheckForUndoExpiredStartTx(const int& p_nHeight)
{
    LOCK2(cs, g_fluxnodeCache.cs);
    int removalHeight = p_nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT;

    if (g_fluxnodeCache.mapStartTxDosHeights.count(removalHeight)) {
        for (const auto& item : g_fluxnodeCache.mapStartTxDosHeights.at(removalHeight)) {

            // If the item isn't in the mapStartTxDosTracker. Logs the errors and shutdown for the safety of the node
            if (!g_fluxnodeCache.mapStartTxDosTracker.count(item)) {
                error("Map:at -> Map Start Tx Dos Tracker doesn't have item: %s", item.ToFullString());
                if (g_fluxnodeCache.mapStartTxTracker.count(item)) {
                    error("Map::at error would of occured. pIndexHeight=%d, itemHeight=%d\n", p_nHeight, g_fluxnodeCache.mapStartTxTracker.at(item).nAddedBlockHeight);
                } else {
                    error("Map Start Dos Tx Tracker doesn't have item - and mapStartTxTracker didn't have item. %s", item.ToFullString());
                }
                StartShutdown();
            }

            mapStartTxTracker.insert(std::make_pair(item, g_fluxnodeCache.mapStartTxDosTracker.at(item)));
            mapStartTxTracker[item].nStatus = FLUXNODE_TX_STARTED;
            mapStartTxHeights[removalHeight].insert(item);

            mapDoSToUndo[removalHeight].insert(item);
        }
    }

    LogPrint("dfluxnode", "%s : Size of mapStartTxTracker: %s\n", __func__, g_fluxnodeCache.mapStartTxTracker.size());
    LogPrint("dfluxnode", "%s : Size of mapStartTxDosTracker: %s\n", __func__, g_fluxnodeCache.mapStartTxDosTracker.size());
    LogPrint("dfluxnode","%s : Size of mapConfirmedFluxnodeData: %s\n", __func__, g_fluxnodeCache.mapConfirmedFluxnodeData.size());
}


bool FluxnodeCache::CheckConfirmationHeights(const int nCurrentHeight, const COutPoint& out, const std::string& ip) {
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
    if (fHalvingActive) {
        if (nCurrentHeight - data.nLastConfirmedBlockHeight <= FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V2) {
            error("%s - %d - Confirmation to soon - %s -> Current Height: %d, lastConfirmed: %d\n", __func__,
                  __LINE__,
                  out.ToFullString(), nCurrentHeight, data.nLastConfirmedBlockHeight);
            return false;
        }
    } else {
        if (nCurrentHeight - data.nLastConfirmedBlockHeight <= FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V1) {
            // TODO - Remove this error message after release + 1 month and we don't see any problems
            error("%s - %d - Confirmation to soon - %s -> Current Height: %d, lastConfirmed: %d\n", __func__,
                  __LINE__,
                  out.ToFullString(), nCurrentHeight, data.nLastConfirmedBlockHeight);
            return false;
        }
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
    return mapStartTxDosTracker.count(out);
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

    if (mapConfirmedFluxnodeData.count(out)) {
        if (fHalvingActive) {
            return p_nHeight - mapConfirmedFluxnodeData.at(out).nLastConfirmedBlockHeight > FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V2;
        } else {
            return p_nHeight - mapConfirmedFluxnodeData.at(out).nLastConfirmedBlockHeight > FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V1;
        }
    }

    return false;
}

FluxnodeCacheData FluxnodeCache::GetFluxnodeData(const CTransaction& tx)
{
    return GetFluxnodeData(tx.collateralOut);
}

FluxnodeCacheData FluxnodeCache::GetFluxnodeData(const COutPoint& out, int* nNeedLocation)
{
    LOCK(cs);
    if (mapStartTxTracker.count(out)) {
        if (nNeedLocation) *nNeedLocation = FLUXNODE_TX_STARTED;
        return mapStartTxTracker.at(out);
    } else if (mapStartTxDosTracker.count(out)) {
        if (nNeedLocation) *nNeedLocation = FLUXNODE_TX_DOS_PROTECTION;
        return mapStartTxDosTracker.at(out);
    } else if (mapConfirmedFluxnodeData.count(out)) {
        if (nNeedLocation) *nNeedLocation = FLUXNODE_TX_CONFIRMED;
        return mapConfirmedFluxnodeData.at(out);
    }

    FluxnodeCacheData data;
    return data;
}

bool FluxnodeCache::GetNextPayment(CTxDestination& dest, const int nTier, COutPoint& p_fluxnodeOut)
{
    if (nTier == NONE || nTier == LAST) {
        return false;
    }

    LOCK(cs);
    if (mapFluxnodeList.count((Tier)nTier)) {
        int setSize = mapFluxnodeList.at((Tier) nTier).setConfirmedTxInList.size();
        if (setSize) {
            for (int i = 0; i < setSize; i++) {
                if (mapFluxnodeList.at((Tier) nTier).listConfirmedFluxnodes.size()) {
                    p_fluxnodeOut = mapFluxnodeList.at((Tier) nTier).listConfirmedFluxnodes.front().out;
                    if (mapConfirmedFluxnodeData.count(p_fluxnodeOut)) {
                        if (IsAP2SHFluxNodePublicKey(mapConfirmedFluxnodeData.at(p_fluxnodeOut).collateralPubkey)) {
                            CTxDestination payment_destination;
                            if (GetFluxNodeP2SHDestination(pcoinsTip, p_fluxnodeOut, payment_destination)) {
                                dest = payment_destination;
                                return true;
                            } else {
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
                        mapFluxnodeList.at((Tier) nTier).listConfirmedFluxnodes.pop_front();
                        mapFluxnodeList.at((Tier) nTier).setConfirmedTxInList.erase(p_fluxnodeOut);
                    }
                } else {
                    return false;
                }
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
    CAmount blockValue = GetBlockSubsidy(p_Height, Params().GetConsensus());
    std::map<Tier, FluxnodePayoutInfo> mapFluxnodePayouts;

    // Gather all correct payout data
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++ ) {
        FluxnodePayoutInfo info;
        if (GetNextPayment(info.dest, currentTier, info.outpoint)) {
            info.script = GetScriptForDestination(info.dest);
            info.amount = GetFluxnodeSubsidy(p_Height, blockValue, currentTier);
            mapFluxnodePayouts.insert(std::make_pair((Tier)currentTier, info));
        }
    }

    // Compare it to what is in the block
    // Loop through Tx to make sure they all got paid
    for (const auto& out : coinbase.vout) {
        for (auto& payout : mapFluxnodePayouts) {
            if (!payout.second.approvedpayout) {
                if (out.scriptPubKey == payout.second.script) {
                    if (out.nValue == payout.second.amount) {
                        payout.second.approvedpayout = true;
                    }
                }
            }
        }
    }

    // Check for failed payouts and add the paid nodes if approved
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
        mapFluxnodePayouts.insert(std::make_pair((Tier)currentTier, info));
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

    std::set<COutPoint> setOutPoint;
    int nHeight = 0;

    // Undo the expired dos outpoints
    for (const auto& item : p_undoData.vecExpiredDosData) {
        nHeight = item.nAddedBlockHeight;
        mapStartTxDosTracker.insert(std::make_pair(item.collateralIn, item));
        setOutPoint.insert(item.collateralIn);
    }

    if (setOutPoint.size()) {
        mapStartTxDosHeights.insert(std::make_pair(nHeight, setOutPoint));
    }

    // Undo the Confirm Update transactions back to the old LastConfirmHeight
    for (const auto& item : p_undoData.mapUpdateLastConfirmHeight) {
        LOCK(g_fluxnodeCache.cs);
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item.first)) {
            mapConfirmedFluxnodeData[item.first] = g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first);
            mapConfirmedFluxnodeData[item.first].nLastConfirmedBlockHeight = item.second;
        } else {
            if (!fIsVerifying)
                error("%s : This should never happen. When undo an update confirm nLastConfirmedBlockHeight . FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n",
                  __func__, item.first.hash.GetHex());
        }
    }

    // Undo the Confirm Update trasnaction back to the old ipAddresses
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
        mapUndoPaidNodes.insert(std::make_pair(item.first, item.second));
    }
}

bool FluxnodeCache::Flush()
{
    std::set<COutPoint> setRemoveFromList;

    std::vector<FluxnodeCacheData> vecNodesToAdd;

    LOCK2(cs, g_fluxnodeCache.cs);
    //! Add new start transactions to the tracker
    for (auto item : mapStartTxTracker) {
        g_fluxnodeCache.mapStartTxTracker.insert(std::make_pair(item.first, item.second));
        if (!g_fluxnodeCache.mapStartTxHeights.count(item.second.nAddedBlockHeight)) {
            g_fluxnodeCache.mapStartTxHeights.insert(make_pair(item.second.nAddedBlockHeight, std::set<COutPoint>()));
        }
        g_fluxnodeCache.mapStartTxHeights.at(item.second.nAddedBlockHeight).insert(item.first);

        g_fluxnodeCache.setDirtyOutPoint.insert(item.first);
    }


    //! If a start transaction isn't confirmed in time, the OutPoint is added to the dos tracker
    for (auto item : mapStartTxDosTracker) {
        g_fluxnodeCache.mapStartTxDosTracker[item.first] = item.second;
        g_fluxnodeCache.mapStartTxTracker.erase(item.first);
        g_fluxnodeCache.setDirtyOutPoint.insert(item.first);
    }

    for (auto item : mapStartTxDosHeights) {
        g_fluxnodeCache.mapStartTxDosHeights[item.first] = item.second;
        g_fluxnodeCache.mapStartTxHeights.erase(item.first);
    }

    //! After the threshhold is met, remove the DoS OutPoints from being banned
    for (auto item : mapDosExpiredToRemove) {
        for (const auto& data : item.second) {
            g_fluxnodeCache.mapStartTxDosTracker.erase(data);
            g_fluxnodeCache.setDirtyOutPoint.insert(data);
        }
        g_fluxnodeCache.mapStartTxDosHeights.erase(item.first);
    }

    //! If we are undo a block, and we undid a block that had Start transaction in it
    for (const auto& item : mapDoSToUndo) {
        for (const auto& out : item.second) {
            g_fluxnodeCache.mapStartTxDosTracker.erase(out);
        }

        g_fluxnodeCache.mapStartTxDosHeights.erase(item.first);
    }

    //! If we are undo a block, and we undid a block that confirmed an Update transaction. We need to undo the update, which just updated the nLastConfirmBlockHeight
    for (const auto& item : mapConfirmedFluxnodeData) {
        g_fluxnodeCache.mapConfirmedFluxnodeData[item.first].nLastConfirmedBlockHeight = item.second.nLastConfirmedBlockHeight;
        g_fluxnodeCache.mapConfirmedFluxnodeData[item.first].ip = item.second.ip;
        g_fluxnodeCache.setDirtyOutPoint.insert(item.first);
    }

    set<Tier> removedTiers;
    set<Tier> undoExpiredTiers;
    bool fUndoExpiredAddedToList = false;
    for (const auto& item : setUndoExpireConfirm) {
        g_fluxnodeCache.mapConfirmedFluxnodeData.insert(std::make_pair(item.collateralIn, item));
        g_fluxnodeCache.setDirtyOutPoint.insert(item.collateralIn);

        if (g_fluxnodeCache.CheckListHas(item)) {
            // already in set, and therefor list. Skip it
            continue;
        } else {
            vecNodesToAdd.emplace_back(item);
            undoExpiredTiers.insert((Tier)item.nTier);
        }
    }

    //! If we are undo a block, and we undid a block that had Start transaction in it
    for (const auto& item : setUndoStartTx) {
        g_fluxnodeCache.mapStartTxTracker.erase(item);
        g_fluxnodeCache.setDirtyOutPoint.insert(item);
    }

    if (setUndoStartTxHeight > 0) {
        g_fluxnodeCache.mapStartTxHeights.erase(setUndoStartTxHeight);
    }

    //! Add the data from Fluxnodes that got confirmed this block
    for (const auto& item : setAddToConfirm) {
        // Take the fluxnodedata from the mapStartTxTracker and move it to the mapConfirm
        if (g_fluxnodeCache.mapStartTxTracker.count(item.first)) {
            FluxnodeCacheData data = g_fluxnodeCache.mapStartTxTracker.at(item.first);

            // Remove from Start Tracking
            g_fluxnodeCache.mapStartTxTracker.erase(item.first);
            if (!g_fluxnodeCache.mapStartTxHeights.count(data.nAddedBlockHeight)) {
                error("%s - %d , Found map:at error", __func__, __LINE__);
            }
            g_fluxnodeCache.mapStartTxHeights.at(data.nAddedBlockHeight).erase(item.first);

            // Update the data (STARTED --> CONFIRM)
            data.nStatus = FLUXNODE_TX_CONFIRMED;
            data.nConfirmedBlockHeight = setAddToConfirmHeight;
            data.nLastConfirmedBlockHeight = setAddToConfirmHeight;

            data.nLastPaidHeight = 0;
            data.ip = item.second;

            // Add the data to the confirm trackers
            g_fluxnodeCache.mapConfirmedFluxnodeData.insert(std::make_pair(data.collateralIn, data));

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
            g_fluxnodeCache.mapStartTxTracker.insert(std::make_pair(item, data));
            g_fluxnodeCache.mapStartTxHeights[data.nAddedBlockHeight].insert(item);

            g_fluxnodeCache.setDirtyOutPoint.insert(item);

            // IMPORTANT: We don't update the list of fluxnodes. Because if we wanted to, we would have to scan through the list until we found the OutPoint that matches
            // Instead we leave the list untouched, and when seeing who to pay next. We check the setConfirmedTxInList to verify they are still confirmed
            // If they aren't confirmed, we will just keep poping the top of the list until we find one that is

        } else {
            error("%s : This should never happen. When moving from confirm map to start map. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.hash.GetHex());
        }
    }

    //! Update the data for Fluxnodes that got the confirmed update this block
    for (const auto& item : setAddToUpdateConfirm) {
        // Take the fluxnodedata from the mapStartTxTracker and move it to the mapConfirm
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item.first)) {

            // Update the nLastConfirmedBlockHeight
            g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first).nLastConfirmedBlockHeight = setAddToUpdateConfirmHeight;

            // Update IP address
            g_fluxnodeCache.mapConfirmedFluxnodeData.at(item.first).ip = item.second;

            g_fluxnodeCache.setDirtyOutPoint.insert(item.first);
        } else {
            error("%s : This should never happen. When updating a fluxnode from the confirm map. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.first.hash.GetHex());
        }
    }

    //! Expire the confirm transactions that haven't been updated in time
    for (const auto& item : setExpireConfirmOutPoints) {
        if (g_fluxnodeCache.mapConfirmedFluxnodeData.count(item)) {

            // Erase the data from the map and set
            g_fluxnodeCache.mapConfirmedFluxnodeData.erase(item);

            // IMPORTANT:: the item stays in the list and the set. This is because we don't want to have to resort the list everytime something expires.
            // Only when new added in added to the list.

            // Add the OutPoint to the dirty set, so it will be erased on database write
            g_fluxnodeCache.setDirtyOutPoint.insert(item);
        } else {
            error("%s : This should never happen. When expiring a fluxnode from the confirm map. FluxnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.hash.GetHex());
        }
    }

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

                auto it = g_fluxnodeCache.mapFluxnodeList.at(tier).listConfirmedFluxnodes.end();
                    while (--it != g_fluxnodeCache.mapFluxnodeList.at(tier).listConfirmedFluxnodes.begin()) {

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
    if (setAddToConfirm.size() || undoExpiredTiers.size() || removedTiers.size() || setRemoveFromList.size() || mapPaidNodes.size()) {

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
    if (data.nStatus == FLUXNODE_TX_STARTED) {
        mapStartTxTracker.insert(std::make_pair(data.collateralIn, data));
        if (!mapStartTxHeights.count(data.nAddedBlockHeight))
            mapStartTxHeights[data.nAddedBlockHeight] = std::set<COutPoint>();

        if (mapStartTxHeights.count(data.nAddedBlockHeight)) {
            mapStartTxHeights.at(data.nAddedBlockHeight).insert(data.collateralIn);
        }
    } else if (data.nStatus == FLUXNODE_TX_DOS_PROTECTION) {
        mapStartTxDosTracker.insert(std::make_pair(data.collateralIn, data));
        if (!mapStartTxDosHeights.count(data.nAddedBlockHeight))
            mapStartTxDosHeights[data.nAddedBlockHeight] = std::set<COutPoint>();

        if (mapStartTxDosHeights.count(data.nAddedBlockHeight)) {
            mapStartTxDosHeights.at(data.nAddedBlockHeight).insert(data.collateralIn);
        }
    } else if (data.nStatus == FLUXNODE_TX_CONFIRMED) {
        mapConfirmedFluxnodeData.insert(std::make_pair(data.collateralIn, data));
        InsertIntoList(data);
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
            mapFluxnodeList.at((Tier) p_fluxnodeData.nTier).setConfirmedTxInList.insert(p_fluxnodeData.collateralIn);
            mapFluxnodeList.at((Tier) p_fluxnodeData.nTier).listConfirmedFluxnodes.emplace_front(listData);
        }
    }
}

void FluxnodeCache::EraseFromListSet(const COutPoint& p_OutPoint)
{
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
        if (mapFluxnodeList.count((Tier) currentTier)) {
            if (mapFluxnodeList.at((Tier) currentTier).setConfirmedTxInList.count(p_OutPoint)) {
                mapFluxnodeList.at((Tier) currentTier).setConfirmedTxInList.erase(p_OutPoint);
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

void FluxnodeCache::DumpFluxnodeCache()
{
    LOCK(cs);
    bool found = false;
    for (auto item : setDirtyOutPoint) {
        found = false;
        if (mapStartTxTracker.count(item)) {
            found = true;
            pFluxnodeDB->WriteFluxnodeCacheData(mapStartTxTracker.at(item));
        } else if (mapStartTxDosTracker.count(item)) {
            found = true;
            pFluxnodeDB->WriteFluxnodeCacheData(mapStartTxDosTracker.at(item));
        } else if (mapConfirmedFluxnodeData.count(item)) {
            found = true;
            pFluxnodeDB->WriteFluxnodeCacheData(mapConfirmedFluxnodeData.at(item));
        }

        if (!found) {
            pFluxnodeDB->EraseFluxnodeCacheData(item);
        }
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

    if (fHalvingActive) {
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

    std::string printme2 = "{ \n";
    if (g_fluxnodeCache.mapStartTxHeights.count(nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT)) {
        for (const auto &printitem: g_fluxnodeCache.mapStartTxHeights.at(nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT)) {
            printme2 = printme2 + printitem.ToFullString() + ",\n";
        }
        printme2 = printme2 + "}";
    }

    std::string printme3 = "{ \n";
    for (const auto &printitem: g_fluxnodeCache.mapStartTxDosTracker) {
        printme3 = printme3 + printitem.first.ToFullString() + "," + printitem.second.ToFullString() + ",\n";
    }
    printme3 = printme3 + "}";

    std::string printme4 = "{ \n";
    if (g_fluxnodeCache.mapStartTxDosHeights.count(nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT)) {
        for (const auto &printitem: g_fluxnodeCache.mapStartTxDosHeights.at(nHeight - FLUXNODE_START_TX_EXPIRATION_HEIGHT)) {
            printme4 = printme4 + printitem.ToFullString() + ",\n";
        }
        printme4 = printme4 + "}";
    }

    if (fFromDisconnect) {
        LogPrintf("Disconnecting - printing after block=%d, hash=%s\n, mapStart=%s\n\n mapStartTxheights=%s\n\n, mapStartTxDosTracker=%s\n\n, mapStartTxDosHeights=%s\n\n",
                  nHeight, blockhash.GetHex(), printme, printme2, printme3, printme4);
    } else {
        LogPrintf("printing after block=%d, hash=%s\n, mapStart=%s\n\n mapStartTxheights=%s\n\n, mapStartTxDosTracker=%s\n\n, mapStartTxDosHeights=%s\n\n",
                  nHeight, blockhash.GetHex(), printme, printme2, printme3, printme4);
    }

}
/** Fluxnode Tier code end **/
