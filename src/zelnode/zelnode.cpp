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

ZelnodeCache g_zelnodeCache;

// Keep track of the active Zelnode
ActiveZelnode activeZelnode;

COutPoint zelnodeOutPoint;

std::string TierToString(int tier)
{
    std::string strStatus = "NONE";

    if (tier == CUMULUS) strStatus = "CUMULUS";
    if (tier == NIMBUS) strStatus = "NIMBUS";
    if (tier == STRATUS) strStatus = "STRATUS";

    if (strStatus == "NONE" && tier != 0) strStatus = "UNKNOWN TIER (" + std::to_string(tier) + ")";

    return strStatus;
}

bool CheckZelnodeTxSignatures(const CTransaction&  transaction)
{
    if (transaction.nType & ZELNODE_START_TX_TYPE) {
        // We need to sign the mutable transaction

        std::string errorMessage;

        std::string strMessage = transaction.GetHash().GetHex();

        if (!obfuScationSigner.VerifyMessage(transaction.collateralPubkey, transaction.sig, strMessage, errorMessage))
            return error("%s - START Error: %s", __func__, errorMessage);

        return true;
    } else if (transaction.nType & ZELNODE_CONFIRM_TX_TYPE) {

        auto data = g_zelnodeCache.GetZelnodeData(transaction.collateralOut);
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
    std::string public_key = GetZelnodeBenchmarkPublicKey(transaction);
    CPubKey pubkey(ParseHex(public_key));
    std::string errorMessage = "";
    std::string strMessage = std::string(transaction.sig.begin(), transaction.sig.end()) + std::to_string(transaction.benchmarkTier) + std::to_string(transaction.benchmarkSigTime) + transaction.ip;

    if (!obfuScationSigner.VerifyMessage(pubkey, transaction.benchmarkSig, strMessage, errorMessage))
        return error("%s - Error: %s", __func__, errorMessage);

    return true;
}

void GetUndoDataForExpiredZelnodeDosScores(CZelnodeTxBlockUndo& p_zelnodeTxUndoData, const int& p_nHeight)
{
    LOCK(g_zelnodeCache.cs);
    int nUndoHeight = p_nHeight - ZELNODE_DOS_REMOVE_AMOUNT;

    if (g_zelnodeCache.mapStartTxDosHeights.count(nUndoHeight)) {
        for (const auto& item : g_zelnodeCache.mapStartTxDosHeights.at(nUndoHeight)) {
            if (g_zelnodeCache.mapStartTxDosTracker.count(item))
                p_zelnodeTxUndoData.vecExpiredDosData.emplace_back(g_zelnodeCache.mapStartTxDosTracker.at(item));
        }
    }
}

void GetUndoDataForExpiredConfirmZelnodes(CZelnodeTxBlockUndo& p_zelnodeTxUndoData, const int& p_nHeight, const std::set<COutPoint> setSpentOuts)
{
    LOCK(g_zelnodeCache.cs);
    int nExpirationCount = GetZelnodeExpirationCount(p_nHeight);
    int nHeightToExpire = p_nHeight - nExpirationCount;

    for (const auto& item : g_zelnodeCache.mapConfirmedZelnodeData) {
        // The p_zelnodeTxUndoData has a map of all new confirms that have been updated this block. So if it is in there don't expire it. They made it barely in time
        if (p_zelnodeTxUndoData.mapUpdateLastConfirmHeight.count(item.first))
            continue;
        if (item.second.nLastConfirmedBlockHeight < nHeightToExpire) {
            p_zelnodeTxUndoData.vecExpiredConfirmedData.emplace_back(item.second);
        }
    }

    for (const auto& out : setSpentOuts) {
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(out)) {
            LogPrint("dzelnode","%s : expiring spent output: %s\n", __func__, out.ToString());
            p_zelnodeTxUndoData.vecExpiredConfirmedData.emplace_back(g_zelnodeCache.mapConfirmedZelnodeData.at(out));
        }
    }
}

void GetUndoDataForPaidZelnodes(CZelnodeTxBlockUndo& zelnodeTxBlockUndo, ZelnodeCache& p_localCache)
{
    LOCK2(p_localCache.cs, g_zelnodeCache.cs);

    for (const auto& item : p_localCache.mapPaidNodes) {
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(item.second.second)) {
            zelnodeTxBlockUndo.mapLastPaidHeights[item.second.second] = g_zelnodeCache.mapConfirmedZelnodeData.at(item.second.second).nLastPaidHeight;
        }
    }
}

void ZelnodeCache::AddNewStart(const CTransaction& p_transaction, const int p_nHeight, int nTier)
{
    ZelnodeCacheData data;
    data.nStatus = ZELNODE_TX_STARTED;
    data.nType = ZELNODE_START_TX_TYPE;
    data.collateralIn = p_transaction.collateralOut;
    data.collateralPubkey = p_transaction.collateralPubkey;
    data.pubKey = p_transaction.pubKey;
    data.ip = p_transaction.ip;
    data.nLastPaidHeight = 0;
    data.nAddedBlockHeight = p_nHeight;
    data.nTier = nTier;

    LOCK(cs);
    mapStartTxTracker.insert(std::make_pair(p_transaction.collateralOut, data));
    setDirtyOutPoint.insert(p_transaction.collateralOut);
}

void ZelnodeCache::UndoNewStart(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    setUndoStartTx.insert(p_transaction.collateralOut);
    setUndoStartTxHeight = p_nHeight;
}

void ZelnodeCache::AddNewConfirm(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    setAddToConfirm.insert(std::make_pair(p_transaction.collateralOut, p_transaction.ip));
    setAddToConfirmHeight = p_nHeight;
}

void ZelnodeCache::UndoNewConfirm(const CTransaction& p_transaction)
{
    LOCK(cs);
    setUndoAddToConfirm.insert(p_transaction.collateralOut);
}

void ZelnodeCache::AddUpdateConfirm(const CTransaction& p_transaction, const int p_nHeight)
{
    LOCK(cs);
    setAddToUpdateConfirm.insert(std::make_pair(p_transaction.collateralOut, p_transaction.ip));
    setAddToUpdateConfirmHeight = p_nHeight;
}

bool ZelnodeCache::CheckIfStarted(const COutPoint& out)
{
    LOCK(cs);
    if (mapStartTxTracker.count(out)) {
        return true;
    }

    LogPrint("dzelnode", "%s :  Initial Confirm tx, fail because outpoint %s is not in the mapStartTxTracker\n", __func__, out.ToString());
    return false;
}

bool ZelnodeCache::CheckIfConfirmed(const COutPoint& out)
{
    LOCK(cs);
    // We use the map here because the set contains list data that might have expired. the map doesn't
    if (mapConfirmedZelnodeData.count(out)) {
        return true;
    }

    return false;
}

bool ZelnodeCache::CheckUpdateHeight(const CTransaction& p_transaction, const int p_nHeight)
{
    int nCurrentHeight;
    if (p_nHeight)
        nCurrentHeight = p_nHeight;
    else
        nCurrentHeight = chainActive.Height();

    COutPoint out = p_transaction.collateralOut;
    if (!p_transaction.IsZelnodeTx()) {
        return false;
    }

    // This function should only be called on UPDATE_CONFIRM tx types
    if (p_transaction.nUpdateType != ZelnodeUpdateType::UPDATE_CONFIRM) {
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

bool ZelnodeCache::CheckNewStartTx(const COutPoint& out)
{
    LOCK(cs);
    if (mapStartTxTracker.count(out)) {
        LogPrint("dzelnode", "%s :  Failed because it is in the mapStartTxTracker: %s\n", __func__, out.ToString());
        return false;
    }

    if (mapStartTxDosTracker.count(out)) {
        LogPrint("dzelnode", "%s :  Failed because it is in the mapStartTxDosTracker: %s\n", __func__, out.ToString());
        return false;
    }

    return true;
}

void ZelnodeCache::CheckForExpiredStartTx(const int& p_nHeight)
{
    LOCK2(cs, g_zelnodeCache.cs);
    int removalHeight = p_nHeight - ZELNODE_START_TX_EXPIRATION_HEIGHT;

    std::vector<COutPoint> vecOutPoints;
    std::set<COutPoint> setNewDosHeights;
    if (g_zelnodeCache.mapStartTxHeights.count(removalHeight)) {
        for (const auto& item: g_zelnodeCache.mapStartTxHeights.at(removalHeight)) {
            // The start transaction might have been confirmed in this block. If it was the outpoint would be in the setAddToConfirm. Skip it
            if (setAddToConfirm.count(item))
                continue;

            ZelnodeCacheData data = g_zelnodeCache.mapStartTxTracker.at(item);
            data.nStatus = ZELNODE_TX_DOS_PROTECTION;
            mapStartTxDosTracker[item] = data;

            setNewDosHeights.insert(item);
        }

        if (setNewDosHeights.size())
            mapStartTxDosHeights[removalHeight] = setNewDosHeights;
    }

    LogPrint("dzelnode", "%s : Size of mapStartTxTracker: %s\n", __func__, g_zelnodeCache.mapStartTxTracker.size());
    LogPrint("dzelnode", "%s : Size of mapStartTxDosTracker: %s\n", __func__, g_zelnodeCache.mapStartTxDosTracker.size());
    LogPrint("dzelnode", "%s : Size of mapConfirmedZelnodeData: %s\n", __func__, g_zelnodeCache.mapConfirmedZelnodeData.size());
}

void ZelnodeCache::CheckForUndoExpiredStartTx(const int& p_nHeight)
{
    LOCK2(cs, g_zelnodeCache.cs);
    int removalHeight = p_nHeight - ZELNODE_START_TX_EXPIRATION_HEIGHT;

    if (g_zelnodeCache.mapStartTxDosHeights.count(removalHeight)) {
        for (const auto& item : g_zelnodeCache.mapStartTxDosHeights.at(removalHeight)) {
            mapStartTxTracker.insert(std::make_pair(item, g_zelnodeCache.mapStartTxDosTracker.at(item)));
            mapStartTxTracker.at(item).nStatus = ZELNODE_TX_STARTED;
            mapStartTxHeights[removalHeight].insert(item);

            mapDoSToUndo[removalHeight].insert(item);
        }
    }

    LogPrint("dzelnode", "%s : Size of mapStartTxTracker: %s\n", __func__, g_zelnodeCache.mapStartTxTracker.size());
    LogPrint("dzelnode", "%s : Size of mapStartTxDosTracker: %s\n", __func__, g_zelnodeCache.mapStartTxDosTracker.size());
    LogPrint("dzelnode","%s : Size of mapConfirmedZelnodeData: %s\n", __func__, g_zelnodeCache.mapConfirmedZelnodeData.size());
}


bool ZelnodeCache::CheckConfirmationHeights(const int nCurrentHeight, const COutPoint& out, const std::string& ip) {
    if (!mapConfirmedZelnodeData.count(out)) {
        return false;
    }

    auto data = g_zelnodeCache.GetZelnodeData(out);
    if (data.IsNull()) {
        return false;
    }

    bool fFluxActive = NetworkUpgradeActive(nCurrentHeight, Params().GetConsensus(), Consensus::UPGRADE_FLUX);
    // Allow ip address changes at a different interval
    if (fFluxActive) {
        if (ip != data.ip) {
            if (nCurrentHeight - mapConfirmedZelnodeData.at(out).nLastConfirmedBlockHeight >= ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE) {
                return true;
            }
        }
    }

    if (nCurrentHeight - mapConfirmedZelnodeData.at(out).nLastConfirmedBlockHeight <= ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT) {
        // TODO - Remove this error message after release + 1 month and we don't see any problems
        error("%s - %d - Confirmation to soon - %s -> Current Height: %d, lastConfirmed: %d\n", __func__,
              __LINE__,
              out.ToFullString(), nCurrentHeight, mapConfirmedZelnodeData.at(out).nLastConfirmedBlockHeight);
        return false;
    }

    return true;
}

bool ZelnodeCache::InStartTracker(const COutPoint& out)
{
    LOCK(cs);
    return mapStartTxTracker.count(out);
}

bool ZelnodeCache::InDoSTracker(const COutPoint& out)
{
    LOCK(cs);
    return mapStartTxDosTracker.count(out);
}

bool ZelnodeCache::InConfirmTracker(const COutPoint& out)
{
    LOCK(cs);
    return mapConfirmedZelnodeData.count(out);
}

bool ZelnodeCache::CheckIfNeedsNextConfirm(const COutPoint& out)
{
    LOCK(cs);
    if (mapConfirmedZelnodeData.count(out)) {
        return chainActive.Height() - mapConfirmedZelnodeData.at(out).nLastConfirmedBlockHeight > ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT;
    }

    return false;
}

ZelnodeCacheData ZelnodeCache::GetZelnodeData(const CTransaction& tx)
{
    return GetZelnodeData(tx.collateralOut);
}

ZelnodeCacheData ZelnodeCache::GetZelnodeData(const COutPoint& out, int* nNeedLocation)
{
    LOCK(cs);
    if (mapStartTxTracker.count(out)) {
        if (nNeedLocation) *nNeedLocation = ZELNODE_TX_STARTED;
        return mapStartTxTracker.at(out);
    } else if (mapStartTxDosTracker.count(out)) {
        if (nNeedLocation) *nNeedLocation = ZELNODE_TX_DOS_PROTECTION;
        return mapStartTxDosTracker.at(out);
    } else if (mapConfirmedZelnodeData.count(out)) {
        if (nNeedLocation) *nNeedLocation = ZELNODE_TX_CONFIRMED;
        return mapConfirmedZelnodeData.at(out);
    }

    ZelnodeCacheData data;
    return data;
}

bool ZelnodeCache::GetNextPayment(CTxDestination& dest, int nTier, COutPoint& p_zelnodeOut)
{
    if (nTier == CUMULUS || nTier == NIMBUS || nTier == STRATUS) {
        LOCK(cs);
        int setSize = mapZelnodeList.at(nTier).setConfirmedTxInList.size();
        if (setSize) {
            for (int i = 0; i < setSize; i++) {
                if (mapZelnodeList.at(nTier).listConfirmedZelnodes.size()) {
                    p_zelnodeOut = mapZelnodeList.at(nTier).listConfirmedZelnodes.front().out;
                    if (mapConfirmedZelnodeData.count(p_zelnodeOut)) {
                        dest = mapConfirmedZelnodeData.at(p_zelnodeOut).collateralPubkey.GetID();
                        return true;
                    } else {
                        // The front of the list, wasn't in the confirmed zelnode data. These means it expired
                        mapZelnodeList.at(nTier).listConfirmedZelnodes.pop_front();
                        mapZelnodeList.at(nTier).setConfirmedTxInList.erase(p_zelnodeOut);
                    }
                } else {
                    return false;
                }
            }
        }
    }

    return false;
}

bool ZelnodeCache::CheckZelnodePayout(const CTransaction& coinbase, const int p_Height, ZelnodeCache* p_zelnodeCache)
{
    LOCK(cs);
    CTxDestination basic_dest;
    CTxDestination super_dest;
    CTxDestination bamf_dest;
    bool fCUMULUSFound = false;
    bool fNIMBUSFound = false;
    bool fSTRATUSFound = false;
    CScript basic_script;
    CScript super_script;
    CScript bamf_script;

    COutPoint basic_out;
    COutPoint super_out;
    COutPoint bamf_out;

    // Get the addresses the should be paid
    if (GetNextPayment(basic_dest, CUMULUS, basic_out)) {
        fCUMULUSFound = true;
    }

    // Get the addresses the should be paid
    if (GetNextPayment(super_dest, NIMBUS, super_out)) {
        fNIMBUSFound = true;
    }

    // Get the addresses the should be paid
    if (GetNextPayment(bamf_dest, STRATUS, bamf_out)) {
        fSTRATUSFound = true;
    }

    if (fCUMULUSFound) basic_script = GetScriptForDestination(basic_dest);
    if (fNIMBUSFound) super_script = GetScriptForDestination(super_dest);
    if (fSTRATUSFound) bamf_script = GetScriptForDestination(bamf_dest);

    // Get the amounts that should be paid per address
    CAmount blockValue = GetBlockSubsidy(p_Height, Params().GetConsensus());
    CAmount basic_amount = GetZelnodeSubsidy(p_Height, blockValue, CUMULUS);
    CAmount super_amount = GetZelnodeSubsidy(p_Height, blockValue, NIMBUS);
    CAmount bamf_amount = GetZelnodeSubsidy(p_Height, blockValue, STRATUS);

    bool fCUMULUSApproved = false;
    bool fNIMBUSApproved = false;
    bool fSTRATUSApproved = false;

    // Loop through Tx to make sure they all got paid
    for (const auto& out : coinbase.vout) {
        if (fCUMULUSFound)
            if (out.scriptPubKey == basic_script)
                if (out.nValue == basic_amount)
                    fCUMULUSApproved = true;

        if (fNIMBUSFound)
            if (out.scriptPubKey == super_script)
                if (out.nValue == super_amount)
                    fNIMBUSApproved = true;

        if (fSTRATUSFound)
            if (out.scriptPubKey == bamf_script)
                if (out.nValue == bamf_amount)
                    fSTRATUSApproved = true;
    }

    bool fFail = false;
    if (fCUMULUSFound && !fCUMULUSApproved) {
        fFail = true;
        error("Invalid block zelnode payee list: Invalid CUMULUS payee. Should be paying : %s -> %u", EncodeDestination(basic_dest), basic_amount);
    }

    if (fNIMBUSFound && !fNIMBUSApproved) {
        fFail = true;
        error("Invalid block zelnode payee list: Invalid NIMBUS payee. Should be paying : %s -> %u", EncodeDestination(super_dest), super_amount);
    }

    if (fSTRATUSFound && !fSTRATUSApproved) {
        fFail = true;
        error("Invalid block zelnode payee list: Invalid STRATUS payee. Should be paying : %s -> %u", EncodeDestination(bamf_dest), bamf_amount);
    }

    if (p_zelnodeCache) {
        if (fCUMULUSFound)
            p_zelnodeCache->AddPaidNode(basic_out, p_Height);
        if (fNIMBUSFound)
            p_zelnodeCache->AddPaidNode(super_out, p_Height);
        if (fSTRATUSFound)
            p_zelnodeCache->AddPaidNode(bamf_out, p_Height);
    }

    return !fFail;
}

void FillBlockPayeeWithDeterministicPayouts(CMutableTransaction& txNew, CAmount nFees, std::map<int, std::pair<CScript, CAmount>>* payments)
{
    CBlockIndex* pindexPrev = chainActive.Tip();

    CTxDestination basic_dest;
    CTxDestination super_dest;
    CTxDestination bamf_dest;
    bool fCUMULUSFound = true;
    bool fNIMBUSFound = true;
    bool fSTRATUSFound = true;

    COutPoint basic_out;
    COutPoint super_out;
    COutPoint bamf_out;

    int nTotalPayouts = 3; // Total number of zelnode payments there could be

    if (!g_zelnodeCache.GetNextPayment(basic_dest, CUMULUS, basic_out)) {
        fCUMULUSFound = false;
        nTotalPayouts--;
    }

    if (!g_zelnodeCache.GetNextPayment(super_dest, NIMBUS, super_out)) {
        fNIMBUSFound = false;
        nTotalPayouts--;
    }

    if (!g_zelnodeCache.GetNextPayment(bamf_dest, STRATUS, bamf_out)) {
        fSTRATUSFound = false;
        nTotalPayouts--;
    }

    CAmount blockValue = GetBlockSubsidy(pindexPrev->nHeight + 1, Params().GetConsensus());
    CAmount basic_amount = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, CUMULUS);
    CAmount super_amount = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, NIMBUS);
    CAmount bamf_amount = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, STRATUS);

    if (nTotalPayouts > 0) {
        txNew.vout.resize(nTotalPayouts + 1);
    }

    CAmount nMinerReward = blockValue;
    int currentIndex = 1;
    if (fCUMULUSFound) {
        txNew.vout[currentIndex].scriptPubKey = GetScriptForDestination(basic_dest);
        txNew.vout[currentIndex].nValue = basic_amount;
        nMinerReward -= basic_amount;
        currentIndex++;

        if (payments)
            payments->insert(std::make_pair(CUMULUS, std::make_pair(GetScriptForDestination(basic_dest), basic_amount)));
    }

    if (fNIMBUSFound) {
        txNew.vout[currentIndex].scriptPubKey = GetScriptForDestination(super_dest);
        txNew.vout[currentIndex].nValue = super_amount;
        nMinerReward -= super_amount;
        currentIndex++;

        if (payments)
            payments->insert(std::make_pair(NIMBUS, std::make_pair(GetScriptForDestination(super_dest), super_amount)));
    }

    if (fSTRATUSFound) {
        txNew.vout[currentIndex].scriptPubKey = GetScriptForDestination(bamf_dest);
        txNew.vout[currentIndex].nValue = bamf_amount;
        nMinerReward -= bamf_amount;

        if (payments)
            payments->insert(std::make_pair(STRATUS, std::make_pair(GetScriptForDestination(bamf_dest), bamf_amount)));
    }

    txNew.vout[0].nValue = nMinerReward;

    LogPrint("dzelnode","Zelnode CUMULUS payment of %s to %s\n", FormatMoney(basic_amount).c_str(), EncodeDestination(basic_dest).c_str());
    LogPrint("dzelnode","Zelnode NIMBUS payment of %s to %s\n", FormatMoney(super_amount).c_str(), EncodeDestination(super_dest).c_str());
    LogPrint("dzelnode","Zelnode STRATUS payment of %s to %s\n", FormatMoney(bamf_amount).c_str(), EncodeDestination(bamf_dest).c_str());
}


void ZelnodeCache::AddExpiredDosTx(const CZelnodeTxBlockUndo& p_undoData, const int p_nHeight)
{
    LOCK(cs);
    std::set<COutPoint> setOutPoint;
    for (const auto& item : p_undoData.vecExpiredDosData) {
        setOutPoint.insert(item.collateralIn);
    }
    mapDosExpiredToRemove[p_nHeight] = setOutPoint;
}

void ZelnodeCache::AddExpiredConfirmTx(const CZelnodeTxBlockUndo& p_undoData)
{
    LOCK(cs);
    for (const auto& item : p_undoData.vecExpiredConfirmedData) {
        setExpireConfirmOutPoints.insert(item.collateralIn);
    }
}

void ZelnodeCache::AddPaidNode(const COutPoint& out, const int p_Height)
{
    // This is being called from ConnectBlock, from function CheckZelnodePayout
    // the g_zelnodeCache cs has already been locked

    if (g_zelnodeCache.mapConfirmedZelnodeData.count(out)) {
        LOCK(cs); // Lock local cache
        mapPaidNodes[g_zelnodeCache.mapConfirmedZelnodeData.at(out).nTier] = std::make_pair(p_Height, out);
    }
}

void ZelnodeCache::AddBackUndoData(const CZelnodeTxBlockUndo& p_undoData)
{
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
        LOCK(g_zelnodeCache.cs);
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(item.first)) {
            mapConfirmedZelnodeData[item.first] = g_zelnodeCache.mapConfirmedZelnodeData.at(item.first);
            mapConfirmedZelnodeData[item.first].nLastConfirmedBlockHeight = item.second;
        } else {
            if (!fIsVerifying)
                error("%s : This should never happen. When undo an update confirm nLastConfirmedBlockHeight . ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n",
                  __func__, item.first.hash.GetHex());
        }
    }

    // Undo the Confirm Update trasnaction back to the old ipAddresses
    for (const auto& item : p_undoData.mapLastIpAddress) {
        LOCK(g_zelnodeCache.cs);
        // Because we might have already retrieved the zelnode global data above when adding back the nLastConfirmedBlockHeight
        // We don't want to override the nLastConfirmedBlockHeight change above
        if (mapConfirmedZelnodeData.count(item.first)) {
            mapConfirmedZelnodeData[item.first].ip = item.second;
        } else if (g_zelnodeCache.mapConfirmedZelnodeData.count(item.first)) {
            mapConfirmedZelnodeData[item.first] = g_zelnodeCache.mapConfirmedZelnodeData.at(item.first);
            mapConfirmedZelnodeData[item.first].ip = item.second;
        } else {
            if (!fIsVerifying)
                error("%s : This should never happen. When undo an update confirm ip address. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n",
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

bool ZelnodeCache::Flush()
{
    std::set<COutPoint> fullList;
    int height = 0;

    std::set<COutPoint> setRemoveFromList;

    std::vector<ZelnodeCacheData> vecNodesToAdd;

    LOCK2(cs, g_zelnodeCache.cs);
    //! Add new start transactions to the tracker
    for (auto item : mapStartTxTracker) {
        height = item.second.nAddedBlockHeight;
        g_zelnodeCache.mapStartTxTracker.insert(std::make_pair(item.first, item.second));
        fullList.insert(item.first);

        g_zelnodeCache.setDirtyOutPoint.insert(item.first);
    }

    if (fullList.size())
        g_zelnodeCache.mapStartTxHeights.insert(std::make_pair(height, fullList));


    //! If a start transaction isn't confirmed in time, the OutPoint is added to the dos tracker
    for (auto item : mapStartTxDosTracker) {
        g_zelnodeCache.mapStartTxDosTracker[item.first] = item.second;
        g_zelnodeCache.mapStartTxTracker.erase(item.first);
        g_zelnodeCache.setDirtyOutPoint.insert(item.first);
    }

    for (auto item : mapStartTxDosHeights) {
        g_zelnodeCache.mapStartTxDosHeights[item.first] = item.second;
        g_zelnodeCache.mapStartTxHeights.erase(item.first);
    }

    //! After the threshhold is met, remove the DoS OutPoints from being banned
    for (auto item : mapDosExpiredToRemove) {
        for (const auto& data : item.second) {
            g_zelnodeCache.mapStartTxDosTracker.erase(data);
            g_zelnodeCache.setDirtyOutPoint.insert(data);
        }
        g_zelnodeCache.mapStartTxDosHeights.erase(item.first);
    }

    //! If we are undo a block, and we undid a block that had Start transaction in it
    for (const auto& item : mapDoSToUndo) {
        for (const auto& out : item.second)
            g_zelnodeCache.mapStartTxDosTracker.erase(out);

        g_zelnodeCache.mapStartTxDosHeights.erase(item.first);
    }

    //! If we are undo a block, and we undid a block that confirmed an Update transaction. We need to undo the update, which just updated the nLastConfirmBlockHeight
    for (const auto& item : mapConfirmedZelnodeData) {
        g_zelnodeCache.mapConfirmedZelnodeData[item.first].nLastConfirmedBlockHeight = item.second.nLastConfirmedBlockHeight;
        g_zelnodeCache.mapConfirmedZelnodeData[item.first].ip = item.second.ip;
        g_zelnodeCache.setDirtyOutPoint.insert(item.first);
    }

    bool fUndoExpiredAddedToList = false;
    bool fUndoExpiredAddedToListCUMULUS = false;
    bool fUndoExpiredAddedToListNIMBUS = false;
    bool fUndoExpiredAddedToListSTRATUS = false;
    for (const auto& item : setUndoExpireConfirm) {
        g_zelnodeCache.mapConfirmedZelnodeData.insert(std::make_pair(item.collateralIn, item));
        g_zelnodeCache.setDirtyOutPoint.insert(item.collateralIn);

        if (g_zelnodeCache.CheckListHas(item)) {
            // already in set, and therefor list. Skip it
            continue;
        } else {
            vecNodesToAdd.emplace_back(item);
            if (item.nTier == CUMULUS) fUndoExpiredAddedToListCUMULUS = true;
            else if (item.nTier == NIMBUS) fUndoExpiredAddedToListNIMBUS = true;
            else if (item.nTier == STRATUS) fUndoExpiredAddedToListSTRATUS = true;
            fUndoExpiredAddedToList = true;
        }
    }

    //! If we are undo a block, and we undid a block that had Start transaction in it
    for (const auto& item : setUndoStartTx) {
        g_zelnodeCache.mapStartTxTracker.erase(item);
        g_zelnodeCache.setDirtyOutPoint.insert(item);
    }

    if (setUndoStartTxHeight > 0)
        g_zelnodeCache.mapStartTxDosHeights.erase(setUndoStartTxHeight);

    bool fRemoveCUMULUS = false;
    bool fRemoveNIMBUS = false;
    bool fRemoveSTRATUS = false;

    //! Add the data from Zelnodes that got confirmed this block
    for (const auto& item : setAddToConfirm) {
        // Take the zelnodedata from the mapStartTxTracker and move it to the mapConfirm
        if (g_zelnodeCache.mapStartTxTracker.count(item.first)) {
            ZelnodeCacheData data = g_zelnodeCache.mapStartTxTracker.at(item.first);

            // Remove from Start Tracking
            g_zelnodeCache.mapStartTxTracker.erase(item.first);
            g_zelnodeCache.mapStartTxHeights.at(data.nAddedBlockHeight).erase(item.first);

            // Update the data (STARTED --> CONFIRM)
            data.nStatus = ZELNODE_TX_CONFIRMED;
            data.nConfirmedBlockHeight = setAddToConfirmHeight;
            data.nLastConfirmedBlockHeight = setAddToConfirmHeight;

            data.nLastPaidHeight = 0;
            data.ip = item.second;

            // Add the data to the confirm trackers
            g_zelnodeCache.mapConfirmedZelnodeData.insert(std::make_pair(data.collateralIn, data));

            // Because we don't automatically remove nodes that have expired from the list, to help not sort it as often
            // If this node is already in the list. We wont add it let. We need to wait for the node to be removed from the list.
            // Then we can add it to the list
            if (g_zelnodeCache.mapZelnodeList.at(data.nTier).setConfirmedTxInList.count(data.collateralIn)) {
                setRemoveFromList.insert(data.collateralIn);
                if (data.nTier == CUMULUS) {
                    fRemoveCUMULUS = true;
                } else if (data.nTier == NIMBUS) {
                    fRemoveNIMBUS = true;
                } else if (data.nTier == STRATUS) {
                    fRemoveSTRATUS = true;
                }
            }

            // TODO, once we are running smoothly. We should be able to place into a list, sort the list. Add add the nodes in order that is is sorted.
            // TODO, if we do this, we should be able to not sort the list, if we only add new confirmed nodes to it.
            vecNodesToAdd.emplace_back(data);

            if (data.nTier == CUMULUS) fUndoExpiredAddedToListCUMULUS = true;
            else if (data.nTier == NIMBUS) fUndoExpiredAddedToListNIMBUS = true;
            else if (data.nTier == STRATUS) fUndoExpiredAddedToListSTRATUS = true;

            g_zelnodeCache.setDirtyOutPoint.insert(item.first);
        } else {
            error("%s : This should never happen. When moving from start map to confirm map. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__,  item.first.hash.GetHex());
        }
    }


    for (const auto& item : setUndoAddToConfirm) {
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(item)) {
            ZelnodeCacheData data = g_zelnodeCache.mapConfirmedZelnodeData.at(item);

            // Remove from Confirm Tracking
            g_zelnodeCache.mapConfirmedZelnodeData.erase(item);

            // adding it to this set, means that it will go and remove the outpoint from the list, and the set if it is in there
            setRemoveFromList.insert(data.collateralIn);

            if (data.nTier == CUMULUS) fRemoveCUMULUS = true;
            else if (data.nTier == CUMULUS) fRemoveNIMBUS = true;
            else if (data.nTier == CUMULUS) fRemoveSTRATUS = true;

            // Update the data (CONFIRM --> STARTED)
            data.nStatus = ZELNODE_TX_STARTED;
            data.nConfirmedBlockHeight = 0;
            data.nLastConfirmedBlockHeight = 0;
            data.nLastPaidHeight = 0;
            data.ip = "";

            // Add the data back into the Start tracker
            g_zelnodeCache.mapStartTxTracker.insert(std::make_pair(item, data));
            g_zelnodeCache.mapStartTxHeights[data.nAddedBlockHeight].insert(item);

            g_zelnodeCache.setDirtyOutPoint.insert(item);

            // IMPORTANT: We don't update the list of zelnodes. Because if we wanted to, we would have to scan through the list until we found the OutPoint that matches
            // Instead we leave the list untouched, and when seeing who to pay next. We check the setConfirmedTxInList to verify they are still confirmed
            // If they aren't confirmed, we will just keep poping the top of the list until we find one that is

        } else {
            error("%s : This should never happen. When moving from confirm map to start map. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.hash.GetHex());
        }
    }

    //! Update the data for Zelnodes that got the confirmed update this block
    for (const auto& item : setAddToUpdateConfirm) {
        // Take the zelnodedata from the mapStartTxTracker and move it to the mapConfirm
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(item.first)) {

            // Update the nLastConfirmedBlockHeight
            g_zelnodeCache.mapConfirmedZelnodeData.at(item.first).nLastConfirmedBlockHeight = setAddToUpdateConfirmHeight;

            // Update IP address
            g_zelnodeCache.mapConfirmedZelnodeData.at(item.first).ip = item.second;

            g_zelnodeCache.setDirtyOutPoint.insert(item.first);
        } else {
            error("%s : This should never happen. When updating a zelnode from the confirm map. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.first.hash.GetHex());
        }
    }

    //! Expire the confirm transactions that haven't been updated in time
    for (const auto& item : setExpireConfirmOutPoints) {
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(item)) {

            // Erase the data from the map and set
            g_zelnodeCache.mapConfirmedZelnodeData.erase(item);

            // IMPORTANT:: the item stays in the list and the set. This is because we don't want to have to resort the list everytime something expires.
            // Only when new added in added to the list.

            // Add the OutPoint to the dirty set, so it will be erased on database write
            g_zelnodeCache.setDirtyOutPoint.insert(item);
        } else {
            error("%s : This should never happen. When expiring a zelnode from the confirm map. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.hash.GetHex());
        }
    }

    for (const auto& item : mapPaidNodes) {
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(item.second.second)) {

            // Set the new last paid height
            g_zelnodeCache.mapConfirmedZelnodeData.at(item.second.second).nLastPaidHeight = item.second.first;
            g_zelnodeCache.setDirtyOutPoint.insert(item.second.second);

            if (g_zelnodeCache.mapZelnodeList.at(item.first).setConfirmedTxInList.count(item.second.second)) {
                if (g_zelnodeCache.mapZelnodeList.at(item.first).listConfirmedZelnodes.front().out == item.second.second) {
                    g_zelnodeCache.mapZelnodeList.at(item.first).listConfirmedZelnodes.pop_front();
                    ZelnodeListData newListData(g_zelnodeCache.mapConfirmedZelnodeData.at(item.second.second));

                    // Put
                    g_zelnodeCache.mapZelnodeList.at(item.first).listConfirmedZelnodes.emplace_back(newListData);
                } else {
                    error("%s : This should never happen. When checking the list of a paid node. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.second.second.hash.GetHex());
                }
            } else {
                error("%s : This should never happen. When adding a paid node. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.second.second.hash.GetHex());
            }
        }
    }

    for (const auto& item : mapUndoPaidNodes) {
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(item.first)) {
            // Set the height back to the last value
            g_zelnodeCache.mapConfirmedZelnodeData.at(item.first).nLastPaidHeight = item.second;
            g_zelnodeCache.setDirtyOutPoint.insert(item.first);

            int nTier = g_zelnodeCache.mapConfirmedZelnodeData.at(item.first).nTier;

            bool fFoundIt = false;
            if (g_zelnodeCache.mapZelnodeList.at(nTier).setConfirmedTxInList.count(item.first)) {

                auto it = g_zelnodeCache.mapZelnodeList.at(nTier).listConfirmedZelnodes.end();
                    while (--it != g_zelnodeCache.mapZelnodeList.at(nTier).listConfirmedZelnodes.begin()) {

                        if (it->out == item.first) {
                            // The node that we are undoing the paid height on, should always be near the last node in the list. So, we need
                            // to get the data. Remove the entry from near the back of the list, and put it at the front.
                            // This allows us to not have to sort() the list afterwards. If this was the only change
                            ZelnodeListData old_data = *it;
                            g_zelnodeCache.mapZelnodeList.at(nTier).listConfirmedZelnodes.erase(it);
                            old_data.nLastPaidHeight = item.second;
                            g_zelnodeCache.mapZelnodeList.at(nTier).listConfirmedZelnodes.emplace_front(old_data);
                            fFoundIt = true;
                            break;
                        }
                    }
                }

                if (!fFoundIt)
                    error("%s : This should never happen. When undoing a paid node. The back most item in the list isn't the correct outpoint. Report this to the dev team to figure out what is happening: %s\n",
                          __func__, item.first.hash.GetHex());
            } else {
                error("%s : This should never happen. When undoing a paid node. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n",
                      __func__, item.first.hash.GetHex());
            }
    }

    //! DO ALL REMOVAL FROM THE ITEMS IN THE LIST HERE (using iterators so we can remove items while going over the list a single time
    // Currently only have to do this when moving from CONFIRM->START (undo blocks only)
    if (setRemoveFromList.size()) {
        if (fRemoveCUMULUS) {
            g_zelnodeCache.EraseFromList(setRemoveFromList, CUMULUS);
        }

        if (fRemoveNIMBUS) {
            g_zelnodeCache.EraseFromList(setRemoveFromList, NIMBUS);
        }

        if (fRemoveSTRATUS ) {
            g_zelnodeCache.EraseFromList(setRemoveFromList, STRATUS);
        }
    }

    //! DO ALL ADDS TO THE LIST HERE
    if (vecNodesToAdd.size()) {
        // Add the list data to the sort zelnode list
        for (const auto& item : vecNodesToAdd)
            g_zelnodeCache.InsertIntoList(item);
    }

    //! ALWAYS THE LAST CALL IN THE FLUSH COMMAND
    // Always the last thing to do in the Flush. Sort the list if any data was added to it
    if (setAddToConfirm.size() || fUndoExpiredAddedToList || setRemoveFromList.size() || mapPaidNodes.size()) {
        if (fRemoveCUMULUS || fUndoExpiredAddedToListCUMULUS || mapPaidNodes.count(CUMULUS)) {
            g_zelnodeCache.SortList(CUMULUS);
        }

        if (fRemoveNIMBUS || fUndoExpiredAddedToListNIMBUS || mapPaidNodes.count(NIMBUS)) {
            g_zelnodeCache.SortList(NIMBUS);
        }

        if (fRemoveSTRATUS || fUndoExpiredAddedToListSTRATUS || mapPaidNodes.count(STRATUS)) {
            g_zelnodeCache.SortList(STRATUS);
        }
    }

    return true;
}

// Needs to be protected by locking cs before calling
bool ZelnodeCache::LoadData(ZelnodeCacheData& data)
{
    if (data.nStatus == ZELNODE_TX_STARTED) {
        mapStartTxTracker.insert(std::make_pair(data.collateralIn, data));
        if (!mapStartTxHeights.count(data.nAddedBlockHeight))
            mapStartTxHeights[data.nAddedBlockHeight] = std::set<COutPoint>();

        mapStartTxHeights.at(data.nAddedBlockHeight).insert(data.collateralIn);
    } else if (data.nStatus == ZELNODE_TX_DOS_PROTECTION) {
        mapStartTxDosTracker.insert(std::make_pair(data.collateralIn, data));
        if (!mapStartTxDosHeights.count(data.nAddedBlockHeight))
            mapStartTxDosHeights[data.nAddedBlockHeight] = std::set<COutPoint>();

        mapStartTxDosHeights.at(data.nAddedBlockHeight).insert(data.collateralIn);
    } else if (data.nStatus == ZELNODE_TX_CONFIRMED) {
        mapConfirmedZelnodeData.insert(std::make_pair(data.collateralIn, data));
        InsertIntoList(data);
    }

    return true;
}

// Needs to be protected by locking cs before calling
void ZelnodeCache::SortList(const int& nTier)
{
    if (nTier == CUMULUS)
        mapZelnodeList.at(CUMULUS).listConfirmedZelnodes.sort();
    else if (nTier == NIMBUS)
        mapZelnodeList.at(NIMBUS).listConfirmedZelnodes.sort();
    else if (nTier == STRATUS)
        mapZelnodeList.at(STRATUS).listConfirmedZelnodes.sort();
}

// Needs to be protected by locking cs before calling
bool ZelnodeCache::CheckListHas(const ZelnodeCacheData& p_zelnodeData)
{
    if (p_zelnodeData.nTier == CUMULUS)
        return mapZelnodeList.at(CUMULUS).setConfirmedTxInList.count(p_zelnodeData.collateralIn);
    else if (p_zelnodeData.nTier == NIMBUS)
        return mapZelnodeList.at(NIMBUS).setConfirmedTxInList.count(p_zelnodeData.collateralIn);
    else if (p_zelnodeData.nTier == STRATUS)
        return mapZelnodeList.at(STRATUS).setConfirmedTxInList.count(p_zelnodeData.collateralIn);

    return false;
}

// Needs to be protected by locking cs before calling
bool ZelnodeCache::CheckListSet(const COutPoint& p_OutPoint)
{
    if (mapZelnodeList.at(CUMULUS).setConfirmedTxInList.count(p_OutPoint)) {
        return true;
    } else if (mapZelnodeList.at(NIMBUS).setConfirmedTxInList.count(p_OutPoint)) {
        return true;
    } else if (mapZelnodeList.at(STRATUS).setConfirmedTxInList.count(p_OutPoint)) {
        return true;
    }

    return false;
}

void ZelnodeCache::InsertIntoList(const ZelnodeCacheData& p_zelnodeData)
{
    ZelnodeListData listData(p_zelnodeData);
    if (p_zelnodeData.nTier == CUMULUS) {
        mapZelnodeList.at(CUMULUS).setConfirmedTxInList.insert(p_zelnodeData.collateralIn);
        mapZelnodeList.at(CUMULUS).listConfirmedZelnodes.emplace_front(listData);
    }
    else if (p_zelnodeData.nTier == NIMBUS) {
        mapZelnodeList.at(NIMBUS).setConfirmedTxInList.insert(p_zelnodeData.collateralIn);
        mapZelnodeList.at(NIMBUS).listConfirmedZelnodes.emplace_front(listData);
    }
    else if (p_zelnodeData.nTier == STRATUS) {
        mapZelnodeList.at(STRATUS).setConfirmedTxInList.insert(p_zelnodeData.collateralIn);
        mapZelnodeList.at(STRATUS).listConfirmedZelnodes.emplace_front(listData);
    }
}

void ZelnodeCache::EraseFromListSet(const COutPoint& p_OutPoint)
{
    if (mapZelnodeList.at(CUMULUS).setConfirmedTxInList.count(p_OutPoint))
        mapZelnodeList.at(CUMULUS).setConfirmedTxInList.erase(p_OutPoint);
    else if (mapZelnodeList.at(NIMBUS).setConfirmedTxInList.count(p_OutPoint))
        mapZelnodeList.at(NIMBUS).setConfirmedTxInList.erase(p_OutPoint);
    else if (mapZelnodeList.at(STRATUS).setConfirmedTxInList.count(p_OutPoint))
        mapZelnodeList.at(STRATUS).setConfirmedTxInList.erase(p_OutPoint);
}

void ZelnodeCache::EraseFromList(const std::set<COutPoint>& setToRemove, const int nTier)
{
    std::list<ZelnodeListData>::iterator i = mapZelnodeList.at(nTier).listConfirmedZelnodes.begin();
    while (i != mapZelnodeList.at(nTier).listConfirmedZelnodes.end())
    {
        bool isDataToRemove = setToRemove.count((*i).out);
        if (isDataToRemove)
        {
            mapZelnodeList.at(nTier).setConfirmedTxInList.erase((*i).out);
            mapZelnodeList.at(nTier).listConfirmedZelnodes.erase(i++);  // alternatively, i = items.erase(i);
        }
        else
        {
            ++i;
        }
    }
}

void ZelnodeCache::DumpZelnodeCache()
{
    LOCK(cs);
    bool found = false;
    for (auto item : setDirtyOutPoint) {
        found = false;
        if (mapStartTxTracker.count(item)) {
            found = true;
            pZelnodeDB->WriteZelnodeCacheData(mapStartTxTracker.at(item));
        } else if (mapStartTxDosTracker.count(item)) {
            found = true;
            pZelnodeDB->WriteZelnodeCacheData(mapStartTxDosTracker.at(item));
        } else if (mapConfirmedZelnodeData.count(item)) {
            found = true;
            pZelnodeDB->WriteZelnodeCacheData(mapConfirmedZelnodeData.at(item));
        }

        if (!found) {
            pZelnodeDB->EraseZelnodeCacheData(item);
        }
    }
}

bool IsDZelnodeActive()
{
    return chainActive.Height() >= Params().StartZelnodePayments();
}

bool IsZelnodeTransactionsActive()
{
    return chainActive.Height() >= Params().GetConsensus().vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight;
}

std::string ZelnodeLocationToString(int nLocation) {
    if (nLocation == ZELNODE_TX_ERROR) {
        return "OFFLINE";
    } else if (nLocation == ZELNODE_TX_STARTED) {
        return "STARTED";
    } else if (nLocation == ZELNODE_TX_DOS_PROTECTION) {
        return "DOS";
    } else if (nLocation == ZELNODE_TX_CONFIRMED) {
        return "CONFIRMED";
    } else {
        return "OFFLINE";
    }
}

void ZelnodeCache::CountNetworks(int& ipv4, int& ipv6, int& onion, int& nCUMULUS, int& nNIMBUS, int& nStratus) {
    for (const auto& entry : mapConfirmedZelnodeData) {
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

        // Gather which location they are in
        if (mapZelnodeList.at(CUMULUS).setConfirmedTxInList.count(entry.first)) {
            nCUMULUS++;
        } else if (mapZelnodeList.at(NIMBUS).setConfirmedTxInList.count(entry.first)) {
            nNIMBUS++;
        } else if (mapZelnodeList.at(STRATUS).setConfirmedTxInList.count(entry.first)) {
            nStratus++;
        }
    }
}

int GetZelnodeExpirationCount(const int& p_nHeight)
{
    // Get the status on if Zelnode params1 is activated
    bool fFluxActive = NetworkUpgradeActive(p_nHeight, Params().GetConsensus(), Consensus::UPGRADE_FLUX);

    if (fFluxActive) {
        return ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_PARAMS_1;
    } else {
        return ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT;
    }
}

std::string GetZelnodeBenchmarkPublicKey(const CTransaction& tx)
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
