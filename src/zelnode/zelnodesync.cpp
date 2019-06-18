// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zelnode/zelnodesync.h"
#include "main.h"
#include "zelnode/activezelnode.h"
#include "zelnode/payments.h"
#include "zelnode/zelnode.h"
#include "zelnode/zelnodeman.h"
#include "zelnode/spork.h"
#include "util.h"
#include "addrman.h"


class ZelnodeSync;
ZelnodeSync zelnodeSync;

ZelnodeSync::ZelnodeSync()
{
    Reset();
}

bool ZelnodeSync::IsSynced()
{
    return RequestedZelnodeAssets == ZELNODE_SYNC_FINISHED;
}

bool ZelnodeSync::IsBlockchainSynced()
{
    static bool fBlockchainSynced = false;
    static int64_t lastProcess = GetTime();

    // if the last call to this function was more than 60 minutes ago (client was in sleep mode) reset the sync process
    if (GetTime() - lastProcess > 60 * 60) {
        Reset();
        fBlockchainSynced = false;
    }
    lastProcess = GetTime();

    if (fBlockchainSynced) return true;

    if (fImporting || fReindex) return false;

    TRY_LOCK(cs_main, lockMain);
    if (!lockMain) return false;

    CBlockIndex* pindex = chainActive.Tip();
    if (pindex == NULL) return false;

    if (pindex->nTime + 60 * 60 < GetTime())
        return false;

    fBlockchainSynced = true;

    return true;
}

void ZelnodeSync::Reset()
{
    lastZelnodeList = 0;
    lastZelnodeWinner = 0;
    mapSeenSyncZNB.clear();
    mapSeenSyncZNW.clear();
    lastFailure = 0;
    nCountFailures = 0;
    sumZelnodeList = 0;
    sumZelnodeWinner = 0;
    countZelnodeList = 0;
    countZelnodeWinner = 0;
    RequestedZelnodeAssets = ZELNODE_SYNC_INITIAL;
    RequestedZelnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
}

void ZelnodeSync::AddedZelnodeList(uint256 hash)
{
    if (zelnodeman.mapSeenZelnodeBroadcast.count(hash)) {
        if (mapSeenSyncZNB[hash] < ZELNODE_SYNC_THRESHOLD) {
            lastZelnodeList = GetTime();
            mapSeenSyncZNB[hash]++;
        }
    } else {
        lastZelnodeList = GetTime();
        mapSeenSyncZNB.insert(make_pair(hash, 1));
    }
}

void ZelnodeSync::AddedZelnodeWinner(uint256 hash)
{
    if (zelnodePayments.mapZelnodePayeeVotes.count(hash)) {
        if (mapSeenSyncZNW[hash] < ZELNODE_SYNC_THRESHOLD) {
            lastZelnodeWinner = GetTime();
            mapSeenSyncZNW[hash]++;
        }
    } else {
        lastZelnodeWinner = GetTime();
        mapSeenSyncZNW.insert(make_pair(hash, 1));
    }
}

void ZelnodeSync::GetNextAsset()
{
    switch (RequestedZelnodeAssets) {
        case (ZELNODE_SYNC_FAILED): // should never be used here actually, use Reset() instead
            ClearFulfilledRequest();
            RequestedZelnodeAssets = ZELNODE_SYNC_INITIAL;
            LogPrintf("ZelnodeSync::GetNextAsset -- Starting %s\n", GetSyncStatus());
            break;
        case(ZELNODE_SYNC_INITIAL):
            RequestedZelnodeAssets = ZELNODE_SYNC_SPORKS;
            LogPrintf("ZelnodeSync::GetNextAsset -- Starting %s\n", GetSyncStatus());
            break;
        case (ZELNODE_SYNC_SPORKS):
            RequestedZelnodeAssets = ZELNODE_SYNC_LIST;
            LogPrintf("ZelnodeSync::GetNextAsset -- Starting %s\n", GetSyncStatus());
            break;
        case (ZELNODE_SYNC_LIST):
            RequestedZelnodeAssets = ZELNODE_SYNC_MNW;
            LogPrintf("ZelnodeSync::GetNextAsset -- Starting %s\n", GetSyncStatus());
            break;
        case (ZELNODE_SYNC_MNW):
            RequestedZelnodeAssets = ZELNODE_SYNC_FINISHED;
            LogPrintf("ZelnodeSync - Sync has finished\n");
            break;
    }
    RequestedZelnodeAttempt = 0;
    nTimeAssetSyncStarted = GetTime();
}

std::string ZelnodeSync::GetSyncStatus()
{
    switch (zelnodeSync.RequestedZelnodeAssets) {
        case ZELNODE_SYNC_INITIAL:
            return _("Synchronization initializing...");
        case ZELNODE_SYNC_SPORKS:
            return _("Synchronizing sporks...");
        case ZELNODE_SYNC_LIST:
            return _("Synchronizing zelnode list...");
        case ZELNODE_SYNC_MNW:
            return _("Synchronizing zelnode winners...");
        case ZELNODE_SYNC_FAILED:
            return _("Synchronization failed");
        case ZELNODE_SYNC_FINISHED:
            return _("Synchronization finished");
    }
    return "";
}

void ZelnodeSync::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (strCommand == "ssc") { //Sync status count
        int nItemID;
        int nCount;
        vRecv >> nItemID >> nCount;

        if (RequestedZelnodeAssets >= ZELNODE_SYNC_FINISHED) return;

        //this means we will receive no further communication
        switch (nItemID) {
            case (ZELNODE_SYNC_LIST):
                if (nItemID != RequestedZelnodeAssets) return;
                sumZelnodeList += nCount;
                countZelnodeList++;
                break;
            case (ZELNODE_SYNC_MNW):
                if (nItemID != RequestedZelnodeAssets) return;
                sumZelnodeWinner += nCount;
                countZelnodeWinner++;
                break;
        }

        LogPrint("zelnode", "%s - ssc - got inventory count %d %d\n", __func__, nItemID, nCount);
    }
}

void ZelnodeSync::ClearFulfilledRequest()
{
    TRY_LOCK(cs_vNodes, lockRecv);
    if (!lockRecv) return;

    for (CNode* pnode : vNodes) {
        pnode->ClearFulfilledRequest("getspork");
        pnode->ClearFulfilledRequest("znsync");
        pnode->ClearFulfilledRequest("znwsync");
    }
}

void ZelnodeSync::Process()
{
    static int tick = 0;

    if (tick++ % ZELNODE_SYNC_TIMEOUT != 0) return;

    if (IsSynced()) {
        /*
            Resync if we lose all zelnodes from sleep/wake or failure to sync originally
        */
        if (zelnodeman.CountEnabled() == 0) {
            Reset();
        } else
            return;
    }

    //try syncing again
    if (RequestedZelnodeAssets == ZELNODE_SYNC_FAILED && lastFailure + (1 * 60) < GetTime()) {
        Reset();
    } else if (RequestedZelnodeAssets == ZELNODE_SYNC_FAILED) {
        return;
    }

    LogPrintf("%s::Process -- Tick %d nCurrentAsset %d\n", __func__, tick, RequestedZelnodeAssets);

    if (RequestedZelnodeAssets == ZELNODE_SYNC_INITIAL) GetNextAsset();

    // sporks synced but blockchain is not, wait until we're almost at a recent block to continue
    if (Params().NetworkID() != CBaseChainParams::REGTEST &&
        !IsBlockchainSynced() && RequestedZelnodeAssets > ZELNODE_SYNC_SPORKS) return;

    TRY_LOCK(cs_vNodes, lockRecv);
    if (!lockRecv)
        return;

    for (CNode* pnode : vNodes) {
        if (Params().NetworkID() == CBaseChainParams::REGTEST) {
            if (RequestedZelnodeAttempt <= 2) {
                pnode->PushMessage("getsporks"); //get current network sporks
            } else if (RequestedZelnodeAttempt < 4) {
                zelnodeman.DsegUpdate(pnode);
            } else if (RequestedZelnodeAttempt < 6) {
                int nZnCount = zelnodeman.CountEnabled();
                pnode->PushMessage("znget", nZnCount); //sync payees
                uint256 n = uint256();
                pnode->PushMessage("znvs", n); //sync zelnode votes
            } else {
                RequestedZelnodeAssets = ZELNODE_SYNC_FINISHED;
            }
            RequestedZelnodeAttempt++;
            return;
        }

        //set to synced
        if (RequestedZelnodeAssets == ZELNODE_SYNC_SPORKS) {
            if (pnode->HasFulfilledRequest("getspork")) continue;
            pnode->FulfilledRequest("getspork");

            pnode->PushMessage("getsporks"); //get current network sporks
            if (RequestedZelnodeAttempt >= 2) GetNextAsset();
            RequestedZelnodeAttempt++;

            return;
        }

        if (pnode->nVersion >= zelnodePayments.GetMinZelnodePaymentsProto()) {
            if (RequestedZelnodeAssets == ZELNODE_SYNC_LIST) {
                LogPrint("zelnode", "%s - lastZelnodeList %lld (GetTime() - ZELNODE_SYNC_TIMEOUT) %lld\n", __func__, lastZelnodeList, GetTime() - ZELNODE_SYNC_TIMEOUT);
                if (lastZelnodeList > 0 && lastZelnodeList < GetTime() - ZELNODE_SYNC_TIMEOUT * 2 && RequestedZelnodeAttempt >= ZELNODE_SYNC_THRESHOLD) { //hasn't received a new item in the last five seconds, so we'll move to the
                    GetNextAsset();
                    return;
                }

                if (pnode->HasFulfilledRequest("znsync")) continue;
                pnode->FulfilledRequest("znsync");

                // timeout
                if (lastZelnodeList == 0 &&
                    (RequestedZelnodeAttempt >= ZELNODE_SYNC_THRESHOLD * 3 || GetTime() - nTimeAssetSyncStarted > ZELNODE_SYNC_TIMEOUT * 10)) {
                    if (IsSporkActive(SPORK_1_ZELNODE_PAYMENT_ENFORCEMENT)) {
                        LogPrintf("%s - ERROR - Syncing zelnode list has failed, failed because %s, will try again\n", __func__, (RequestedZelnodeAttempt >= ZELNODE_SYNC_THRESHOLD * 3) ? "Requested zelnode attempt greater than threshold" : "nTimeAsset Sync timeout");
                        RequestedZelnodeAssets = ZELNODE_SYNC_FAILED;
                        RequestedZelnodeAttempt = 0;
                        lastFailure = GetTime();
                        nCountFailures++;
                    } else {
                        GetNextAsset();
                    }
                    return;
                }

                if (RequestedZelnodeAttempt >= ZELNODE_SYNC_THRESHOLD * 3) return;

                zelnodeman.DsegUpdate(pnode);
                RequestedZelnodeAttempt++;
                return;
            }

            if (RequestedZelnodeAssets == ZELNODE_SYNC_MNW) {
                if (lastZelnodeWinner > 0 && lastZelnodeWinner < GetTime() - ZELNODE_SYNC_TIMEOUT * 2 && RequestedZelnodeAttempt >= ZELNODE_SYNC_THRESHOLD) { //hasn't received a new item in the last five seconds, so we'll move to the
                    GetNextAsset();
                    return;
                }

                if (pnode->HasFulfilledRequest("znwsync")) continue;
                pnode->FulfilledRequest("znwsync");

                // timeout
                if (lastZelnodeWinner == 0 &&
                    (RequestedZelnodeAttempt >= ZELNODE_SYNC_THRESHOLD * 3 || GetTime() - nTimeAssetSyncStarted > ZELNODE_SYNC_TIMEOUT * 10)) {
                    if (IsSporkActive(SPORK_1_ZELNODE_PAYMENT_ENFORCEMENT)) {
                        LogPrintf("%s - ERROR - Syncing zelnode winners has failed, failed because %s, will try again\n", __func__, (RequestedZelnodeAttempt >= ZELNODE_SYNC_THRESHOLD * 3) ? "Requested zelnode attempt greater than threshold" : "nTimeAsset Sync timeout");
                        RequestedZelnodeAssets = ZELNODE_SYNC_FAILED;
                        RequestedZelnodeAttempt = 0;
                        lastFailure = GetTime();
                        nCountFailures++;
                    } else {
                        GetNextAsset();
                    }
                    return;
                }

                if (RequestedZelnodeAttempt >= ZELNODE_SYNC_THRESHOLD * 3) return;

                CBlockIndex* pindexPrev = chainActive.Tip();
                if (pindexPrev == NULL) return;

                int nZnCount = zelnodeman.CountEnabled();
                pnode->PushMessage("znget", nZnCount); //sync payees
                RequestedZelnodeAttempt++;

                return;
            }
        }
    }
}

