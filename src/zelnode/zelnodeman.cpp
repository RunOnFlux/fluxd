// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "zelnode/zelnodeman.h"
#include "zelnode/activezelnode.h"
#include "addrman.h"
#include "zelnode/zelnode.h"
#include "zelnode/obfuscation.h"
#include "zelnode/spork.h"
#include "util.h"
#include <boost/filesystem.hpp>


#define ZN_WINNER_MINIMUM_AGE 8000    // Age in seconds. This should be > ZELNODE_REMOVAL_SECONDS to avoid misconfigured new nodes in the list.



/** Zelnode manager */
ZelnodeMan zelnodeman;

struct CompareLastPaid {
    bool operator()(const pair<int64_t, CTxIn>& t1,
                    const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareScoreTxIn {
    bool operator()(const pair<int64_t, CTxIn>& t1,
                    const pair<int64_t, CTxIn>& t2) const
    {
        return t1.first < t2.first;
    }
};

struct CompareScoreZN {
    bool operator()(const pair<int64_t, Zelnode>& t1,
                    const pair<int64_t, Zelnode>& t2) const
    {
        return t1.first < t2.first;
    }
};

//
// ZelnodeDB
//

ZelnodeDB::ZelnodeDB()
{
    pathZN = GetDataDir() / "zelnodecache.dat";
    strMagicMessage = "ZelnodeCache";
}

bool ZelnodeDB::Write(const ZelnodeMan& zelnodemanToSave)
{
    int64_t nStart = GetTimeMillis();

    // serialize, checksum data up to that point, then append checksum
    CDataStream ssZelnodes(SER_DISK, CLIENT_VERSION);
    ssZelnodes << strMagicMessage;                   // zelnode cache file specific magic message
    ssZelnodes << FLATDATA(Params().MessageStart()); // network specific magic number
    ssZelnodes << zelnodemanToSave;
    uint256 hash = Hash(ssZelnodes.begin(), ssZelnodes.end());
    ssZelnodes << hash;

    // open output file, and associate with CAutoFile
    FILE* file = fopen(pathZN.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s : Failed to open file %s", __func__, pathZN.string());

    // Write and commit header, data
    try {
        fileout << ssZelnodes;
    } catch (std::exception& e) {
        return error("%s : Serialize or I/O error - %s", __func__, e.what());
    }
    //    FileCommit(fileout);
    fileout.fclose();

    LogPrint("zelnode","Written info to zelnodecache.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrint("zelnode","  %s\n", zelnodemanToSave.ToString());

    return true;
}


ZelnodeDB::ReadResult ZelnodeDB::Read(ZelnodeMan& zelnodemanToLoad, bool fDryRun)
{
    int64_t nStart = GetTimeMillis();
    // open input file, and associate with CAutoFile
    FILE* file = fopen(pathZN.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        error("%s : Failed to open file %s", __func__, pathZN.string());
        return FileError;
    }

    // use file size to size memory buffer
    int fileSize = boost::filesystem::file_size(pathZN);
    int dataSize = fileSize - sizeof(uint256);
    // Don't try to resize to a negative number if file is small
    if (dataSize < 0)
        dataSize = 0;
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char*)&vchData[0], dataSize);
        filein >> hashIn;
    } catch (std::exception& e) {
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return HashReadError;
    }
    filein.fclose();

    CDataStream ssZelnodes(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssZelnodes.begin(), ssZelnodes.end());
    if (hashIn != hashTmp) {
        error("%s : Checksum mismatch, data corrupted", __func__);
        return IncorrectHash;
    }

    unsigned char pchMsgTmp[4];
    std::string strMagicMessageTmp;
    try {
        // de-serialize file header (zelnode cache file specific magic message) and ..

        ssZelnodes >> strMagicMessageTmp;

        // ... verify the message matches predefined one
        if (strMagicMessage != strMagicMessageTmp) {
            error("%s : Invalid zelnode cache magic message", __func__);
            return IncorrectMagicMessage;
        }

        // de-serialize file header (network specific magic number) and ..
        ssZelnodes >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp))) {
            error("%s : Invalid network magic number", __func__);
            return IncorrectMagicNumber;
        }
        // de-serialize data into ZelnodeMan object
        ssZelnodes >> zelnodemanToLoad;
    } catch (std::exception& e) {
        zelnodemanToLoad.Clear();
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return IncorrectFormat;
    }

    LogPrint("zelnode","Loaded info from zelnodecache.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrint("zelnode","  %s\n", zelnodemanToLoad.ToString());
    if (!fDryRun) {
        LogPrint("zelnode","Zelnode manager - cleaning....\n");
        zelnodemanToLoad.CheckAndRemove(true);
        LogPrint("zelnode","Zelnode manager - result:\n");
        LogPrint("zelnode","  %s\n", zelnodemanToLoad.ToString());
    }

    return Ok;
}

void DumpZelnodes()
{
    int64_t nStart = GetTimeMillis();

    ZelnodeDB zndb;
    ZelnodeMan tempZelnodeman;

    LogPrint("zelnode","Verifying zelnodecache.dat format...\n");
    ZelnodeDB::ReadResult readResult = zndb.Read(tempZelnodeman, true);
    // there was an error and it was not an error on file opening => do not proceed
    if (readResult == ZelnodeDB::FileError)
        LogPrint("zelnode","Missing zelnode cache file - zelnodecache.dat, will try to recreate\n");
    else if (readResult != ZelnodeDB::Ok) {
        LogPrint("zelnode","Error reading zelnodecache.dat: ");
        if (readResult == ZelnodeDB::IncorrectFormat)
            LogPrint("zelnode","magic is ok but data has invalid format, will try to recreate\n");
        else {
            LogPrint("zelnode","file format is unknown or invalid, please fix it manually\n");
            return;
        }
    }
    LogPrint("zelnode","Writting info to zelnodecache.dat...\n");
    zndb.Write(zelnodeman);

    LogPrint("zelnode","Zelnode dump finished  %dms\n", GetTimeMillis() - nStart);
}

ZelnodeMan::ZelnodeMan()
{
    nDsqCount = 0;
}


bool ZelnodeMan::Add(Zelnode& zelnode)
{
    LOCK(cs);

    if (!zelnode.IsEnabled())
        return false;

    Zelnode* pzn = Find(zelnode.vin);
    if (pzn == NULL) {
        LogPrint("zelnode", "%s: Adding new Zelnode %s - %i now\n", __func__, zelnode.vin.prevout.hash.ToString(), size() + 1);

        if (zelnode.IsBasic()) {
            mapBasicZelnodes.insert(make_pair(zelnode.vin, zelnode));
            return true;
        }

        if (zelnode.IsSuper()) {
            mapSuperZelnodes.insert(make_pair(zelnode.vin, zelnode));
            return true;
        }

        if (zelnode.IsBAMF()) {
            mapBAMFZelnodes.insert(make_pair(zelnode.vin, zelnode));
            return true;
        }
    }

    return false;
}

void ZelnodeMan::AskForZN(CNode* pnode, CTxIn& vin)
{
    std::map<COutPoint, int64_t>::iterator i = mWeAskedForZelnodeListEntry.find(vin.prevout);
    if (i != mWeAskedForZelnodeListEntry.end()) {
        int64_t t = (*i).second;
        if (GetTime() < t) return; // we've asked recently
    }

    // ask for the znb info once from the node that sent znp

    LogPrint("zelnode", "%s - Asking node for missing entry, vin: %s\n", __func__, vin.prevout.hash.ToString());
    pnode->PushMessage("dseg", vin);
    int64_t askAgain = GetTime() + ZELNODE_MIN_ZNP_SECONDS;
    mWeAskedForZelnodeListEntry[vin.prevout] = askAgain;
}

void ZelnodeMan::Check()
{
    LOCK(cs);

    map<CTxIn, Zelnode>::iterator basicIt = mapBasicZelnodes.begin();
    while(basicIt != mapBasicZelnodes.end()) {
        basicIt->second.Check();
        ++basicIt;
    }

    map<CTxIn, Zelnode>::iterator superIt = mapSuperZelnodes.begin();
    while(superIt != mapSuperZelnodes.end()) {
        superIt->second.Check();
        ++superIt;
    }

    map<CTxIn, Zelnode>::iterator bamfIt = mapBAMFZelnodes.begin();
    while(bamfIt != mapBAMFZelnodes.end()) {
        bamfIt->second.Check();
        ++bamfIt;
    }
}

void ZelnodeMan::CheckAndRemove(bool forceExpiredRemoval)
{
    Check();

    LOCK(cs);

    //remove inactive and outdated
    map<CTxIn, Zelnode>::iterator basicIt = mapBasicZelnodes.begin();
    map<CTxIn, Zelnode>::iterator superIt = mapSuperZelnodes.begin();
    map<CTxIn, Zelnode>::iterator bamfIt = mapBAMFZelnodes.begin();

    // Remove Basic Nodes
    while (basicIt != mapBasicZelnodes.end()) {
        if ((basicIt->second).activeState == Zelnode::ZELNODE_REMOVE ||
            (basicIt->second).activeState == Zelnode::ZELNODE_VIN_SPENT ||
            (forceExpiredRemoval && (basicIt->second).activeState == Zelnode::ZELNODE_EXPIRED) ||
            (basicIt->second).protocolVersion < zelnodePayments.GetMinZelnodePaymentsProto()) {
            LogPrint("zelnode", "%s: Removing inactive Basic Zelnode %s - %i now\n", __func__, (basicIt->second).vin.prevout.hash.ToString(), size() - 1);

            //erase all of the broadcasts we've seen from this vin
            // -- if we missed a few pings and the node was removed, this will allow is to get it back without them
            //    sending a brand new znb
            map<uint256, ZelnodeBroadcast>::iterator it3 = mapSeenZelnodeBroadcast.begin();
            while (it3 != mapSeenZelnodeBroadcast.end()) {
                if ((*it3).second.vin == (basicIt->second).vin) {
                    zelnodeSync.mapSeenSyncZNB.erase((*it3).first);
                    mapSeenZelnodeBroadcast.erase(it3++);
                } else {
                    ++it3;
                }
            }

            // allow us to ask for this zelnode again if we see another ping
            map<COutPoint, int64_t>::iterator it2 = mWeAskedForZelnodeListEntry.begin();
            while (it2 != mWeAskedForZelnodeListEntry.end()) {
                if ((*it2).first == (basicIt->second).vin.prevout) {
                    mWeAskedForZelnodeListEntry.erase(it2++);
                } else {
                    ++it2;
                }
            }

            basicIt = mapBasicZelnodes.erase(basicIt);
        } else {
            ++basicIt;
        }
    }

    // Remove Super Nodes
    while (superIt != mapSuperZelnodes.end()) {
        if ((superIt->second).activeState == Zelnode::ZELNODE_REMOVE ||
            (superIt->second).activeState == Zelnode::ZELNODE_VIN_SPENT ||
            (forceExpiredRemoval && (superIt->second).activeState == Zelnode::ZELNODE_EXPIRED) ||
            (superIt->second).protocolVersion < zelnodePayments.GetMinZelnodePaymentsProto()) {
            LogPrint("zelnode", "%s: Removing inactive Super Zelnode %s - %i now\n", __func__, (superIt->second).vin.prevout.hash.ToString(), size() - 1);

            //erase all of the broadcasts we've seen from this vin
            // -- if we missed a few pings and the node was removed, this will allow is to get it back without them
            //    sending a brand new znb
            map<uint256, ZelnodeBroadcast>::iterator it3 = mapSeenZelnodeBroadcast.begin();
            while (it3 != mapSeenZelnodeBroadcast.end()) {
                if ((*it3).second.vin == (superIt->second).vin) {
                    zelnodeSync.mapSeenSyncZNB.erase((*it3).first);
                    mapSeenZelnodeBroadcast.erase(it3++);
                } else {
                    ++it3;
                }
            }

            // allow us to ask for this zelnode again if we see another ping
            map<COutPoint, int64_t>::iterator it2 = mWeAskedForZelnodeListEntry.begin();
            while (it2 != mWeAskedForZelnodeListEntry.end()) {
                if ((*it2).first == (superIt->second).vin.prevout) {
                    mWeAskedForZelnodeListEntry.erase(it2++);
                } else {
                    ++it2;
                }
            }

            superIt = mapSuperZelnodes.erase(superIt);
        } else {
            ++superIt;
        }
    }

    // Remove BAMF Nodes
    while (bamfIt != mapBAMFZelnodes.end()) {
        if ((bamfIt->second).activeState == Zelnode::ZELNODE_REMOVE ||
            (bamfIt->second).activeState == Zelnode::ZELNODE_VIN_SPENT ||
            (forceExpiredRemoval && (bamfIt->second).activeState == Zelnode::ZELNODE_EXPIRED) ||
            (bamfIt->second).protocolVersion < zelnodePayments.GetMinZelnodePaymentsProto()) {
            LogPrint("zelnode", "%s: Removing inactive BAMF Zelnode %s - %i now\n", __func__, (bamfIt->second).vin.prevout.hash.ToString(), size() - 1);

            //erase all of the broadcasts we've seen from this vin
            // -- if we missed a few pings and the node was removed, this will allow is to get it back without them
            //    sending a brand new znb
            map<uint256, ZelnodeBroadcast>::iterator it3 = mapSeenZelnodeBroadcast.begin();
            while (it3 != mapSeenZelnodeBroadcast.end()) {
                if ((*it3).second.vin == (bamfIt->second).vin) {
                    zelnodeSync.mapSeenSyncZNB.erase((*it3).first);
                    mapSeenZelnodeBroadcast.erase(it3++);
                } else {
                    ++it3;
                }
            }

            // allow us to ask for this zelnode again if we see another ping
            map<COutPoint, int64_t>::iterator it2 = mWeAskedForZelnodeListEntry.begin();
            while (it2 != mWeAskedForZelnodeListEntry.end()) {
                if ((*it2).first == (bamfIt->second).vin.prevout) {
                    mWeAskedForZelnodeListEntry.erase(it2++);
                } else {
                    ++it2;
                }
            }

            bamfIt = mapBAMFZelnodes.erase(bamfIt);
        } else {
            ++bamfIt;
        }
    }

    // check who's asked for the Zelnode list
    map<CNetAddr, int64_t>::iterator it1 = mAskedUsForZelnodeList.begin();
    while (it1 != mAskedUsForZelnodeList.end()) {
        if ((*it1).second < GetTime()) {
            mAskedUsForZelnodeList.erase(it1++);
        } else {
            ++it1;
        }
    }

    // check who we asked for the Zelnode list
    it1 = mWeAskedForZelnodeList.begin();
    while (it1 != mWeAskedForZelnodeList.end()) {
        if ((*it1).second < GetTime()) {
            mWeAskedForZelnodeList.erase(it1++);
        } else {
            ++it1;
        }
    }

    // check which Zelnode we've asked for
    map<COutPoint, int64_t>::iterator it2 = mWeAskedForZelnodeListEntry.begin();
    while (it2 != mWeAskedForZelnodeListEntry.end()) {
        if ((*it2).second < GetTime()) {
            mWeAskedForZelnodeListEntry.erase(it2++);
        } else {
            ++it2;
        }
    }

    // remove expired mapSeenZelnodeBroadcast
    map<uint256, ZelnodeBroadcast>::iterator it3 = mapSeenZelnodeBroadcast.begin();
    while (it3 != mapSeenZelnodeBroadcast.end()) {
        if ((*it3).second.lastPing.sigTime < GetTime() - (ZELNODE_REMOVAL_SECONDS * 2)) {
            mapSeenZelnodeBroadcast.erase(it3++);
            zelnodeSync.mapSeenSyncZNB.erase((*it3).second.GetHash());
        } else {
            ++it3;
        }
    }

    // remove expired mapSeenZelnodePing
    map<uint256, ZelnodePing>::iterator it4 = mapSeenZelnodePing.begin();
    while (it4 != mapSeenZelnodePing.end()) {
        if ((*it4).second.sigTime < GetTime() - (ZELNODE_REMOVAL_SECONDS * 2)) {
            mapSeenZelnodePing.erase(it4++);
        } else {
            ++it4;
        }
    }
}

void ZelnodeMan::Clear()
{
    LOCK(cs);
    mapBasicZelnodes.clear();
    mapSuperZelnodes.clear();
    mapBAMFZelnodes.clear();
    mAskedUsForZelnodeList.clear();
    mWeAskedForZelnodeList.clear();
    mWeAskedForZelnodeListEntry.clear();
    mapSeenZelnodeBroadcast.clear();
    mapSeenZelnodePing.clear();
    nDsqCount = 0;
}

int ZelnodeMan::stable_size ()
{
    int nStable_size = 0;
    int nMinProtocol = MIN_PEER_PROTO_VERSION;
    int64_t nZelnode_Min_Age = ZN_WINNER_MINIMUM_AGE;
    int64_t nZelnode_Age = 0;

    for (auto& entry : mapBasicZelnodes) {
        if (entry.second.protocolVersion < nMinProtocol) {
            continue; // Skip obsolete versions
        }

        if (IsSporkActive (SPORK_1_ZELNODE_PAYMENT_ENFORCEMENT)) {
            nZelnode_Age = GetAdjustedTime() - entry.second.sigTime;
            if ((nZelnode_Age) < nZelnode_Min_Age) {
                continue; // Skip zelnodes younger than (default) 8000 sec (MUST be > ZELNODE_REMOVAL_SECONDS)
            }
        }

        entry.second.Check();
        if (!entry.second.IsEnabled())
            continue; // Skip not-enabled zelnodes

        nStable_size++;
    }

    for (auto& entry : mapSuperZelnodes) {
        if (entry.second.protocolVersion < nMinProtocol) {
            continue; // Skip obsolete versions
        }

        if (IsSporkActive (SPORK_1_ZELNODE_PAYMENT_ENFORCEMENT)) {
            nZelnode_Age = GetAdjustedTime() - entry.second.sigTime;
            if ((nZelnode_Age) < nZelnode_Min_Age) {
                continue; // Skip zelnodes younger than (default) 8000 sec (MUST be > ZELNODE_REMOVAL_SECONDS)
            }
        }

        entry.second.Check();
        if (!entry.second.IsEnabled())
            continue; // Skip not-enabled zelnodes

        nStable_size++;
    }

    for (auto& entry : mapBAMFZelnodes) {
        if (entry.second.protocolVersion < nMinProtocol) {
            continue; // Skip obsolete versions
        }

        if (IsSporkActive (SPORK_1_ZELNODE_PAYMENT_ENFORCEMENT)) {
            nZelnode_Age = GetAdjustedTime() - entry.second.sigTime;
            if ((nZelnode_Age) < nZelnode_Min_Age) {
                continue; // Skip zelnodes younger than (default) 8000 sec (MUST be > ZELNODE_REMOVAL_SECONDS)
            }
        }

        entry.second.Check();
        if (!entry.second.IsEnabled())
            continue; // Skip not-enabled zelnodes

        nStable_size++;
    }

    return nStable_size;
}

int ZelnodeMan::CountEnabled(int protocolVersion, int nNodeTier)
{
    int basic = 0;
    int super = 0;
    int bamf = 0;
    protocolVersion = protocolVersion == -1 ? zelnodePayments.GetMinZelnodePaymentsProto() : protocolVersion;

    if (nNodeTier == Zelnode::NONE || nNodeTier == Zelnode::BASIC) {
        for (auto& entry : mapBasicZelnodes) {
            entry.second.Check();
            if (entry.second.protocolVersion < protocolVersion || !entry.second.IsEnabled()) continue;
            basic++;
        }
        if (nNodeTier == Zelnode::BASIC) return basic;
    }


    if (nNodeTier == Zelnode::NONE || nNodeTier == Zelnode::SUPER) {
        for (auto& entry : mapSuperZelnodes) {
            entry.second.Check();
            if (entry.second.protocolVersion < protocolVersion || !entry.second.IsEnabled()) continue;
            super++;
        }
        if (nNodeTier == Zelnode::SUPER) return super;
    }

    if (nNodeTier == Zelnode::NONE || nNodeTier == Zelnode::BAMF) {
        for (auto& entry : mapBAMFZelnodes) {
            entry.second.Check();
            if (entry.second.protocolVersion < protocolVersion || !entry.second.IsEnabled()) continue;
            bamf++;
        }
        if (nNodeTier == Zelnode::BAMF) return bamf;
    }

    return basic + super + bamf;
}

void ZelnodeMan::CountNetworks(int protocolVersion, int& ipv4, int& ipv6, int& onion)
{
    protocolVersion = protocolVersion == -1 ? zelnodePayments.GetMinZelnodePaymentsProto() : protocolVersion;

    for (auto& entry : mapBasicZelnodes) {
        entry.second.Check();
        std::string strHost;
        int port;
        SplitHostPort(entry.second.addr.ToString(), port, strHost);
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
    }

    for (auto& entry : mapSuperZelnodes) {
        entry.second.Check();
        std::string strHost;
        int port;
        SplitHostPort(entry.second.addr.ToString(), port, strHost);
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
    }

    for (auto& entry : mapBAMFZelnodes) {
        entry.second.Check();
        std::string strHost;
        int port;
        SplitHostPort(entry.second.addr.ToString(), port, strHost);
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
    }
}

void ZelnodeMan::DsegUpdate(CNode* pnode)
{
    LOCK(cs);

    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        if (!(pnode->addr.IsRFC1918() || pnode->addr.IsLocal())) {
            std::map<CNetAddr, int64_t>::iterator it = mWeAskedForZelnodeList.find(pnode->addr);
            if (it != mWeAskedForZelnodeList.end()) {
                if (GetTime() < (*it).second) {
                    LogPrint("zelnode", "dseg - we already asked peer %i for the list; skipping...\n", pnode->GetId());
                    return;
                }
            }
        }
    }

    pnode->PushMessage("dseg", CTxIn());
    int64_t askAgain = GetTime() + ZELNODES_DSEG_SECONDS;
    mWeAskedForZelnodeList[pnode->addr] = askAgain;
}


Zelnode* ZelnodeMan::Find(const CScript& payee)
{
    LOCK(cs);
    CScript payee2;

    for (auto& pair : mapBasicZelnodes) {
        payee2 = GetScriptForDestination(pair.second.pubKeyCollateralAddress.GetID());
        if (payee2 == payee)
            return &pair.second;
    }

    for (auto& pair : mapSuperZelnodes) {
        payee2 = GetScriptForDestination(pair.second.pubKeyCollateralAddress.GetID());
        if (payee2 == payee)
            return &pair.second;
    }

    for (auto& pair : mapBAMFZelnodes) {
        payee2 = GetScriptForDestination(pair.second.pubKeyCollateralAddress.GetID());
        if (payee2 == payee)
            return &pair.second;
    }

    return NULL;
}

Zelnode* ZelnodeMan::Find(const CTxIn& vin)
{
    LOCK(cs);

    if (mapBasicZelnodes.count(vin)) {
        return &mapBasicZelnodes.at(vin);
    }

    if (mapSuperZelnodes.count(vin)) {
        return &mapSuperZelnodes.at(vin);
    }

    if (mapBAMFZelnodes.count(vin)) {
        return &mapBAMFZelnodes.at(vin);
    }

    return NULL;
}

Zelnode* ZelnodeMan::Find(const CPubKey& pubKeyZelnode)
{
    LOCK(cs);

    for (auto& entry : mapBasicZelnodes) {
        if (entry.second.pubKeyZelnode == pubKeyZelnode)
            return &entry.second;
    }

    for (auto& entry : mapSuperZelnodes) {
        if (entry.second.pubKeyZelnode == pubKeyZelnode)
            return &entry.second;
    }

    for (auto& entry : mapBAMFZelnodes) {
        if (entry.second.pubKeyZelnode == pubKeyZelnode)
            return &entry.second;
    }

    return NULL;
}


//
// Deterministically select the oldest/best zelnode to pay on the network
//

vector<Zelnode*> ZelnodeMan::GetNextZelnodeInQueueForPayment(int nBlockHeight, bool fFilterSigTime, int& nBasicCount, int& nSuperCount, int& nBAMFCount)
{
    LOCK(cs);

    Zelnode* pBestBasicZelnode = NULL;
    Zelnode* pBestSuperZelnode = NULL;
    Zelnode* pBestBAMFZelnode = NULL;
    std::vector<pair<int64_t, CTxIn> > vecBasicZelnodeLastPaid;
    std::vector<pair<int64_t, CTxIn> > vecSuperZelnodeLastPaid;
    std::vector<pair<int64_t, CTxIn> > vecBAMFZelnodeLastPaid;

    /*
        Make a vector with all of the last paid times
    */

    int nBasicZnCount = CountEnabled(-1, Zelnode::BASIC);
    for (auto& entry : mapBasicZelnodes) {
        entry.second.Check();
        if (!entry.second.IsEnabled()) continue;

        // //check protocol version
        if (entry.second.protocolVersion < zelnodePayments.GetMinZelnodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if (zelnodePayments.IsScheduled(entry.second, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if (fFilterSigTime && entry.second.sigTime + (nBasicZnCount * 2.6 * 60) > GetAdjustedTime()) continue;

        //make sure it has as many confirmations as there are zelnodes
        if (entry.second.GetZelnodeInputAge() < nBasicZnCount) continue;

        vecBasicZelnodeLastPaid.push_back(make_pair(entry.second.SecondsSincePayment(), entry.second.vin));
    }

    int nSuperZnCount = CountEnabled(-1, Zelnode::SUPER);
    for (auto& entry : mapSuperZelnodes) {
        entry.second.Check();
        if (!entry.second.IsEnabled()) continue;

        // //check protocol version
        if (entry.second.protocolVersion < zelnodePayments.GetMinZelnodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if (zelnodePayments.IsScheduled(entry.second, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if (fFilterSigTime && entry.second.sigTime + (nSuperZnCount * 2.6 * 60) > GetAdjustedTime()) continue;

        //make sure it has as many confirmations as there are zelnodes
        if (entry.second.GetZelnodeInputAge() < nSuperZnCount) continue;

        vecSuperZelnodeLastPaid.push_back(make_pair(entry.second.SecondsSincePayment(), entry.second.vin));
    }

    int nBAMFZnCount = CountEnabled(-1, Zelnode::BAMF);
    for (auto& entry : mapBAMFZelnodes) {
        entry.second.Check();
        if (!entry.second.IsEnabled()) continue;

        // //check protocol version
        if (entry.second.protocolVersion < zelnodePayments.GetMinZelnodePaymentsProto()) continue;

        //it's in the list (up to 8 entries ahead of current block to allow propagation) -- so let's skip it
        if (zelnodePayments.IsScheduled(entry.second, nBlockHeight)) continue;

        //it's too new, wait for a cycle
        if (fFilterSigTime && entry.second.sigTime + (nBAMFZnCount * 2.6 * 60) > GetAdjustedTime()) continue;

        //make sure it has as many confirmations as there are zelnodes
        if (entry.second.GetZelnodeInputAge() < nBAMFZnCount) continue;

        vecBAMFZelnodeLastPaid.push_back(make_pair(entry.second.SecondsSincePayment(), entry.second.vin));
    }

    nBasicCount = (int)vecBasicZelnodeLastPaid.size();
    nSuperCount = (int)vecSuperZelnodeLastPaid.size();
    nBAMFCount = (int)vecBAMFZelnodeLastPaid.size();

    //when the network is in the process of upgrading, don't penalize nodes that recently restarted
    if (fFilterSigTime && ((nBasicCount < nBasicZnCount / 3) || (nSuperCount < nSuperZnCount / 3) || (nBAMFCount < nBAMFZnCount / 3))) return GetNextZelnodeInQueueForPayment(nBlockHeight, false, nBasicCount, nSuperCount, nBAMFCount);

    // Sort them high to low
    sort(vecBasicZelnodeLastPaid.rbegin(), vecBasicZelnodeLastPaid.rend(), CompareLastPaid());
    sort(vecSuperZelnodeLastPaid.rbegin(), vecSuperZelnodeLastPaid.rend(), CompareLastPaid());
    sort(vecBAMFZelnodeLastPaid.rbegin(), vecBAMFZelnodeLastPaid.rend(), CompareLastPaid());

    // Look at 1/10 of the oldest nodes (by last payment), calculate their scores and pay the best one
    //  -- This doesn't look at who is being paid in the +8-10 blocks, allowing for double payments very rarely
    //  -- 1/100 payments should be a double payment on mainnet - (1/(3000/10))*2
    //  -- (chance per block * chances before IsScheduled will fire)
    int nBasicTenthNetwork = nBasicZnCount / 10;
    int nCountTenth = 0;
    uint256 nHigh = uint256();
    for (PAIRTYPE(int64_t, CTxIn)& s : vecBasicZelnodeLastPaid) {
        Zelnode* pzn = Find(s.second);
        if (!pzn) break;

        uint256 n = pzn->CalculateScore(1, nBlockHeight - 100);
        if (nHigh < n) {
            nHigh = n;
            pBestBasicZelnode = pzn;
        }
        nCountTenth++;
        if (nCountTenth >= nBasicTenthNetwork) break;
    }

    int nSuperTenthNetwork = nSuperZnCount / 10;
    nCountTenth = 0;
    nHigh = uint256();

    for (PAIRTYPE(int64_t, CTxIn)& s : vecSuperZelnodeLastPaid) {
        Zelnode* pzn = Find(s.second);
        if (!pzn) break;

        uint256 n = pzn->CalculateScore(1, nBlockHeight - 100);
        if (nHigh < n) {
            nHigh = n;
            pBestSuperZelnode = pzn;
        }
        nCountTenth++;
        if (nCountTenth >= nSuperTenthNetwork) break;
    }

    int nBAMFTenthNetwork = nBAMFZnCount / 10;
    nCountTenth = 0;
    nHigh = uint256();

    for (PAIRTYPE(int64_t, CTxIn)& s : vecBAMFZelnodeLastPaid) {
        Zelnode* pzn = Find(s.second);
        if (!pzn) break;

        uint256 n = pzn->CalculateScore(1, nBlockHeight - 100);
        if (nHigh < n) {
            nHigh = n;
            pBestBAMFZelnode = pzn;
        }
        nCountTenth++;
        if (nCountTenth >= nBAMFTenthNetwork) break;
    }

    std::vector<Zelnode*> vecPointers;
    vecPointers.emplace_back(pBestBasicZelnode);
    vecPointers.emplace_back(pBestSuperZelnode);
    vecPointers.emplace_back(pBestBAMFZelnode);
    return vecPointers;
}

bool ZelnodeMan::GetCurrentZelnode(Zelnode& winner, int nNodeTier, int mod, int64_t nBlockHeight, int minProtocol)
{
    int64_t score = 0;

    if (nNodeTier == Zelnode::BASIC) {
        bool found = false;
        for (auto& entry : mapBasicZelnodes) {
            entry.second.Check();
            if (entry.second.protocolVersion < minProtocol || !entry.second.IsEnabled()) continue;

            // calculate the score for each Zelnode
            uint256 n = entry.second.CalculateScore(mod, nBlockHeight);
            int64_t n2 = UintToArith256(n).GetCompact(false);

            // determine the winner
            if (n2 > score) {
                score = n2;
                winner = entry.second;
                found = true;
            }
        }
        return found;
    } else if (nNodeTier == Zelnode::SUPER) {
        bool found = false;
        for (auto& entry : mapSuperZelnodes) {
            entry.second.Check();
            if (entry.second.protocolVersion < minProtocol || !entry.second.IsEnabled()) continue;

            // calculate the score for each Zelnode
            uint256 n = entry.second.CalculateScore(mod, nBlockHeight);
            int64_t n2 = UintToArith256(n).GetCompact(false);

            // determine the winner
            if (n2 > score) {
                score = n2;
                winner = entry.second;
                found = true;
            }
        }
        return found;
    } else if (nNodeTier == Zelnode::BAMF) {
        bool found = false;
        for (auto& entry : mapBAMFZelnodes) {
            entry.second.Check();
            if (entry.second.protocolVersion < minProtocol || !entry.second.IsEnabled()) continue;

            // calculate the score for each Zelnode
            uint256 n = entry.second.CalculateScore(mod, nBlockHeight);
            int64_t n2 = UintToArith256(n).GetCompact(false);

            // determine the winner
            if (n2 > score) {
                score = n2;
                winner = entry.second;
                found = true;
            }
        }
        return found;
    }

    return false;
}

int ZelnodeMan::GetZelnodeRank(const CTxIn& vin, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
{
    std::vector<pair<int64_t, CTxIn> > vecZelnodeScores;
    int64_t nZelnode_Min_Age = ZN_WINNER_MINIMUM_AGE;
    int64_t nZelnode_Age = 0;

    //make sure we know about this block
    uint256 hash = uint256();
    if (!GetBlockHash(hash, nBlockHeight)) return -1;

    bool isBasic = false;
    bool isSuper = false;
    bool isBAMF = false;

    if (mapBasicZelnodes.count(vin))
        isBasic = true;
    else if (mapSuperZelnodes.count(vin))
        isSuper = true;
    else if (mapBAMFZelnodes.count(vin))
        isBAMF = true;

    if (!isBasic && !isSuper && !isBAMF)
        return -1;

    for (auto& entry : isBasic ? mapBasicZelnodes : isSuper ? mapSuperZelnodes : mapBAMFZelnodes) {
        if (entry.second.protocolVersion < minProtocol) {
            LogPrint("zelnode","Skipping Zelnode with obsolete version %d\n", entry.second.protocolVersion);
            continue;                                                       // Skip obsolete versions
        }

        if (IsSporkActive(SPORK_1_ZELNODE_PAYMENT_ENFORCEMENT)) {
            nZelnode_Age = GetAdjustedTime() - entry.second.sigTime;
            if ((nZelnode_Age) < nZelnode_Min_Age) {
                if (fDebug) LogPrint("zelnode","Skipping just activated Zelnode. Age: %ld Vin: %s\n", nZelnode_Age, entry.second.vin.ToString());
                continue;                                                   // Skip zelnodes younger than (default) 1 hour
            }
        }
        if (fOnlyActive) {
            entry.second.Check();
            if (!entry.second.IsEnabled()) continue;
        }
        uint256 n = entry.second.CalculateScore(1, nBlockHeight);
        int64_t n2 = UintToArith256(n).GetCompact(false);

        vecZelnodeScores.push_back(make_pair(n2, entry.second.vin));
    }

    sort(vecZelnodeScores.rbegin(), vecZelnodeScores.rend(), CompareScoreTxIn());

    int rank = 0;
    for (PAIRTYPE(int64_t, CTxIn) & s : vecZelnodeScores) {
        rank++;
        if (s.second.prevout == vin.prevout) {
            return rank;
        }
    }

    return -1;
}


std::vector<pair<int, Zelnode> > ZelnodeMan::GetZelnodeRanks(int nNodeTier, int64_t nBlockHeight, int minProtocol)
{
    std::vector<pair<int64_t, Zelnode> > vecZelnodeScores;
    std::vector<pair<int, Zelnode> > vecZelnodeRanks;

    bool getBasic = false;
    bool getSuper = false;
    bool getBAMF = false;

    if (nNodeTier == Zelnode::BASIC)
        getBasic = true;
    else if (nNodeTier == Zelnode::SUPER) {
        getSuper = true;
    } else if ((nNodeTier == Zelnode::BAMF))
        getBAMF = true;

    if (!getBasic && !getSuper && !getBAMF)
        return vecZelnodeRanks;

    //make sure we know about this blockG
    uint256 hash = uint256();
    if (!GetBlockHash(hash, nBlockHeight)) return vecZelnodeRanks;

    // scan for winner
    for (auto& entry : getBasic ? mapBasicZelnodes : getSuper ? mapSuperZelnodes : mapBAMFZelnodes) {
        entry.second.Check();

        if (entry.second.protocolVersion < minProtocol) continue;

        if (!entry.second.IsEnabled()) {
            vecZelnodeScores.push_back(make_pair(9999, entry.second));
            continue;
        }

        uint256 n = entry.second.CalculateScore(1, nBlockHeight);
        int64_t n2 = UintToArith256(n).GetCompact(false);

        vecZelnodeScores.push_back(make_pair(n2, entry.second));
    }

    sort(vecZelnodeScores.rbegin(), vecZelnodeScores.rend(), CompareScoreZN());

    int rank = 0;
    for (PAIRTYPE(int64_t, Zelnode) & s : vecZelnodeScores) {
        rank++;
        vecZelnodeRanks.push_back(make_pair(rank, s.second));
    }

    return vecZelnodeRanks;
}

//Zelnode* ZelnodeMan::GetZelnodeByRank(int nRank, int64_t nBlockHeight, int minProtocol, bool fOnlyActive)
//{
//    std::vector<pair<int64_t, CTxIn> > vecZelnodeScores;
//
//    // scan for winner
//    for (Zelnode& zelnode : vZelnodes) {
//        if (zelnode.protocolVersion < minProtocol) continue;
//        if (fOnlyActive) {
//            zelnode.Check();
//            if (!zelnode.IsEnabled()) continue;
//        }
//
//        uint256 n = zelnode.CalculateScore(1, nBlockHeight);
//        int64_t n2 = UintToArith256(n).GetCompact(false);
//
//        vecZelnodeScores.push_back(make_pair(n2, zelnode.vin));
//    }
//
//    sort(vecZelnodeScores.rbegin(), vecZelnodeScores.rend(), CompareScoreTxIn());
//
//    int rank = 0;
//    for (PAIRTYPE(int64_t, CTxIn) & s : vecZelnodeScores) {
//        rank++;
//        if (rank == nRank) {
//            return Find(s.second);
//        }
//    }
//
//    return NULL;
//}

void ZelnodeMan::ProcessMessage(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (!zelnodeSync.IsBlockchainSynced()) return;

    LOCK(cs_process_message);

    if (strCommand == "znb") { //Zelnode Broadcast
        ZelnodeBroadcast znb;
        vRecv >> znb;

        if (mapSeenZelnodeBroadcast.count(znb.GetHash())) { //seen
            zelnodeSync.AddedZelnodeList(znb.GetHash());
            return;
        }
        mapSeenZelnodeBroadcast.insert(make_pair(znb.GetHash(), znb));

        int nDoS = 0;
        if (!znb.CheckAndUpdate(nDoS)) {
            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);

            //failed
            return;
        }

        // make sure the vout that was signed is related to the transaction that spawned the Zelnode
        //  - this is expensive, so it's only done once per Zelnode
        if (!obfuScationSigner.IsVinAssociatedWithPubkey(znb.vin, znb.pubKeyCollateralAddress, znb.tier)) {
            LogPrintf("%s : znb - Got mismatched pubkey and vin\n", __func__);
            Misbehaving(pfrom->GetId(), 33);
            return;
        }

        // make sure it's still unspent
        //  - this is checked later by .check() in many places and by ThreadCheckObfuScationPool()
        if (znb.CheckInputsAndAdd(nDoS)) {
            // use this as a peer
            addrman.Add(CAddress(znb.addr), pfrom->addr, 2 * 60 * 60);
            zelnodeSync.AddedZelnodeList(znb.GetHash());
        } else {
            LogPrint("zelnode","znb - Rejected Zelnode entry %s\n", znb.vin.prevout.hash.ToString());

            if (nDoS > 0)
                Misbehaving(pfrom->GetId(), nDoS);
        }
    }

    else if (strCommand == "znp") { //Zelnode Ping
        ZelnodePing znp;
        vRecv >> znp;

        LogPrint("zelnode", "znp - Zelnode ping, vin: %s\n", znp.vin.prevout.hash.ToString());

        if (mapSeenZelnodePing.count(znp.GetHash())) return; //seen
        mapSeenZelnodePing.insert(make_pair(znp.GetHash(), znp));

        int nDoS = 0;
        if (znp.CheckAndUpdate(nDoS)) return;

        if (nDoS > 0) {
            // if anything significant failed, mark that node
            Misbehaving(pfrom->GetId(), nDoS);
        } else {
            // if nothing significant failed, search existing Zelnode list
            Zelnode* pzn = Find(znp.vin);
            // if it's known, don't ask for the znb, just return
            if (pzn != NULL) return;
        }

        // something significant is broken or zn is unknown,
        // we might have to ask for a zelnode entry once
        AskForZN(pfrom, znp.vin);

    } else if (strCommand == "dseg") { //Get Zelnode list or specific entry

        CTxIn vin;
        vRecv >> vin;

        if (vin == CTxIn()) { //only should ask for this once
            //local network
            bool isLocal = (pfrom->addr.IsRFC1918() || pfrom->addr.IsLocal());

            if (!isLocal && Params().NetworkID() == CBaseChainParams::MAIN) {
                std::map<CNetAddr, int64_t>::iterator i = mAskedUsForZelnodeList.find(pfrom->addr);
                if (i != mAskedUsForZelnodeList.end()) {
                    int64_t t = (*i).second;
                    if (GetTime() < t) {
                        LogPrintf("%s : dseg - peer already asked me for the list\n", __func__);
                        Misbehaving(pfrom->GetId(), 34);
                        return;
                    }
                }
                int64_t askAgain = GetTime() + ZELNODES_DSEG_SECONDS;
                mAskedUsForZelnodeList[pfrom->addr] = askAgain;
            }
        } //else, asking for a specific node which is ok


        int nInvCount = 0;

        std::vector<Zelnode> allZelnodes = GetAllZelnodeVector();

        for (Zelnode& zelnode : allZelnodes) {
            if (zelnode.addr.IsRFC1918()) continue; //local network

            if (zelnode.IsEnabled()) {
                LogPrint("zelnode", "dseg - Sending Zelnode entry - %s \n", zelnode.vin.prevout.hash.ToString());
                if (vin == CTxIn() || vin == zelnode.vin) {
                    ZelnodeBroadcast znb = ZelnodeBroadcast(zelnode);
                    uint256 hash = znb.GetHash();
                    pfrom->PushInventory(CInv(MSG_ZELNODE_ANNOUNCE, hash));
                    nInvCount++;

                    if (!mapSeenZelnodeBroadcast.count(hash)) mapSeenZelnodeBroadcast.insert(make_pair(hash, znb));

                    if (vin == zelnode.vin) {
                        LogPrint("zelnode", "dseg - Sent 1 Zelnode entry to peer %i\n", pfrom->GetId());
                        return;
                    }
                }
            }
        }

        if (vin == CTxIn()) {
            pfrom->PushMessage("ssc", ZELNODE_SYNC_LIST, nInvCount);
            LogPrint("zelnode", "dseg - Sent %d Zelnode entries to peer %i\n", nInvCount, pfrom->GetId());
        }
    }
}

void ZelnodeMan::Remove(CTxIn vin)
{
    LOCK(cs);

    if (mapBasicZelnodes.count(vin)) {
        LogPrint("zelnode", "%s: Removing Basic Zelnode %s - %i now\n", __func__, mapBasicZelnodes.at(vin).vin.prevout.hash.ToString(), size() - 1);
        mapBasicZelnodes.erase(vin);
    }

    if (mapSuperZelnodes.count(vin)) {
        LogPrint("zelnode", "%s: Removing Super Zelnode %s - %i now\n", __func__, mapSuperZelnodes.at(vin).vin.prevout.hash.ToString(), size() - 1);
        mapSuperZelnodes.erase(vin);
    }

    if (mapBAMFZelnodes.count(vin)) {
        LogPrint("zelnode", "%s: Removing BAMF Zelnode %s - %i now\n", __func__, mapBAMFZelnodes.at(vin).vin.prevout.hash.ToString(), size() - 1);
        mapBAMFZelnodes.erase(vin);
    }
}

void ZelnodeMan::UpdateZelnodeList(ZelnodeBroadcast znb)
{
    mapSeenZelnodePing.insert(make_pair(znb.lastPing.GetHash(), znb.lastPing));
    mapSeenZelnodeBroadcast.insert(make_pair(znb.GetHash(), znb));
    zelnodeSync.AddedZelnodeList(znb.GetHash());

    LogPrint("zelnode","%s -- zelnode=%s\n", __func__, znb.vin.prevout.ToString());

    Zelnode* pzn = Find(znb.vin);
    if (pzn == NULL) {
        Zelnode zelnode(znb);
        Add(zelnode);
    } else {
        pzn->UpdateFromNewBroadcast(znb);
    }
}

std::string ZelnodeMan::ToString() const
{
    std::ostringstream info;
    int size = mapBasicZelnodes.size() + mapSuperZelnodes.size() + mapBAMFZelnodes.size();

    info << "Zelnodes: " << size << ", peers who asked us for Zelnodes list: " << (int)mAskedUsForZelnodeList.size() << ", peers we asked for Zelnode list: " << (int)mWeAskedForZelnodeList.size() << ", entries in Zelnode list we asked for: " << (int)mWeAskedForZelnodeListEntry.size() << ", nDsqCount: " << (int)nDsqCount;

    return info.str();
}


