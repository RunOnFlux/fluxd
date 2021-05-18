// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASHNODES_ZELNODE_H
#define ZELCASHNODES_ZELNODE_H

#include "base58.h"
#include "key.h"
#include "main.h"
#include "net.h"
#include "sync.h"
#include "timedata.h"
#include "util.h"

/// Deterministic Zelnode consensus
#define ZELNODE_CUMULUS_COLLATERAL 10000
#define ZELNODE_NIMBUS_COLLATERAL 25000
#define ZELNODE_STRATUS_COLLATERAL 100000

// How old the output must be for zelnodes collateral to be considered valid
#define ZELNODE_MIN_CONFIRMATION_DETERMINISTIC 100

// If the zelnode isn't confirmed within this amount of blocks, the zelnode is moved to a DoS list
#define ZELNODE_START_TX_EXPIRATION_HEIGHT 60

// How long the zelnode will stay in the DoS list. Is the calculated from that height the start transaction was added to the chain
#define ZELNODE_DOS_REMOVE_AMOUNT 180

// How often a new confirmation transaction needs to be seen on chain to keep a node up and running
#define ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT 60
#define ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_PARAMS_1 80

// Nodes are allowed to send a update confirm notification only after this many blocks past there last confirm
#define ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT 40
#define ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE 5

/// Mempool only
// Max signature time that we accept into the mempool
#define ZELNODE_MAX_SIG_TIME 3600

class ZelnodeCache;
class CZelnodeTxBlockUndo;
class ActiveZelnode;

extern ZelnodeCache g_zelnodeCache;
extern ActiveZelnode activeZelnode;
extern COutPoint zelnodeOutPoint;

/** REMOVE THE ABOVE CODE AFTER DETERMINISTIC ZELNODES IS ACTIVATED **/

std::string TierToString(int tier);

bool CheckZelnodeTxSignatures(const CTransaction& transaction);
bool CheckBenchmarkSignature(const CTransaction& transaction);

// Locations
enum {
    ZELNODE_TX_ERROR = 0,
    ZELNODE_TX_STARTED = 1,
    ZELNODE_TX_DOS_PROTECTION,
    ZELNODE_TX_CONFIRMED,
    ZELNODE_TX_MISS_CONFIRMED,
    ZELNODE_TX_EXPIRED
};

enum  ZelnodeUpdateType {
    INITIAL_CONFIRM = 0,
    UPDATE_CONFIRM = 1
};

enum Tier {
    NONE = 0,
    CUMULUS = 1,
    NIMBUS = 2,
    STRATUS = 3
};

std::string ZelnodeLocationToString(int nLocation);

void GetUndoDataForExpiredZelnodeDosScores(CZelnodeTxBlockUndo& p_zelnodeTxUudoData, const int& p_nHeight);
void GetUndoDataForExpiredConfirmZelnodes(CZelnodeTxBlockUndo& p_zelnodeTxUudoData, const int& p_nHeight, const std::set<COutPoint> setSpentOuts);

void GetUndoDataForPaidZelnodes(CZelnodeTxBlockUndo& zelnodeTxBlockUndo, ZelnodeCache& p_localCache);

class ZelnodeCacheData {
public:
    // Zelnode Tx data
    int8_t nType;
    COutPoint collateralIn; // collateral in
    CPubKey collateralPubkey;
    CPubKey pubKey; // Pubkey used for VPS signature verification
    int nAddedBlockHeight;
    int nConfirmedBlockHeight;
    int nLastConfirmedBlockHeight;
    int nLastPaidHeight;
    std::string ip;
    int8_t nTier;

    int8_t nStatus;

    void SetNull() {
        nType = ZELNODE_NO_TYPE;
        nAddedBlockHeight = 0;
        nConfirmedBlockHeight = 0;
        nLastConfirmedBlockHeight = 0;
        nLastPaidHeight = 0;
        ip = "";
        nTier = 0;
        nStatus =  ZELNODE_TX_ERROR;
    }

    ZelnodeCacheData() {
        SetNull();
    }

    bool IsNull() {
        return nType == ZELNODE_NO_TYPE;
    }

    bool isCUMULUS()
    {
        return nTier == CUMULUS;
    }

    bool isNIMBUS()
    {
        return nTier == NIMBUS;
    }

    bool IsSTRATUS()
    {
        return nTier == STRATUS;
    }

    std::string Tier()
    {
        std::string strStatus = "NONE";

        if (nTier == CUMULUS) strStatus = "CUMULUS";
        if (nTier == NIMBUS) strStatus = "NIMBUS";
        if (nTier == STRATUS) strStatus = "STRATUS";

        return strStatus;
    }

    friend bool operator<(const ZelnodeCacheData& a, const ZelnodeCacheData& b)
    {
        int aComparatorHeight = a.nLastPaidHeight > 0 ? a.nLastPaidHeight : a.nConfirmedBlockHeight;
        int bComparatorHeight = b.nLastPaidHeight > 0 ? b.nLastPaidHeight : b.nConfirmedBlockHeight;

        return (aComparatorHeight < bComparatorHeight || (aComparatorHeight == bComparatorHeight && a.collateralIn < b.collateralIn));
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nType);
        READWRITE(collateralIn);
        READWRITE(collateralPubkey);
        READWRITE(pubKey);
        READWRITE(nAddedBlockHeight);
        READWRITE(nConfirmedBlockHeight);
        READWRITE(nLastConfirmedBlockHeight);
        READWRITE(nLastPaidHeight);
        READWRITE(ip);
        READWRITE(nTier);
        READWRITE(nStatus);
    }
};

class ZelnodeListData {
public:

    COutPoint out;
    int nConfirmedBlockHeight;
    int nLastPaidHeight;

    void SetNull()
    {
        nConfirmedBlockHeight = 0;
        nLastPaidHeight = 0;
        out.hash = uint256();
        out.n = 0;
    }

    ZelnodeListData()
    {
        SetNull();
    }

    ZelnodeListData(const ZelnodeCacheData& p_zelnodeData)
    {
        nConfirmedBlockHeight = p_zelnodeData.nConfirmedBlockHeight;
        nLastPaidHeight = p_zelnodeData.nLastPaidHeight;
        out = p_zelnodeData.collateralIn;
    }

    friend bool operator<(const ZelnodeListData& a, const ZelnodeListData& b)
    {
        int aComparatorHeight = a.nLastPaidHeight > 0 ? a.nLastPaidHeight : a.nConfirmedBlockHeight;
        int bComparatorHeight = b.nLastPaidHeight > 0 ? b.nLastPaidHeight : b.nConfirmedBlockHeight;

        // if you were paid at the same height that nodes were added. You should have less priority in the list
        if (a.nLastPaidHeight && b.nLastPaidHeight) {
            return (aComparatorHeight < bComparatorHeight || (aComparatorHeight == bComparatorHeight && a.out < b.out));
        } else if (a.nLastPaidHeight) {
            return aComparatorHeight < bComparatorHeight;
        } else if (b.nLastPaidHeight) {
            return aComparatorHeight < bComparatorHeight || aComparatorHeight == bComparatorHeight;
        } else {
            return (aComparatorHeight < bComparatorHeight || (aComparatorHeight == bComparatorHeight && a.out < b.out));
        }
    }
};

class ZelnodeList {
public:
    // Sorted list of zelnodes ready to be paid
    std::set<COutPoint> setConfirmedTxInList;
    std::list<ZelnodeListData> listConfirmedZelnodes;

    ZelnodeList(){
        SetNull();
    }

    void SetNull() {
        setConfirmedTxInList.clear();
        listConfirmedZelnodes.clear();
    }
};

void FillBlockPayeeWithDeterministicPayouts(CMutableTransaction& txNew, CAmount nFees, std::map<int, std::pair<CScript, CAmount>>* payments);

class ZelnodeCache {
public:

    mutable CCriticalSection cs;

    //! DIRTY CACHE ITEMS ONLY
    // Dirty set of OutPoints whose data has been updated and needs to be saved to database
    std::set<COutPoint> setDirtyOutPoint;

    //! LOCAL CACHE ITEMS ONLY
    // Set only used by local cache to inform the global cache when Flushing to remove Started Zelnode from being tracked
    std::set<COutPoint> setUndoStartTx;

    // Int only used by local cache to inform the global cache when Flushing to remove all Started Outpoint at this height from being tracked
    int setUndoStartTxHeight;

    // Map only used by local cache to inform the global cache when Flushing to expire DoS Zelnode from being tracked
    std::map<int, std::set<COutPoint>> mapDosExpiredToRemove;

    // Map only used by local cache to inform the global cache to undo Zelnode added to DoS tacker, and put them back into the Started Zelnode tracking
    std::map<int, std::set<COutPoint>> mapDoSToUndo;

    // Set only used by local cache to inform the global cache when Flushing to move Started Zelnodes to the Confirm list and updating IP address
    std::map<COutPoint, std::string> setAddToConfirm;

    // Int only used by local cache to inform the global cache when Flushing to set the Started Zelnodes Confirm Height
    int setAddToConfirmHeight;

    // Set only used by local chache to inform the global cache when Flushing to undo the Confirm Zelnodes
    std::set<COutPoint> setUndoAddToConfirm;

    // Set only used by local cache to inform the global cache when Flushing to update the Confirm Zelnodes nLastConfirmHeight and IP address
    std::map<COutPoint, std::string> setAddToUpdateConfirm;

    // Int only used by local cache to inform the global cache when Flushing to update the Confirm Zelnodes nLastConfirmHeight
    int setAddToUpdateConfirmHeight;

    // Set only used by local cache to inform the global cache when Flushing to remove certain OutPoints from the Confirm Zelnode data
    std::set<COutPoint> setExpireConfirmOutPoints;

    std::set<ZelnodeCacheData> setUndoExpireConfirm;

    // nTier -> height, outpoint
    std::map<int, std::pair<int, COutPoint>> mapPaidNodes;
    std::map<COutPoint, int> mapUndoPaidNodes;

    //! GLOBAL CACHE ITEMS ONLY
    // Global tracking of Started Zelnode
    std::map<COutPoint, ZelnodeCacheData> mapStartTxTracker;
    std::map<int, std::set<COutPoint> > mapStartTxHeights;

    // Global tracking of DoS Prevention Zelnode
    std::map<COutPoint, ZelnodeCacheData> mapStartTxDosTracker;
    std::map<int, std::set<COutPoint> > mapStartTxDosHeights;

    // Global tracking of Confirmed Zelnodes
    std::map<COutPoint, ZelnodeCacheData> mapConfirmedZelnodeData;

    std::map<int, ZelnodeList> mapZelnodeList;

    ZelnodeCache(){
        SetNull();
    }

    void InitMapZelnodeList() {
        mapZelnodeList.insert(std::make_pair(CUMULUS, ZelnodeList()));
        mapZelnodeList.insert(std::make_pair(NIMBUS, ZelnodeList()));
        mapZelnodeList.insert(std::make_pair(STRATUS, ZelnodeList()));
    }

    void SetNull() {
        setDirtyOutPoint.clear();
        mapStartTxTracker.clear();
        mapStartTxHeights.clear();
        mapStartTxDosTracker.clear();
        mapStartTxDosHeights.clear();
        mapDosExpiredToRemove.clear();
        mapDoSToUndo.clear();
        setUndoStartTx.clear();
        setUndoStartTxHeight = 0;
        setAddToConfirm.clear();
        setAddToConfirmHeight = 0;
        mapConfirmedZelnodeData.clear();
        setAddToUpdateConfirm.clear();
        setAddToUpdateConfirmHeight = 0;
        setUndoAddToConfirm.clear();

        mapZelnodeList.clear();

        mapPaidNodes.clear();
    }

    void AddNewStart(const CTransaction& p_transaction, const int p_nHeight, int nTier = 0);
    void UndoNewStart(const CTransaction& p_transaction, const int p_nHeight);

    void AddNewConfirm(const CTransaction& p_transaction, const int p_nHeight);
    void UndoNewConfirm(const CTransaction& p_transaction);

    void AddUpdateConfirm(const CTransaction& p_transaction, const int p_nHeight);

    void AddExpiredDosTx(const CZelnodeTxBlockUndo& p_undoData, const int p_nHeight);
    void AddExpiredConfirmTx(const CZelnodeTxBlockUndo& p_undoData);

    void AddPaidNode(const COutPoint& out, const int p_Height);

    void AddBackUndoData(const CZelnodeTxBlockUndo& p_undoData);

    //! Getting info Methods
    bool InStartTracker(const COutPoint& out);
    bool InDoSTracker(const COutPoint& out);
    bool InConfirmTracker(const COutPoint& out);
    bool CheckIfNeedsNextConfirm(const COutPoint& out);

    bool GetNextPayment(CTxDestination& dest, int nTier, COutPoint& p_zelnodeOut);

    //! Confirmation Tx Methods
    bool CheckNewStartTx(const COutPoint& out);
    void CheckForExpiredStartTx(const int& p_nHeight);
    void CheckForUndoExpiredStartTx(const int& p_nHeight);
    bool CheckIfStarted(const COutPoint& out);
    bool CheckIfConfirmed(const COutPoint& out);
    bool CheckUpdateHeight(const CTransaction& p_transaction, const int p_nHeight = 0);

    bool CheckZelnodePayout(const CTransaction& coinbase, const int p_Height, ZelnodeCache* p_zelnodeCache = nullptr);

    //! Helper functions
    ZelnodeCacheData GetZelnodeData(const CTransaction& tx);
    ZelnodeCacheData GetZelnodeData(const COutPoint& out, int* fNeedLocation = nullptr);

    bool Flush();
    bool LoadData(ZelnodeCacheData& data);
    void SortList(const int& nTier);

    bool CheckListSet(const COutPoint& p_OutPoint);
    bool CheckListHas(const ZelnodeCacheData& p_zelnodeData);
    void InsertIntoList(const ZelnodeCacheData& p_zelnodeData);
    void EraseFromListSet(const COutPoint& p_OutPoint);
    void EraseFromList(const std::set<COutPoint>& setToRemove, const int nTier);

    void DumpZelnodeCache();

    void CountNetworks(int& ipv4, int& ipv6, int& onion, int& nCUMULUS, int& nNIMBUS, int& nStratus);

    bool CheckConfirmationHeights(const int nHeight, const COutPoint& out, const std::string& ip);
};

int GetZelnodeExpirationCount(const int& p_nHeight);
std::string GetZelnodeBenchmarkPublicKey(const CTransaction& tx);

bool IsDZelnodeActive();
bool IsZelnodeTransactionsActive();




#endif //ZELCASHNODES_ZELNODE_H
