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

// How old the output must be for zelnodes collateral to be considered valid
#define ZELNODE_MIN_CONFIRMATION_DETERMINISTIC 100

// If the zelnode isn't confirmed within this amount of blocks, the zelnode is moved to a DoS list
#define ZELNODE_START_TX_EXPIRATION_HEIGHT 60

// How long the zelnode will stay in the DoS list. Is the calculated from that height the start transaction was added to the chain
#define ZELNODE_DOS_REMOVE_AMOUNT 180

// How often a new confirmation transaction needs to be seen on chain to keep a node up and running
#define ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V1 60
#define ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V2 80
#define ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V3 160

// Nodes are allowed to send a update confirm notification only after this many blocks past there last confirm
#define ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT_V1 40
#define ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT_V2 120
#define ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1 5

// Maximum ip address size in zelnode confirm transaction
#define FLUXNODE_CONFIRM_TX_IP_ADDRESS_SIZE_V1 40
#define FLUXNODE_CONFIRM_TX_IP_ADDRESS_SIZE_V2 60



/// Mempool only
// Max signature time that we accept into the mempool
#define ZELNODE_MAX_SIG_TIME 3600

/** Zelnode Collateral Amounts
 * This will be the place that will hold all zelnode collateral amounts
 * As we make changes to the node structure, this is where the new amount should be placed
 * Use the naming mechanism as we make changes V1 -> V2 -> V3 -> V4
 */
#define V1_ZELNODE_COLLAT_CUMULUS 10000
#define V1_ZELNODE_COLLAT_NIMBUS 25000
#define V1_ZELNODE_COLLAT_STRATUS 100000

#define V2_ZELNODE_COLLAT_CUMULUS 1000
#define V2_ZELNODE_COLLAT_NIMBUS 12500
#define V2_ZELNODE_COLLAT_STRATUS 40000


/** Zelnode Payout Percentages
 * This will be the place that will hold all Zelnode Payout Percentages
 * As we make changes to the node structure, this is where the new percentages should be placed
 * Use the naming mechanism as we make changes V1 -> V2 -> V3 -> V4
 */
#define ZELNODE_PERCENT_NULL 0.00
#define V1_ZELNODE_PERCENT_CUMULUS 0.0375
#define V1_ZELNODE_PERCENT_NIMBUS 0.0625
#define V1_ZELNODE_PERCENT_STRATUS 0.15

class FluxnodeCache;
class CZelnodeTxBlockUndo;
class ActiveZelnode;

extern FluxnodeCache g_fluxnodeCache;
extern ActiveZelnode activeZelnode;
extern COutPoint fluxnodeOutPoint;

/** REMOVE THE ABOVE CODE AFTER DETERMINISTIC ZELNODES IS ACTIVATED **/

std::string TierToString(int tier);

bool CheckZelnodeTxSignatures(const CTransaction& transaction);
bool CheckBenchmarkSignature(const CTransaction& transaction);
bool IsMigrationCollateralAmount(const CAmount& amount);

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
    STRATUS = 3,
    LAST = 4 // All newly added Tier must be added above LAST, and change the assigned values so they are in order
};

/** Zelnode Tier code start
 * Any changes to this code needs to be also made to the code in coins.h and coins.cpp
 * We are unable to use the same code because of build/linking restrictions
 */
bool IsTierValid(const int& nTier);
int GetNumberOfTiers();
/** Zelnode Tier code end **/


std::string ZelnodeLocationToString(int nLocation);

void GetUndoDataForExpiredZelnodeDosScores(CZelnodeTxBlockUndo& p_zelnodeTxUudoData, const int& p_nHeight);
void GetUndoDataForExpiredConfirmZelnodes(CZelnodeTxBlockUndo& p_zelnodeTxUudoData, const int& p_nHeight, const std::set<COutPoint> setSpentOuts);

void GetUndoDataForPaidZelnodes(CZelnodeTxBlockUndo& zelnodeTxBlockUndo, FluxnodeCache& p_localCache);

class FluxnodeCacheData {

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

    CAmount nCollateral;

    void SetNull() {
        nType = ZELNODE_NO_TYPE;
        nAddedBlockHeight = 0;
        nConfirmedBlockHeight = 0;
        nLastConfirmedBlockHeight = 0;
        nLastPaidHeight = 0;
        ip = "";
        nTier = 0;
        nStatus =  ZELNODE_TX_ERROR;
        nCollateral = 0;
    }

    FluxnodeCacheData() {
        SetNull();
    }

    bool IsNull() {
        return nType == ZELNODE_NO_TYPE;
    }

    bool isCumulus()
    {
        return nTier == CUMULUS;
    }

    bool isNimbus()
    {
        return nTier == NIMBUS;
    }

    bool isStratus()
    {
        return nTier == STRATUS;
    }

    bool isTierValid() {
        return nTier > NONE && nTier < LAST;
    }

    std::string TierToString() const
    {
        std::string strStatus = "NONE";
        if (nTier == CUMULUS) strStatus = "CUMULUS";
        else if (nTier == NIMBUS) strStatus = "NIMBUS";
        else if (nTier == STRATUS) strStatus = "STRATUS";
        else if (nTier == NONE) strStatus = "None";
        else strStatus = "UNKNOWN TIER (" + std::to_string(nTier) + ")";

        return strStatus;
    }

    std::string ToFullString() const
    {
        return strprintf("FluxnodeCacheData Type(%d), %s, nAddedBlockHeight(%d), nConfirmedBlockHeight(%d), nLastConfirmedBlockHeight(%d), nLastPaidHeight(%d), %s", nType,  collateralIn.ToFullString(), nAddedBlockHeight, nConfirmedBlockHeight, nLastConfirmedBlockHeight, nLastPaidHeight, this->TierToString());
    }

    friend bool operator<(const FluxnodeCacheData& a, const FluxnodeCacheData& b)
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
        if (nType & ZELNODE_HAS_COLLATERAL) {
            READWRITE(nCollateral);
        }
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

    ZelnodeListData(const FluxnodeCacheData& p_zelnodeData)
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

class FluxnodeCache {
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

    std::set<FluxnodeCacheData> setUndoExpireConfirm;

    // nTier -> height, outpoint
    std::map<int, std::pair<int, COutPoint>> mapPaidNodes;
    std::map<COutPoint, int> mapUndoPaidNodes;

    //! GLOBAL CACHE ITEMS ONLY
    // Global tracking of Started Zelnode
    std::map<COutPoint, FluxnodeCacheData> mapStartTxTracker;
    std::map<int, std::set<COutPoint> > mapStartTxHeights;

    // Global tracking of DoS Prevention Zelnode
    std::map<COutPoint, FluxnodeCacheData> mapStartTxDosTracker;
    std::map<int, std::set<COutPoint> > mapStartTxDosHeights;

    // Global tracking of Confirmed Zelnodes
    std::map<COutPoint, FluxnodeCacheData> mapConfirmedFluxnodeData;

    std::map<Tier, ZelnodeList> mapZelnodeList;

    FluxnodeCache(){
        SetNull();
    }

    void InitMapZelnodeList() {
        for (int currentTier = CUMULUS; currentTier != LAST; currentTier++ )
        {
            mapZelnodeList.insert(std::make_pair((Tier)currentTier, ZelnodeList()));
        }
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
        mapConfirmedFluxnodeData.clear();
        setAddToUpdateConfirm.clear();
        setAddToUpdateConfirmHeight = 0;
        setUndoAddToConfirm.clear();

        mapZelnodeList.clear();

        mapPaidNodes.clear();
    }

    void AddNewStart(const CTransaction& p_transaction, const int p_nHeight, int nTier = 0, const CAmount nCollateral = 0);
    void UndoNewStart(const CTransaction& p_transaction, const int p_nHeight);

    void AddNewConfirm(const CTransaction& p_transaction, const int p_nHeight);
    void UndoNewConfirm(const CTransaction& p_transaction);

    void AddUpdateConfirm(const CTransaction& p_transaction, const int p_nHeight);

    void AddExpiredDosTx(const CZelnodeTxBlockUndo& p_undoData, const int p_nHeight);
    void AddExpiredConfirmTx(const CZelnodeTxBlockUndo& p_undoData);

    void AddPaidNode(const int& tier, const COutPoint& out, const int p_Height);

    void AddBackUndoData(const CZelnodeTxBlockUndo& p_undoData);

    //! Getting info Methods
    bool InStartTracker(const COutPoint& out);
    bool InDoSTracker(const COutPoint& out);
    bool InConfirmTracker(const COutPoint& out);
    bool CheckIfNeedsNextConfirm(const COutPoint& out, const int& p_nHeight);

    bool GetNextPayment(CTxDestination& dest, int nTier, COutPoint& p_fluxnodeOut);

    //! Confirmation Tx Methods
    bool CheckNewStartTx(const COutPoint& out);
    void CheckForExpiredStartTx(const int& p_nHeight);
    void CheckForUndoExpiredStartTx(const int& p_nHeight);
    bool CheckIfStarted(const COutPoint& out);
    bool CheckIfConfirmed(const COutPoint& out);
    bool CheckUpdateHeight(const CTransaction& p_transaction, const int p_nHeight = 0);

    bool CheckZelnodePayout(const CTransaction& coinbase, const int p_Height, FluxnodeCache* p_fluxnodeCache = nullptr);

    //! Helper functions
    FluxnodeCacheData GetFluxnodeData(const CTransaction& tx);
    FluxnodeCacheData GetFluxnodeData(const COutPoint& out, int* fNeedLocation = nullptr);

    void LogDebugData(const int& nHeight, const uint256& blockhash, bool fFromDisconnect = false);

    bool Flush();
    bool LoadData(FluxnodeCacheData& data);
    void SortList(const int& nTier);

    bool CheckListSet(const COutPoint& p_OutPoint);
    bool CheckListHas(const FluxnodeCacheData& p_zelnodeData);
    void InsertIntoList(const FluxnodeCacheData& p_zelnodeData);
    void EraseFromListSet(const COutPoint& p_OutPoint);
    void EraseFromList(const std::set<COutPoint>& setToRemove, const Tier nTier);

    void DumpFluxnodeCache();

    void CountNetworks(int& ipv4, int& ipv6, int& onion, std::vector<int>& vNodeCount);
    void CountMigration(int& nOldTotal, int& nNewTotal, std::vector<int>& vOldNodeCount, std::vector<int>& vNewNodeCount);

    bool CheckConfirmationHeights(const int nHeight, const COutPoint& out, const std::string& ip);
};

int GetZelnodeExpirationCount(const int& p_nHeight);
std::string GetZelnodeBenchmarkPublicKey(const CTransaction& tx);
std::string GetP2SHFluxNodePublicKey(const uint32_t& nSigTime);
std::string GetP2SHFluxNodePublicKey(const CTransaction& tx);
bool GetKeysForP2SHFluxNode(CPubKey& pubKeyRet, CKey& keyRet);

bool IsDZelnodeActive();
bool IsZelnodeTransactionsActive();




#endif //ZELCASHNODES_ZELNODE_H
