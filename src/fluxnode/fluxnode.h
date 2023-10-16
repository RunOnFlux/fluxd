// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASHNODES_FLUXNODE_H
#define ZELCASHNODES_FLUXNODE_H

#include "base58.h"
#include "key.h"
#include "main.h"
#include "net.h"
#include "sync.h"
#include "timedata.h"
#include "util.h"

// How old the output must be for fluxnodes collateral to be considered valid
#define FLUXNODE_MIN_CONFIRMATION_DETERMINISTIC 100

// If the fluxnode isn't confirmed within this amount of blocks, the fluxnode is moved to a DoS list
#define FLUXNODE_START_TX_EXPIRATION_HEIGHT 60

// How long the fluxnode will stay in the DoS list. Is the calculated from that height the start transaction was added to the chain
#define FLUXNODE_DOS_REMOVE_AMOUNT 180

// How often a new confirmation transaction needs to be seen on chain to keep a node up and running
#define FLUXNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V1 60
#define FLUXNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V2 80
#define FLUXNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT_V3 160

// Nodes are allowed to send a update confirm notification only after this many blocks past there last confirm
#define FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V1 40
#define FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_V2 120
#define FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1 5

// Maximum ip address size in fluxnode confirm transaction
#define FLUXNODE_CONFIRM_TX_IP_ADDRESS_SIZE_V1 40
#define FLUXNODE_CONFIRM_TX_IP_ADDRESS_SIZE_V2 60



/// Mempool only
// Max signature time that we accept into the mempool
#define FLUXNODE_MAX_SIG_TIME 3600

/** Fluxnode Collateral Amounts
 * This will be the place that will hold all fluxnode collateral amounts
 * As we make changes to the node structure, this is where the new amount should be placed
 * Use the naming mechanism as we make changes V1 -> V2 -> V3 -> V4
 */
#define V1_FLUXNODE_COLLAT_CUMULUS 10000
#define V1_FLUXNODE_COLLAT_NIMBUS 25000
#define V1_FLUXNODE_COLLAT_STRATUS 100000

#define V2_FLUXNODE_COLLAT_CUMULUS 1000
#define V2_FLUXNODE_COLLAT_NIMBUS 12500
#define V2_FLUXNODE_COLLAT_STRATUS 40000


/** Fluxnode Payout Percentages
 * This will be the place that will hold all Fluxnode Payout Percentages
 * As we make changes to the node structure, this is where the new percentages should be placed
 * Use the naming mechanism as we make changes V1 -> V2 -> V3 -> V4
 */
#define FLUXNODE_PERCENT_NULL 0.00
#define V1_FLUXNODE_PERCENT_CUMULUS 0.0375
#define V1_FLUXNODE_PERCENT_NIMBUS 0.0625
#define V1_FLUXNODE_PERCENT_STRATUS 0.15

class FluxnodeCache;
class CFluxnodeTxBlockUndo;
class ActiveFluxnode;

extern FluxnodeCache g_fluxnodeCache;
extern ActiveFluxnode activeFluxnode;
extern COutPoint fluxnodeOutPoint;

/** REMOVE THE ABOVE CODE AFTER DETERMINISTIC FLUXNODES IS ACTIVATED **/

std::string TierToString(int tier);

bool CheckFluxnodeTxSignatures(const CTransaction& transaction);
bool CheckBenchmarkSignature(const CTransaction& transaction);
bool IsMigrationCollateralAmount(const CAmount& amount);

// Locations
enum {
    FLUXNODE_TX_ERROR = 0,
    FLUXNODE_TX_STARTED = 1,
    FLUXNODE_TX_DOS_PROTECTION,
    FLUXNODE_TX_CONFIRMED,
    FLUXNODE_TX_MISS_CONFIRMED,
    FLUXNODE_TX_EXPIRED
};

enum  FluxnodeUpdateType {
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

/** Fluxnode Tier code start
 * Any changes to this code needs to be also made to the code in coins.h and coins.cpp
 * We are unable to use the same code because of build/linking restrictions
 */
bool IsTierValid(const int& nTier);
int GetNumberOfTiers();
/** Fluxnode Tier code end **/


std::string FluxnodeLocationToString(int nLocation);

void GetUndoDataForExpiredFluxnodeDosScores(CFluxnodeTxBlockUndo& p_fluxnodeTxUudoData, const int& p_nHeight);
void GetUndoDataForExpiredConfirmFluxnodes(CFluxnodeTxBlockUndo& p_fluxnodeTxUudoData, const int& p_nHeight, const std::set<COutPoint> setSpentOuts);

void GetUndoDataForPaidFluxnodes(CFluxnodeTxBlockUndo& fluxnodeTxBlockUndo, FluxnodeCache& p_localCache);

class FluxnodeCacheData {

public:
    // Fluxnode Tx data
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

    // New Version Tracking (adding in P2SH node upgrade)
    int32_t nFluxTxVersion;
    CScript P2SHRedeemScript;
    int8_t nTransactionType;

    int8_t nStatus;

    CAmount nCollateral;

    void SetNull() {
        nType = FLUXNODE_NO_TYPE;
        nAddedBlockHeight = 0;
        nConfirmedBlockHeight = 0;
        nLastConfirmedBlockHeight = 0;
        nLastPaidHeight = 0;
        ip = "";
        nTier = 0;
        nStatus =  FLUXNODE_TX_ERROR;
        nCollateral = 0;
        nFluxTxVersion = 0;
        P2SHRedeemScript.clear();
        nTransactionType = FLUXNODE_NO_TYPE;
    }

    FluxnodeCacheData() {
        SetNull();
    }

    bool IsNull() const{
        if ((nType&FLUXNODE_TX_TYPE_UPGRADED) == FLUXNODE_TX_TYPE_UPGRADED) {
            return nTransactionType == FLUXNODE_NO_TYPE;
        }
        return nType == FLUXNODE_NO_TYPE;
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
        return strprintf("FluxnodeCacheData Type(%d), FluxnodeCacheData nTransactionType (%d), %s, nAddedBlockHeight(%d), nConfirmedBlockHeight(%d), nLastConfirmedBlockHeight(%d), nLastPaidHeight(%d), %s, RedeemScript(%s)", nType, nTransactionType,  collateralIn.ToFullString(), nAddedBlockHeight, nConfirmedBlockHeight, nLastConfirmedBlockHeight, nLastPaidHeight, this->TierToString(), P2SHRedeemScript.ToString());
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

        // New nType Version Checker
        if ((nType&FLUXNODE_TX_TYPE_UPGRADED) == FLUXNODE_TX_TYPE_UPGRADED) {
            LogPrintf("FLUXNODE_TX_TYPE_UPGRADED Found %d - %s    - nType = %d - TX-Type (%d), result = %d\n", __LINE__, __func__, nType, FLUXNODE_TX_TYPE_UPGRADED, nType ^ FLUXNODE_TX_TYPE_UPGRADED);
            READWRITE(nFluxTxVersion);
            READWRITE(nTransactionType);
            // Normal and P2SH data share most fields so for now we can just check at the end for P2SH
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
            READWRITE(nCollateral);
            if (nFluxTxVersion == FLUXNODE_INTERNAL_P2SH_TX_VERSION) {
                READWRITE(*(CScriptBase*)(&P2SHRedeemScript));
            }
        } else {
            // We must retain backwards compatibility with older transactions
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
            if ((nType ^ FLUXNODE_HAS_COLLATERAL) == 0) {
                READWRITE(nCollateral);
            }
        }
    }
};

class FluxnodeListData {
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

    FluxnodeListData()
    {
        SetNull();
    }

    FluxnodeListData(const FluxnodeCacheData& p_fluxnodeData)
    {
        nConfirmedBlockHeight = p_fluxnodeData.nConfirmedBlockHeight;
        nLastPaidHeight = p_fluxnodeData.nLastPaidHeight;
        out = p_fluxnodeData.collateralIn;
    }

    friend bool operator<(const FluxnodeListData& a, const FluxnodeListData& b)
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

class FluxnodeList {
public:
    // Sorted list of fluxnodes ready to be paid
    std::set<COutPoint> setConfirmedTxInList;
    std::list<FluxnodeListData> listConfirmedFluxnodes;

    FluxnodeList(){
        SetNull();
    }

    void SetNull() {
        setConfirmedTxInList.clear();
        listConfirmedFluxnodes.clear();
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
    // Set only used by local cache to inform the global cache when Flushing to remove Started Fluxnode from being tracked
    std::set<COutPoint> setUndoStartTx;

    // Map only used by local cache to inform the global cache when Flushing to expire DoS Fluxnode from being tracked
    std::map<int, std::set<COutPoint>> mapDosExpiredToRemove;

    // Map only used by local cache to inform the global cache to undo Fluxnode added to DoS tacker, and put them back into the Started Fluxnode tracking
    std::map<int, std::set<COutPoint>> mapDOSToUndo;

    // Set only used by local cache to inform the global cache when Flushing to move Started Fluxnodes to the Confirm list and updating IP address
    std::map<COutPoint, std::string> mapAddToConfirm;

    // Int only used by local cache to inform the global cache when Flushing to set the Started Fluxnodes Confirm Height
    int setAddToConfirmHeight;

    // Set only used by local chache to inform the global cache when Flushing to undo the Confirm Fluxnodes
    std::set<COutPoint> setUndoAddToConfirm;

    // Set only used by local cache to inform the global cache when Flushing to update the Confirm Fluxnodes nLastConfirmHeight and IP address
    std::map<COutPoint, std::string> mapAddToUpdateConfirm;

    // Int only used by local cache to inform the global cache when Flushing to update the Confirm Fluxnodes nLastConfirmHeight
    int setAddToUpdateConfirmHeight;

    // Set only used by local cache to inform the global cache when Flushing to remove certain OutPoints from the Confirm Fluxnode data
    std::set<COutPoint> setExpireConfirmOutPoints;

    std::set<FluxnodeCacheData> setUndoExpireConfirm;

    // nTier -> height, outpoint
    std::map<int, std::pair<int, COutPoint>> mapPaidNodes;
    std::map<COutPoint, int> mapUndoPaidNodes;

    //! GLOBAL CACHE ITEMS ONLY
    // Global tracking of Started Fluxnodes
    std::map<COutPoint, FluxnodeCacheData> mapStartTxTracker;

    // Global tracking of DoS Prevention Fluxnodes
    std::map<COutPoint, FluxnodeCacheData> mapStartTxDOSTracker;

    // Global tracking of Confirmed Fluxnodes
    std::map<COutPoint, FluxnodeCacheData> mapConfirmedFluxnodeData;

    std::map<Tier, FluxnodeList> mapFluxnodeList;

    FluxnodeCache(){
        SetNull();
    }

    void InitMapFluxnodeList() {
        for (int currentTier = CUMULUS; currentTier != LAST; currentTier++ )
        {
            mapFluxnodeList.insert(std::make_pair((Tier)currentTier, FluxnodeList()));
        }
    }

    void SetNull() {
        setDirtyOutPoint.clear();
        mapStartTxTracker.clear();
        mapStartTxDOSTracker.clear();
        mapDosExpiredToRemove.clear();
        mapDOSToUndo.clear();
        setUndoStartTx.clear();
        mapAddToConfirm.clear();
        setAddToConfirmHeight = 0;
        mapConfirmedFluxnodeData.clear();
        mapAddToUpdateConfirm.clear();
        setAddToUpdateConfirmHeight = 0;
        setUndoAddToConfirm.clear();

        mapFluxnodeList.clear();

        mapPaidNodes.clear();
    }

    void AddNewStart(const CTransaction& p_transaction, const int p_nHeight, int nTier = 0, const CAmount nCollateral = 0);
    void UndoNewStart(const CTransaction& p_transaction, const int p_nHeight);

    void AddNewConfirm(const CTransaction& p_transaction, const int p_nHeight);
    void UndoNewConfirm(const CTransaction& p_transaction);

    void AddUpdateConfirm(const CTransaction& p_transaction, const int p_nHeight);

    void AddExpiredDosTx(const CFluxnodeTxBlockUndo& p_undoData, const int p_nHeight);
    void AddExpiredConfirmTx(const CFluxnodeTxBlockUndo& p_undoData);

    void AddPaidNode(const int& tier, const COutPoint& out, const int p_Height);

    void AddBackUndoData(const CFluxnodeTxBlockUndo& p_undoData);

    //! Getting info Methods
    bool InStartTracker(const COutPoint& out);
    bool InDoSTracker(const COutPoint& out);
    bool InConfirmTracker(const COutPoint& out);
    bool CheckIfNeedsNextConfirm(const COutPoint& out, const int& p_nHeight);

    bool GetNextPayment(CTxDestination& dest, int nTier, COutPoint& p_fluxnodeOut, bool fFluxnodeDBRebuild = false);

    //! Confirmation Tx Methods
    bool CheckNewStartTx(const COutPoint& out);
    void CheckForExpiredStartTx(const int& p_nHeight);
    void CheckForUndoExpiredStartTx(const int& p_nHeight);
    bool CheckIfStarted(const COutPoint& out);
    bool CheckIfConfirmed(const COutPoint& out);
    bool CheckUpdateHeight(const CTransaction& p_transaction, const int p_nHeight = 0);

    bool CheckFluxnodePayout(const CTransaction& coinbase, const int p_Height, FluxnodeCache* p_fluxnodeCache = nullptr);

    //! Helper functions
    FluxnodeCacheData GetFluxnodeData(const CTransaction& tx);
    FluxnodeCacheData GetFluxnodeData(const COutPoint& out, int* fNeedLocation = nullptr);

    void LogDebugData(const int& nHeight, const uint256& blockhash, bool fFromDisconnect = false);

    bool Flush();
    bool LoadData(FluxnodeCacheData& data);
    void SortList(const int& nTier);

    bool CheckListSet(const COutPoint& p_OutPoint);
    bool CheckListHas(const FluxnodeCacheData& p_fluxnodeData);
    void InsertIntoList(const FluxnodeCacheData& p_fluxnodeData);
    void EraseFromListSet(const COutPoint& p_OutPoint);
    void EraseFromList(const std::set<COutPoint>& setToRemove, const Tier nTier);

    void DumpFluxnodeCache();

    void CountNetworks(int& ipv4, int& ipv6, int& onion, std::vector<int>& vNodeCount);
    void CountMigration(int& nOldTotal, int& nNewTotal, std::vector<int>& vOldNodeCount, std::vector<int>& vNewNodeCount);

    bool CheckConfirmationHeights(const int nHeight, const COutPoint& out, const std::string& ip);
};

int GetFluxnodeExpirationCount(const int& p_nHeight);
std::string GetFluxnodeBenchmarkPublicKey(const CTransaction& tx);
std::string GetP2SHFluxNodePublicKey(const uint32_t& nSigTime);
std::string GetP2SHFluxNodePublicKey(const CTransaction& tx);
bool GetKeysForP2SHFluxNode(CPubKey& pubKeyRet, CKey& keyRet);

bool IsFluxnodeTransactionsActive();

#endif //ZELCASHNODES_FLUXNODE_H
