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

#define ZELNODE_MIN_CONFIRMATIONS 15 // Zelnode collateral minimum confirmations
#define ZELNODE_MIN_ZNP_SECONDS (10 * 60) // Zelnode minimum ping time
#define ZELNODE_MIN_ZNB_SECONDS (5 * 60) // Zelnode minimum broadcast time
#define ZELNODE_PING_SECONDS (5 * 60)
#define ZELNODE_EXPIRATION_SECONDS (120 * 60)
#define ZELNODE_REMOVAL_SECONDS (130 * 60)
#define ZELNODE_CHECK_SECONDS 5
#define ZELNODE_MIN_BENCHMARK_SECONDS (60 * 60) // Benchmark required new zelnode broadcast


/// Deterministic Zelnode consensus
#define ZELNODE_BASIC_COLLATERAL 10000
#define ZELNODE_SUPER_COLLATERAL 25000
#define ZELNODE_BAMF_COLLATERAL 100000

// How old the output must be for zelnodes collateral to be considered valid
#define ZELNODE_MIN_CONFIRMATION_DETERMINISTIC 100

// If the zelnode isn't confirmed within this amount of blocks, the zelnode is moved to a DoS list
#define ZELNODE_START_TX_EXPIRATION_HEIGHT 60

// How long the zelnode will stay in the DoS list. Is the calculated from that height the start transaction was added to the chain
#define ZELNODE_DOS_REMOVE_AMOUNT 180

// How often a new confirmation transaction needs to be seen on chain to keep a node up and running
#define ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT 60

// Nodes are allowed to send a update confirm notification only after this many blocks past there last confirm
#define ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT 40


/// Mempool only
// Max signature time that we accept into the mempool
#define ZELNODE_MAX_SIG_TIME 3600

class Zelnode;
class ZelnodeBroadcast;
class ZelnodePing;
class ZelnodeCache;
class CZelnodeTxBlockUndo;

extern std::map<int64_t, uint256> mapCacheBlockHashes;
bool GetBlockHash(uint256& hash, int nBlockHeight);

// ZELNODE_START map
extern std::map<COutPoint, uint256> mapZelnodeStarted;
extern ZelnodeCache g_zelnodeCache;


/** Note: The Zelnode Ping class, contains a different serial method for sending pings from zelnodes throughout the network */

class ZelnodePing
{
public:
    CTxIn vin;
    uint256 blockHash;
    int64_t sigTime; //znb message times
    std::vector<unsigned char> vchSig;

    ZelnodePing();
    ZelnodePing(CTxIn& newVin);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(vin);
        READWRITE(blockHash);
        READWRITE(sigTime);
        READWRITE(vchSig);
    }

    bool CheckAndUpdate(int& nDos, bool fRequireEnabled = true, bool fCheckSigTimeOnly = false);
    bool Sign(CKey& keyZelnode, CPubKey& pubKeyZelnode);
    bool VerifySignature(CPubKey& pubKeyZelnode, int &nDos);
    void Relay();

    uint256 GetHash()
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << vin;
        ss << sigTime;
        return ss.GetHash();
    }

    void swap(ZelnodePing& first, ZelnodePing& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.blockHash, second.blockHash);
        swap(first.sigTime, second.sigTime);
        swap(first.vchSig, second.vchSig);
    }

    ZelnodePing& operator=(ZelnodePing from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const ZelnodePing& a, const ZelnodePing& b)
    {
        return a.vin == b.vin && a.blockHash == b.blockHash;
    }
    friend bool operator!=(const ZelnodePing& a, const ZelnodePing& b)
    {
        return !(a == b);
    }
};


class Zelnode
{

private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;
    int64_t lastTimeChecked;

public:
    enum state {
        ZELNODE_PRE_ENABLED,
        ZELNODE_ENABLED,
        ZELNODE_EXPIRED,
        ZELNODE_REMOVE,
        ZELNODE_VIN_SPENT
    };

    enum tier {
        NONE = 0,
        BASIC = 1,
        SUPER = 2,
        BAMF = 3
    };

    CTxIn vin;
    CService addr;
    CPubKey pubKeyCollateralAddress;
    CPubKey pubKeyZelnode;
    std::vector<unsigned char> sig;
    int activeState;
    int tier;
    int64_t sigTime; //znb message time
    int cacheInputAge;
    int cacheInputAgeBlock;
    bool unitTest;
    bool allowFreeTx;
    int protocolVersion;
    int nActiveState;
    int64_t nLastDsq; //the dsq count from the last dsq broadcast of this node
    int nScanningErrorCount;
    int nLastScanningErrorBlockHeight;
    ZelnodePing lastPing;

    int64_t nLastDsee;  // temporary, do not save. Remove after migration to v12
    int64_t nLastDseep; // temporary, do not save. Remove after migration to v12

    Zelnode();
    Zelnode(const Zelnode& other);
    Zelnode(const ZelnodeBroadcast& znb);


    void swap(Zelnode& first, Zelnode& second) // nothrow
    {
        // enable ADL (not necessary in our case, but good practice)
        using std::swap;

        // by swapping the members of two classes,
        // the two classes are effectively swapped
        swap(first.vin, second.vin);
        swap(first.addr, second.addr);
        swap(first.pubKeyCollateralAddress, second.pubKeyCollateralAddress);
        swap(first.pubKeyZelnode, second.pubKeyZelnode);
        swap(first.sig, second.sig);
        swap(first.activeState, second.activeState);
        swap(first.sigTime, second.sigTime);
        swap(first.lastPing, second.lastPing);
        swap(first.cacheInputAge, second.cacheInputAge);
        swap(first.cacheInputAgeBlock, second.cacheInputAgeBlock);
        swap(first.unitTest, second.unitTest);
        swap(first.allowFreeTx, second.allowFreeTx);
        swap(first.protocolVersion, second.protocolVersion);
        swap(first.nLastDsq, second.nLastDsq);
        swap(first.nScanningErrorCount, second.nScanningErrorCount);
        swap(first.nLastScanningErrorBlockHeight, second.nLastScanningErrorBlockHeight);
        swap(first.tier, second.tier);
    }

    Zelnode& operator=(Zelnode from)
    {
        swap(*this, from);
        return *this;
    }
    friend bool operator==(const Zelnode& a, const Zelnode& b)
    {
        return a.vin == b.vin;
    }
    friend bool operator!=(const Zelnode& a, const Zelnode& b)
    {
        return !(a.vin == b.vin);
    }

    uint256 CalculateScore(int mod = 1, int64_t nBlockHeight = 0);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        LOCK(cs);

        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyZelnode);
        READWRITE(sig);
        READWRITE(sigTime);
        READWRITE(protocolVersion);
        READWRITE(activeState);
        READWRITE(lastPing);
        READWRITE(cacheInputAge);
        READWRITE(cacheInputAgeBlock);
        READWRITE(unitTest);
        READWRITE(allowFreeTx);
        READWRITE(nLastDsq);
        READWRITE(nScanningErrorCount);
        READWRITE(nLastScanningErrorBlockHeight);
        READWRITE(tier);
    }

    int64_t SecondsSincePayment();

    bool UpdateFromNewBroadcast(ZelnodeBroadcast& znb);

    inline uint64_t SliceHash(uint256& hash, int slice)
    {
        uint64_t n = 0;
        memcpy(&n, &hash + slice * 64, 64);
        return n;
    }

    void Check(bool forceCheck = false);

    bool IsBroadcastedWithin(int seconds)
    {
        return (GetAdjustedTime() - sigTime) < seconds;
    }

    bool IsPingedWithin(int seconds, int64_t now = -1)
    {
        now == -1 ? now = GetAdjustedTime() : now;

        return (lastPing == ZelnodePing()) ? false : now - lastPing.sigTime < seconds;
    }

    void Disable()
    {
        sigTime = 0;
        lastPing = ZelnodePing();
    }

    bool IsEnabled()
    {
        return activeState == ZELNODE_ENABLED;
    }

    bool IsBasic()
    {
        return tier == BASIC;
    }

    bool IsSuper()
    {
        return tier == SUPER;
    }

    bool IsBAMF()
    {
        return tier == BAMF;
    }

    int GetZelnodeInputAge()
    {
        if (chainActive.Tip() == NULL) return 0;

        if (cacheInputAge == 0) {
            cacheInputAge = GetInputAge(vin);
            cacheInputAgeBlock = chainActive.Tip()->nHeight;
        }

        return cacheInputAge + (chainActive.Tip()->nHeight - cacheInputAgeBlock);
    }

    std::string GetStatus();

    std::string Status()
    {
        std::string strStatus = "ACTIVE";

        if (activeState == Zelnode::ZELNODE_ENABLED) strStatus = "ENABLED";
        if (activeState == Zelnode::ZELNODE_PRE_ENABLED) strStatus = "PRE_ENABLED";
        if (activeState == Zelnode::ZELNODE_EXPIRED) strStatus = "EXPIRED";
        if (activeState == Zelnode::ZELNODE_VIN_SPENT) strStatus = "VIN_SPENT";
        if (activeState == Zelnode::ZELNODE_REMOVE) strStatus = "REMOVE";

        return strStatus;
    }

    std::string Tier()
    {
        std::string strStatus = "NONE";

        if (tier == Zelnode::BASIC) strStatus = "BASIC";
        if (tier == Zelnode::SUPER) strStatus = "SUPER";
        if (tier == Zelnode::BAMF) strStatus = "BAMF";

        return strStatus;
    }

    int64_t GetLastPaid();
    bool IsValidNetAddr();
};

bool DecodeHexZelnodeBroadcast(ZelnodeBroadcast& zelnodeBroadcast, std::string strHexZelnodeBroadcast);

/** Note: Zelnode Broadcast contains a different serialize method for the sending zelndoes through the network */

class ZelnodeBroadcast : public Zelnode
{
public:
    ZelnodeBroadcast();
    ZelnodeBroadcast(CService newAddr, CTxIn newVin, CPubKey newPubkey, CPubKey newPubkey2, int protocolVersionIn);
    ZelnodeBroadcast(const Zelnode& mn);

    bool CheckAndUpdate(int& nDoS);
    bool CheckInputsAndAdd(int& nDos);
    bool Sign(CKey& keyCollateralAddress);
    bool VerifySignature();
    void Relay();
    std::string GetStrMessage();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(vin);
        READWRITE(addr);
        READWRITE(pubKeyCollateralAddress);
        READWRITE(pubKeyZelnode);
        READWRITE(sig);
        READWRITE(sigTime);
        READWRITE(protocolVersion);
        READWRITE(lastPing);
        READWRITE(nLastDsq);
    }

    uint256 GetHash()
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << sigTime;
        ss << pubKeyCollateralAddress;

        return ss.GetHash();
    }

    /// Create Zelnode broadcast, needs to be relayed manually after that
    static bool Create(CTxIn vin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyZelnodeNew, CPubKey pubKeyZelnodeNew, std::string& strErrorRet, ZelnodeBroadcast& znbRet);
    static bool Create(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, ZelnodeBroadcast& znbRet, bool fOffline = false);
    static bool CheckDefaultPort(std::string strService, std::string& strErrorRet, std::string strContext);
};

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
    BASIC = 1,
    SUPER = 2,
    BAMF = 3
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

    bool IsBasic()
    {
        return nTier == BASIC;
    }

    bool IsSuper()
    {
        return nTier == SUPER;
    }

    bool IsBAMF()
    {
        return nTier == BAMF;
    }

    std::string Tier()
    {
        std::string strStatus = "NONE";

        if (nTier == Zelnode::BASIC) strStatus = "BASIC";
        if (nTier == Zelnode::SUPER) strStatus = "SUPER";
        if (nTier == Zelnode::BAMF) strStatus = "BAMF";

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
        mapZelnodeList.insert(std::make_pair(Zelnode::BASIC, ZelnodeList()));
        mapZelnodeList.insert(std::make_pair(Zelnode::SUPER, ZelnodeList()));
        mapZelnodeList.insert(std::make_pair(Zelnode::BAMF, ZelnodeList()));
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

    void CountNetworks(int& ipv4, int& ipv6, int& onion);
};

bool IsDZelnodeActive();
bool IsZelnodeTransactionsActive();




#endif //ZELCASHNODES_ZELNODE_H
