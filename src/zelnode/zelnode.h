// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018 The Zelcash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

#define ZELNODE_BASIC_COLLATERAL 10000
#define ZELNODE_SUPER_COLLATERAL 25000
#define ZELNODE_BAMF_COLLATERAL 100000

class Zelnode;
class ZelnodeBroadcast;
class ZelnodePing;

extern std::map<int64_t, uint256> mapCacheBlockHashes;
bool GetBlockHash(uint256& hash, int nBlockHeight);


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

std::string TierToString(int tier);

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

#endif //ZELCASHNODES_ZELNODE_H
