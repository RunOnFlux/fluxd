// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2018 The PIVX developers
// Copyright (c) 2018 The Zelcash developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
#include "zelnode/zelnode.h"
#include "addrman.h"
#include "zelnode/zelnodeman.h"
#include "zelnode/obfuscation.h"
#include "sync.h"
#include "util.h"
#include "key_io.h"

// keep track of the scanning errors I've seen
map<uint256, int> mapSeenZelnodeScanningErrors;
// cache block hashes as we calculate them
std::map<int64_t, uint256> mapCacheBlockHashes;


//Get the last hash that matches the modulus given. Processed in reverse order
bool GetBlockHash(uint256& hash, int nBlockHeight)
{
    if (chainActive.Tip() == NULL) return false;

    if (nBlockHeight == 0)
        nBlockHeight = chainActive.Tip()->nHeight;

    if (mapCacheBlockHashes.count(nBlockHeight)) {
        hash = mapCacheBlockHashes[nBlockHeight];
        return true;
    }

    const CBlockIndex* BlockLastSolved = chainActive.Tip();
    const CBlockIndex* BlockReading = chainActive.Tip();

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || chainActive.Tip()->nHeight + 1 < nBlockHeight) return false;

    int nBlocksAgo = 0;
    if (nBlockHeight > 0) nBlocksAgo = (chainActive.Tip()->nHeight + 1) - nBlockHeight;
    assert(nBlocksAgo >= 0);

    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (n >= nBlocksAgo) {
            hash = BlockReading->GetBlockHash();
            mapCacheBlockHashes[nBlockHeight] = hash;
            return true;
        }
        n++;

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    return false;
}


Zelnode::Zelnode()
{
    LOCK(cs);
    vin = CTxIn();
    addr = CService();
    pubKeyCollateralAddress = CPubKey();
    pubKeyZelnode = CPubKey();
    sig = std::vector<unsigned char>();
    activeState = ZELNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = ZelnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    nActiveState = ZELNODE_ENABLED,
    protocolVersion = PROTOCOL_VERSION;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    lastTimeChecked = 0;
    tier = NONE;
    nLastDsee = 0;  // temporary, do not save. Remove after migration to v12
    nLastDseep = 0; // temporary, do not save. Remove after migration to v12
}

Zelnode::Zelnode(const Zelnode& other)
{
    LOCK(cs);
    vin = other.vin;
    addr = other.addr;
    pubKeyCollateralAddress = other.pubKeyCollateralAddress;
    pubKeyZelnode = other.pubKeyZelnode;
    sig = other.sig;
    activeState = other.activeState;
    sigTime = other.sigTime;
    lastPing = other.lastPing;
    cacheInputAge = other.cacheInputAge;
    cacheInputAgeBlock = other.cacheInputAgeBlock;
    unitTest = other.unitTest;
    allowFreeTx = other.allowFreeTx;
    nActiveState = ZELNODE_ENABLED,
    protocolVersion = other.protocolVersion;
    nLastDsq = other.nLastDsq;
    nScanningErrorCount = other.nScanningErrorCount;
    nLastScanningErrorBlockHeight = other.nLastScanningErrorBlockHeight;
    lastTimeChecked = 0;
    tier = other.tier;
    nLastDsee = other.nLastDsee;   // temporary, do not save. Remove after migration to v12
    nLastDseep = other.nLastDseep; // temporary, do not save. Remove after migration to v12
}

Zelnode::Zelnode(const ZelnodeBroadcast& znb)
{
    LOCK(cs);
    vin = znb.vin;
    addr = znb.addr;
    pubKeyCollateralAddress = znb.pubKeyCollateralAddress;
    pubKeyZelnode = znb.pubKeyZelnode;
    sig = znb.sig;
    activeState = ZELNODE_ENABLED;
    sigTime = znb.sigTime;
    lastPing = znb.lastPing;
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    nActiveState = ZELNODE_ENABLED,
    protocolVersion = znb.protocolVersion;
    nLastDsq = znb.nLastDsq;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    lastTimeChecked = 0;
    tier = znb.tier;
    nLastDsee = 0;  // temporary, do not save. Remove after migration to v12
    nLastDseep = 0; // temporary, do not save. Remove after migration to v12
}

ZelnodeBroadcast::ZelnodeBroadcast()
{
    vin = CTxIn();
    addr = CService();
    pubKeyCollateralAddress = CPubKey();
    pubKeyZelnode = CPubKey();
    sig = std::vector<unsigned char>();
    activeState = ZELNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = ZelnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = PROTOCOL_VERSION;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    tier = NONE;
}

ZelnodeBroadcast::ZelnodeBroadcast(CService newAddr, CTxIn newVin, CPubKey pubKeyCollateralAddressNew, CPubKey pubKeyZelnodeNew, int protocolVersionIn)
{
    vin = newVin;
    addr = newAddr;
    pubKeyCollateralAddress = pubKeyCollateralAddressNew;
    pubKeyZelnode = pubKeyZelnodeNew;
    sig = std::vector<unsigned char>();
    activeState = ZELNODE_ENABLED;
    sigTime = GetAdjustedTime();
    lastPing = ZelnodePing();
    cacheInputAge = 0;
    cacheInputAgeBlock = 0;
    unitTest = false;
    allowFreeTx = true;
    protocolVersion = protocolVersionIn;
    nLastDsq = 0;
    nScanningErrorCount = 0;
    nLastScanningErrorBlockHeight = 0;
    tier = NONE;
}

ZelnodeBroadcast::ZelnodeBroadcast(const Zelnode& zelnode)
{
    vin = zelnode.vin;
    addr = zelnode.addr;
    pubKeyCollateralAddress = zelnode.pubKeyCollateralAddress;
    pubKeyZelnode = zelnode.pubKeyZelnode;
    sig = zelnode.sig;
    activeState = zelnode.activeState;
    sigTime = zelnode.sigTime;
    lastPing = zelnode.lastPing;
    cacheInputAge = zelnode.cacheInputAge;
    cacheInputAgeBlock = zelnode.cacheInputAgeBlock;
    unitTest = zelnode.unitTest;
    allowFreeTx = zelnode.allowFreeTx;
    protocolVersion = zelnode.protocolVersion;
    nLastDsq = zelnode.nLastDsq;
    nScanningErrorCount = zelnode.nScanningErrorCount;
    nLastScanningErrorBlockHeight = zelnode.nLastScanningErrorBlockHeight;
    tier = zelnode.tier;
}

void Zelnode::Check(bool forceCheck)
{
    if (ShutdownRequested()) return;

    if (!forceCheck && (GetTime() - lastTimeChecked < ZELNODE_CHECK_SECONDS)) return;
    lastTimeChecked = GetTime();


    //once spent, stop doing the checks
    if (activeState == ZELNODE_VIN_SPENT) return;


    if (!IsPingedWithin(ZELNODE_REMOVAL_SECONDS)) {
        activeState = ZELNODE_REMOVE;
        return;
    }

    if (!IsPingedWithin(ZELNODE_EXPIRATION_SECONDS)) {
        activeState = ZELNODE_EXPIRED;
        return;
    }

    if(lastPing.sigTime - sigTime < ZELNODE_MIN_ZNP_SECONDS){
        activeState = ZELNODE_PRE_ENABLED;
        return;
    }

    if (!unitTest) {
        CValidationState state;
        CMutableTransaction tx = CMutableTransaction();

        CScript scriptPubKey;
        if (!GetTestingCollateralScript(Params().ZelnodeTestingDummyAddress(), scriptPubKey)){
            LogPrintf("%s: Failed to get a valid scriptPubkey\n", __func__);
            return;
        }


        CTxOut vout;
        if (tier == BASIC) {
            vout = CTxOut(9999.99 * COIN, scriptPubKey);
        } else if (tier == SUPER) {
            vout = CTxOut(24999.99 * COIN, scriptPubKey);
        } else if (tier == BAMF) {
            vout = CTxOut(99999.99 * COIN, scriptPubKey);
        }

        tx.vin.push_back(vin);
        tx.vout.push_back(vout);

        {
            TRY_LOCK(cs_main, lockMain);
            if (!lockMain) return;
            
            if (!AcceptableInputs(mempool, state, CTransaction(tx), false, NULL)) {
                activeState = ZELNODE_VIN_SPENT;
                return;
            }
        }
    }

    activeState = ZELNODE_ENABLED; // OK
}

bool Zelnode::IsValidNetAddr()
{
    // TODO: regtest is fine with any addresses for now,
    // should probably be a bit smarter if one day we start to implement tests for this
    return Params().NetworkID() == CBaseChainParams::REGTEST ||
           (IsReachable(addr) && addr.IsRoutable());
}

//
// When a new zelnode broadcast is sent, update our information
//
bool Zelnode::UpdateFromNewBroadcast(ZelnodeBroadcast& znb)
{
    if (znb.sigTime > sigTime) {
        pubKeyZelnode = znb.pubKeyZelnode;
        pubKeyCollateralAddress = znb.pubKeyCollateralAddress;
        sigTime = znb.sigTime;
        sig = znb.sig;
        protocolVersion = znb.protocolVersion;
        addr = znb.addr;
        lastTimeChecked = 0;
        int nDoS = 0;
        if (znb.lastPing == ZelnodePing() || (znb.lastPing != ZelnodePing() && znb.lastPing.CheckAndUpdate(nDoS, false))) {
            lastPing = znb.lastPing;
            zelnodeman.mapSeenZelnodePing.insert(make_pair(lastPing.GetHash(), lastPing));
        }
        return true;
    }
    return false;
}

int64_t Zelnode::SecondsSincePayment()
{
    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    int64_t sec = (GetAdjustedTime() - GetLastPaid());
    int64_t month = 60 * 60 * 24 * 30;
    if (sec < month) return sec; //if it's less than 30 days, give seconds

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    ss << sigTime;
    uint256 hash = ss.GetHash();

    // return some deterministic value for unknown/unpaid but force it to be more than 30 days old
    return month + UintToArith256(hash).GetCompact(false);
}

int64_t Zelnode::GetLastPaid()
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (pindexPrev == NULL) return false;

    CScript mnpayee;
    mnpayee = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << vin;
    ss << sigTime;
    uint256 hash = ss.GetHash();

    // use a deterministic offset to break a tie -- 2.5 minutes
    int64_t nOffset = UintToArith256(hash).GetCompact(false) % 150;

    if (chainActive.Tip() == NULL) return false;

    const CBlockIndex* BlockReading = chainActive.Tip();

    int nMnCount = zelnodeman.CountEnabled() * 1.25;
    int n = 0;
    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (n >= nMnCount) {
            return 0;
        }
        n++;

        if (zelnodePayments.mapZelnodeBlocks.count(BlockReading->nHeight)) {
            /*
                Search for this payee, with at least 2 votes. This will aid in consensus allowing the network
                to converge on the same payees quickly, then keep the same schedule.
            */
            if (zelnodePayments.mapZelnodeBlocks[BlockReading->nHeight].HasPayeeWithVotes(mnpayee, 2)) {
                return BlockReading->nTime + nOffset;
            }
        }

        if (BlockReading->pprev == NULL) {
            assert(BlockReading);
            break;
        }
        BlockReading = BlockReading->pprev;
    }

    return 0;
}


//
// Deterministically calculate a given "score" for a Zelnode depending on how close it's hash is to
// the proof of work for that block. The further away they are the better, the furthest will win the election
// and get paid this block
//
uint256 Zelnode::CalculateScore(int mod, int64_t nBlockHeight)
{
    if (chainActive.Tip() == NULL) return uint256();

    uint256 hash = uint256();
    COutPoint out(vin.prevout.hash, vin.prevout.n);
    uint256 aux = Hash(BEGIN(out.hash), END(out.n));

    if (!GetBlockHash(hash, nBlockHeight)) {
        LogPrint("zelnode","CalculateScore ERROR - nHeight %d - Returned 0\n", nBlockHeight);
        return uint256();
    }

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << hash;
    uint256 hash2 = ss.GetHash();

    CHashWriter ss2(SER_GETHASH, PROTOCOL_VERSION);
    ss2 << hash;
    ss2 << aux;
    uint256 hash3 = ss2.GetHash();

    uint256 r = (hash3 > hash2 ? hash3 - hash2 : hash2 - hash3);

    return r;
}

bool ZelnodeBroadcast::Create(std::string strService, std::string strKeyZelnode, std::string strTxHash, std::string strOutputIndex, std::string& strErrorRet, ZelnodeBroadcast& znbRet, bool fOffline)
{
    CTxIn txin;
    CPubKey pubKeyCollateralAddressNew;
    CKey keyCollateralAddressNew;
    CPubKey pubKeyZelnodeNew;
    CKey keyZelnodeNew;

    //need correct blocks to send ping
    if (!fOffline && !zelnodeSync.IsBlockchainSynced()) {
        strErrorRet = "Sync in progress. Must wait until sync is complete to start Zelnode";
        LogPrint("zelnode","%s -- %s\n", __func__, strErrorRet);
        return false;
    }

    if (!obfuScationSigner.GetKeysFromSecret(strKeyZelnode, keyZelnodeNew, pubKeyZelnodeNew)) {
        strErrorRet = strprintf("Invalid zelnode key %s", strKeyZelnode);
        LogPrint("zelnode","%s -- %s\n", __func__, strErrorRet);
        return false;
    }

    if (!pwalletMain->GetZelnodeVinAndKeys(txin, pubKeyCollateralAddressNew, keyCollateralAddressNew, strTxHash, strOutputIndex)) {
        strErrorRet = strprintf("Could not allocate txin %s:%s for zelnode %s", strTxHash, strOutputIndex, strService);
        LogPrint("zelnode","%s -- %s\n", __func__, strErrorRet);
        return false;
    }

    // The service needs the correct default port to work properly
    if(!CheckDefaultPort(strService, strErrorRet, "ZelnodeBroadcast::Create"))
        return false;

    return Create(txin, CService(strService), keyCollateralAddressNew, pubKeyCollateralAddressNew, keyZelnodeNew, pubKeyZelnodeNew, strErrorRet, znbRet);
}

bool ZelnodeBroadcast::Create(CTxIn txin, CService service, CKey keyCollateralAddressNew, CPubKey pubKeyCollateralAddressNew, CKey keyZelnodeNew, CPubKey pubKeyZelnodeNew, std::string& strErrorRet, ZelnodeBroadcast& znbRet)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;


    LogPrint("zelnode", "%s -- pubKeyCollateralAddressNew = %s, pubKeyZelnodeNew.GetID() = %s\n", __func__,
             EncodeDestination(pubKeyCollateralAddressNew.GetID()),
             pubKeyZelnodeNew.GetID().ToString());

    ZelnodePing znp(txin);
    if (!znp.Sign(keyZelnodeNew, pubKeyZelnodeNew)) {
        strErrorRet = strprintf("Failed to sign ping, zelnode=%s", txin.prevout.hash.ToString());
        LogPrint("zelnode","%s -- %s\n", __func__, strErrorRet);
        znbRet = ZelnodeBroadcast();
        return false;
    }

    znbRet = ZelnodeBroadcast(service, txin, pubKeyCollateralAddressNew, pubKeyZelnodeNew, PROTOCOL_VERSION);

    if (!znbRet.IsValidNetAddr()) {
        strErrorRet = strprintf("Invalid IP address %s, zelnode=%s", znbRet.addr.ToStringIP (), txin.prevout.hash.ToString());
        LogPrint("zelnode","%s -- %s\n", __func__, strErrorRet);
        znbRet = ZelnodeBroadcast();
        return false;
    }

    znbRet.lastPing = znp;
    if (!znbRet.Sign(keyCollateralAddressNew)) {
        strErrorRet = strprintf("Failed to sign broadcast, zelnode=%s", txin.prevout.hash.ToString());
        LogPrint("zelnode","%s -- %s\n", __func__, strErrorRet);
        znbRet = ZelnodeBroadcast();
        return false;
    }

    return true;
}

bool ZelnodeBroadcast::CheckDefaultPort(std::string strService, std::string& strErrorRet, std::string strContext)
{
    CService service = CService(strService);
    int nDefaultPort = Params().GetDefaultPort();

    if (service.GetPort() != nDefaultPort) {
        strErrorRet = strprintf("Invalid port %u for zelnode %s, only %d is supported on %s-net.",
                                service.GetPort(), strService, nDefaultPort, Params().NetworkIDString());
        LogPrint("zelnode", "%s -- %s - %s\n", __func__, strContext, strErrorRet);
        return false;
    }

    return true;
}


bool ZelnodeBroadcast::CheckAndUpdate(int& nDos)
{
    // make sure signature isn't in the future (past is OK)
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrint("zelnode","znb - Signature rejected, too far into the future %s\n", vin.prevout.hash.ToString());
        nDos = 1;
        return false;
    }

    // incorrect ping or its sigTime
    if(lastPing == ZelnodePing() || !lastPing.CheckAndUpdate(nDos, false, true))
        return false;

    if (protocolVersion < zelnodePayments.GetMinZelnodePaymentsProto()) {
        LogPrint("zelnode","znb - ignoring outdated Zelnode %s protocol version %d\n", vin.prevout.hash.ToString(), protocolVersion);
        return false;
    }

    CScript pubkeyScript;
    pubkeyScript = GetScriptForDestination(pubKeyCollateralAddress.GetID());

    if (pubkeyScript.size() != 25) {
        LogPrint("zelnode","znb - pubkey the wrong size\n");
        nDos = 100;
        return false;
    }

    CScript pubkeyScript2;
    pubkeyScript2 = GetScriptForDestination(pubKeyZelnode.GetID());

    if (pubkeyScript2.size() != 25) {
        LogPrint("zelnode","znb - pubkey2 the wrong size\n");
        nDos = 100;
        return false;
    }

    if (!vin.scriptSig.empty()) {
        LogPrint("zelnode","znb - Ignore Not Empty ScriptSig %s\n", vin.prevout.hash.ToString());
        return false;
    }

    std::string errorMessage = "";
    if (!obfuScationSigner.VerifyMessage(pubKeyCollateralAddress, sig, GetStrMessage(), errorMessage))
    {
        // don't ban for old zelnodes, their sigs could be broken because of the bug
        nDos = protocolVersion < MIN_PEER_PROTO_VERSION_ZELNODE ? 0 : 100;
        return error("%s - Got bad Zelnode address signature : %s", __func__, errorMessage);
    }

    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        if (addr.GetPort() != 16125) return false;
    } else if (addr.GetPort() == 16125)
        return false;

    //search existing Zelnode list, this is where we update existing Zelnodes with new znb broadcasts
    Zelnode* pzn = zelnodeman.Find(vin);

    // no such zelnode, nothing to update
    if (pzn == NULL) return true;

    // this broadcast is older or equal than the one that we already have - it's bad and should never happen
    // unless someone is doing something fishy
    // (mapSeenZelnodeBroadcast in ZelnodeMan::ProcessMessage should filter legit duplicates)
    if(pzn->sigTime >= sigTime) {
        return error("%s - Bad sigTime %d for Zelnode %20s %105s (existing broadcast is at %d)",
                     __func__, sigTime, addr.ToString(), vin.ToString(), pzn->sigTime);
    }

    // zelnode is not enabled yet/already, nothing to update
    if (!pzn->IsEnabled()) return true;

    // zn.pubkey = pubkey, IsVinAssociatedWithPubkey is validated once below,
    //   after that they just need to match
    if (pzn->pubKeyCollateralAddress == pubKeyCollateralAddress && !pzn->IsBroadcastedWithin(ZELNODE_MIN_ZNB_SECONDS)) {
        //take the newest entry
        LogPrint("zelnode","znb - Got updated entry for %s\n", vin.prevout.hash.ToString());
        if (pzn->UpdateFromNewBroadcast((*this))) {
            pzn->Check();
            if (pzn->IsEnabled()) Relay();
        }
        zelnodeSync.AddedZelnodeList(GetHash());
    }

    return true;
}


// Zelnode broadcast has been checked and has been assigned a tier before this method is called
bool ZelnodeBroadcast::CheckInputsAndAdd(int& nDoS)
{
    // we are a zelnode with the same vin (i.e. already activated) and this znb is ours (matches our Zelnode privkey)
    // so nothing to do here for us
    if (fZelnode && vin.prevout == activeZelnode.vin.prevout && pubKeyZelnode == activeZelnode.pubKeyZelnode)
        return true;

    // incorrect ping or its sigTime
    if(lastPing == ZelnodePing() || !lastPing.CheckAndUpdate(nDoS, false, true)) return false;

    // search existing Zelnode list
    Zelnode* pzn = zelnodeman.Find(vin);

    if (pzn != NULL) {
        // nothing to do here if we already know about this zelnode and it's enabled
        if (pzn->IsEnabled()) return true;
            // if it's not enabled, remove old ZN first and continue
        else
            zelnodeman.Remove(pzn->vin);
    }

    {
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain) {
            // not znb fault, let it to be checked again later
            zelnodeman.mapSeenZelnodeBroadcast.erase(GetHash());
            zelnodeSync.mapSeenSyncZNB.erase(GetHash());
            return false;
        }
    }

    LogPrint("zelnode", "znb - Accepted Zelnode entry\n");

    if (GetInputAge(vin) < ZELNODE_MIN_CONFIRMATIONS) {
        LogPrint("zelnode","znb - Input must have at least %d confirmations\n", ZELNODE_MIN_CONFIRMATIONS);
        // maybe we miss few blocks, let this znb to be checked again later
        zelnodeman.mapSeenZelnodeBroadcast.erase(GetHash());
        zelnodeSync.mapSeenSyncZNB.erase(GetHash());
        return false;
    }

    // verify that sig time is legit in past
    // should be at least not earlier than block when 10000, 25000, 100000 ZEL tx got ZELNODE_MIN_CONFIRMATIONS
    uint256 hashBlock = uint256();
    CTransaction tx2;
    GetTransaction(vin.prevout.hash, tx2, hashBlock, true);
    BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi != mapBlockIndex.end() && (*mi).second) {
        CBlockIndex* pZNIndex = (*mi).second;                                                        // block for 10000, 25000, 100000 ZEL tx -> 1 confirmation
        CBlockIndex* pConfIndex = chainActive[pZNIndex->nHeight + ZELNODE_MIN_CONFIRMATIONS - 1]; // block where tx got ZELNODE_MIN_CONFIRMATIONS
        if (pConfIndex->GetBlockTime() > sigTime) {
            LogPrint("zelnode","znb - Bad sigTime %d for Zelnode %s (%i conf block is at %d)\n",
                     sigTime, vin.prevout.hash.ToString(), ZELNODE_MIN_CONFIRMATIONS, pConfIndex->GetBlockTime());
            return false;
        }
    }

    LogPrint("zelnode","znb - Got NEW Zelnode entry - %s - %lli \n", vin.prevout.hash.ToString(), sigTime);
    Zelnode zn(*this);
    zelnodeman.Add(zn);

    // if it matches our Zelnode privkey, then we've been remotely activated
    if (pubKeyZelnode == activeZelnode.pubKeyZelnode && protocolVersion == PROTOCOL_VERSION) {
        activeZelnode.EnableHotColdZelnode(vin, addr);
    }

    bool isLocal = addr.IsRFC1918() || addr.IsLocal();
    if (Params().NetworkID() == CBaseChainParams::REGTEST) isLocal = false;

    if (!isLocal) Relay();

    return true;
}

void ZelnodeBroadcast::Relay()
{
    CInv inv(MSG_ZELNODE_ANNOUNCE, GetHash());
    RelayInv(inv);
}

bool ZelnodeBroadcast::Sign(CKey& keyCollateralAddress)
{
    std::string errorMessage;
    sigTime = GetAdjustedTime();

    std::string strMessage = GetStrMessage();

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage, sig, keyCollateralAddress))
        return error("%s - Error: %s", __func__, errorMessage);

    if (!obfuScationSigner.VerifyMessage(pubKeyCollateralAddress, sig, strMessage, errorMessage))
        return error("%s - Error: %s", __func__, errorMessage);

    return true;
}

bool ZelnodeBroadcast::VerifySignature()
{
    std::string errorMessage;

    if(!obfuScationSigner.VerifyMessage(pubKeyCollateralAddress, sig, GetStrMessage(), errorMessage))
        return error("%s - Error: %s", __func__, errorMessage);

    return true;
}

std::string ZelnodeBroadcast::GetStrMessage()
{
    std::string strMessage;

    strMessage = addr.ToString() + std::to_string(sigTime) + pubKeyCollateralAddress.GetID().ToString() + pubKeyZelnode.GetID().ToString() + std::to_string(protocolVersion);

    return strMessage;
}

ZelnodePing::ZelnodePing()
{
    vin = CTxIn();
    blockHash = uint256();
    sigTime = 0;
    vchSig = std::vector<unsigned char>();
}

ZelnodePing::ZelnodePing(CTxIn& newVin)
{
    vin = newVin;
    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
    sigTime = GetAdjustedTime();
    vchSig = std::vector<unsigned char>();
}

bool ZelnodePing::Sign(CKey& keyZelnode, CPubKey& pubKeyZelnode)
{
    std::string errorMessage;

    sigTime = GetAdjustedTime();
    std::string strMessage = vin.ToString() + blockHash.ToString() + std::to_string(sigTime);

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage, vchSig, keyZelnode)) {
        LogPrint("zelnode","%s - Error: %s\n", __func__, errorMessage);
        return false;
    }

    if (!obfuScationSigner.VerifyMessage(pubKeyZelnode, vchSig, strMessage, errorMessage)) {
        LogPrint("zelnode","%s - Error: %s\n", __func__, errorMessage);
        return false;
    }

    return true;
}

bool ZelnodePing::VerifySignature(CPubKey& pubKeyZelnode, int &nDos)
{
    std::string strMessage = vin.ToString() + blockHash.ToString() + std::to_string(sigTime);
    std::string errorMessage = "";

    if(!obfuScationSigner.VerifyMessage(pubKeyZelnode, vchSig, strMessage, errorMessage)){
        nDos = 33;
        return error("%s - Got bad Zelnode ping signature %s Error: %s", __func__, vin.ToString(), errorMessage);

    }
    return true;
}

bool ZelnodePing::CheckAndUpdate(int& nDos, bool fRequireEnabled, bool fCheckSigTimeOnly)
{
    if (sigTime > GetAdjustedTime() + 60 * 60) {
        LogPrint("zelnode","%s - Signature rejected, too far into the future %s\n", __func__, vin.prevout.hash.ToString());
        nDos = 1;
        return false;
    }

    if (sigTime <= GetAdjustedTime() - 60 * 60) {
        LogPrint("zelnode","%s - Signature rejected, too far into the past %s - %d %d \n", __func__, vin.prevout.hash.ToString(), sigTime, GetAdjustedTime());
        nDos = 1;
        return false;
    }

    if(fCheckSigTimeOnly) {
        Zelnode* pzn = zelnodeman.Find(vin);
        if(pzn) return VerifySignature(pzn->pubKeyZelnode, nDos);
        return true;
    }

    LogPrint("zelnode", "%s - New Ping - %s - %s - %lli\n", __func__, GetHash().ToString(), blockHash.ToString(), sigTime);

    // see if we have this Zelnode
    Zelnode* pzn = zelnodeman.Find(vin);
    if (pzn != NULL && pzn->protocolVersion >= zelnodePayments.GetMinZelnodePaymentsProto()) {
        if (fRequireEnabled && !pzn->IsEnabled()) return false;

        LogPrint("zelnode","znping - Found corresponding zn for vin: %s\n", vin.ToString());

        // update only if there is no known ping for this zelnode or
        // last ping was more then ZELNODE_MIN_MNP_SECONDS-60 ago comparing to this one
        if (!pzn->IsPingedWithin(ZELNODE_MIN_ZNP_SECONDS - 60, sigTime)) {
            if (!VerifySignature(pzn->pubKeyZelnode, nDos))
                return false;

            BlockMap::iterator mi = mapBlockIndex.find(blockHash);
            if (mi != mapBlockIndex.end() && (*mi).second) {
                if ((*mi).second->nHeight < chainActive.Height() - 24) {
                    LogPrint("zelnode","%s - Zelnode %s block hash %s is too old\n", __func__, vin.prevout.hash.ToString(), blockHash.ToString());
                    // Do nothing here (no Zelnode update, no znping relay)
                    // Let this node to be visible but fail to accept znping

                    return false;
                }
            } else {
                if (fDebug) LogPrint("zelnode","%s - Zelnode %s block hash %s is unknown\n", __func__, vin.prevout.hash.ToString(), blockHash.ToString());
                // maybe we stuck so we shouldn't ban this node, just fail to accept it
                // TODO: or should we also request this block?

                return false;
            }

            pzn->lastPing = *this;

            //zelnodeman.mapSeenZelnodeBroadcast.lastPing is probably outdated, so we'll update it
            ZelnodeBroadcast znb(*pzn);
            uint256 hash = znb.GetHash();
            if (zelnodeman.mapSeenZelnodeBroadcast.count(hash)) {
                zelnodeman.mapSeenZelnodeBroadcast[hash].lastPing = *this;
            }

            pzn->Check(true);
            if (!pzn->IsEnabled()) return false;

            LogPrint("zelnode", "%s - Zelnode ping accepted, vin: %s\n", __func__, vin.prevout.hash.ToString());

            Relay();
            return true;
        }
        LogPrint("zelnode", "%s - Zelnode ping arrived too early, vin: %s\n", __func__, vin.prevout.hash.ToString());
        //nDos = 1; //disable, this is happening frequently and causing banned peers
        return false;
    }
    LogPrint("zelnode", "%s - Couldn't find compatible Zelnode entry, vin: %s\n", __func__, vin.prevout.hash.ToString());

    return false;
}

void ZelnodePing::Relay()
{
    CInv inv(MSG_ZELNODE_PING, GetHash());
    RelayInv(inv);
}


std::string TierToString(int tier)
{
    std::string strStatus = "NONE";

    if (tier == Zelnode::BASIC) strStatus = "BASIC";
    if (tier == Zelnode::SUPER) strStatus = "SUPER";
    if (tier == Zelnode::BAMF) strStatus = "BAMF";

    if (strStatus == "NONE" && tier != 0) strStatus = "UNKNOWN TIER (" + std::to_string(tier) + ")";

    return strStatus;
}



