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
#include "zelnode/zelnodeman.h"
#include "zelnode/obfuscation.h"
#include "sync.h"
#include "util.h"
#include "key_io.h"
#include "spork.h"

// keep track of the scanning errors I've seen
map<uint256, int> mapSeenZelnodeScanningErrors;
// cache block hashes as we calculate them
std::map<int64_t, uint256> mapCacheBlockHashes;

ZelnodeCache g_zelnodeCache;

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
    GetTransaction(vin.prevout.hash, tx2, Params().GetConsensus(), hashBlock, true);
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
//    blockHash = chainActive[chainActive.Height() - 12]->GetBlockHash();
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

bool DecodeHexZelnodeBroadcast(ZelnodeBroadcast& zelnodeBroadcast, std::string strHexZelnodeBroadcast) {

    if (!IsHex(strHexZelnodeBroadcast))
        return false;

    vector<unsigned char> zelnodeData(ParseHex(strHexZelnodeBroadcast));
    CDataStream ssData(zelnodeData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> zelnodeBroadcast;
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
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

bool CheckZelnodeTxSignatures(const CTransaction& transaction)
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
            if (!obfuScationSigner.VerifyMessage(data.pubKey, transaction.sig, strMessage, errorMessage))
                return error("%s - CONFIRM Error: %s", __func__, errorMessage);
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
    std::string public_key = Params().BenchmarkingPublicKey();
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
    int nHeightToExpire = p_nHeight - ZELNODE_CONFIRM_UPDATE_EXPIRATION_HEIGHT;

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
    if (!p_transaction.IsZelnodeTx())
        return false;

    // This function should only be called on UPDATE_CONFIRM tx types
    if (p_transaction.nUpdateType != ZelnodeUpdateType::UPDATE_CONFIRM) {
        return false;
    }

    LOCK(cs);
    // Check the confirm set before contining
    if (!CheckListSet(out))
        return false;

    // Check the mapConfirmedZelnodeData
    if (!mapConfirmedZelnodeData.count(out)) {
        return false;
    }

    // Check to make sure they don't confirm until it has been atleast 30 blocks from there last confirmation
    if (nCurrentHeight - mapConfirmedZelnodeData.at(out).nLastConfirmedBlockHeight <= ZELNODE_CONFIRM_UPDATE_MIN_HEIGHT) {
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

    LogPrintf("%s : Size of mapStartTxTracker: %s\n", __func__, g_zelnodeCache.mapStartTxTracker.size());
    LogPrintf("%s : Size of mapStartTxDosTracker: %s\n", __func__, g_zelnodeCache.mapStartTxDosTracker.size());
    LogPrintf("%s : Size of mapConfirmedZelnodeData: %s\n", __func__, g_zelnodeCache.mapConfirmedZelnodeData.size());
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
    if (nTier == BASIC || nTier == SUPER || nTier == BAMF) {
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
    bool fBasicFound = false;
    bool fSuperFound = false;
    bool fBAMFFound = false;
    CScript basic_script;
    CScript super_script;
    CScript bamf_script;

    COutPoint basic_out;
    COutPoint super_out;
    COutPoint bamf_out;

    // Get the addresses the should be paid
    if (GetNextPayment(basic_dest, BASIC, basic_out)) {
        fBasicFound = true;
    }

    // Get the addresses the should be paid
    if (GetNextPayment(super_dest, SUPER, super_out)) {
        fSuperFound = true;
    }

    // Get the addresses the should be paid
    if (GetNextPayment(bamf_dest, BAMF, bamf_out)) {
        fBAMFFound = true;
    }

    if (fBasicFound) basic_script = GetScriptForDestination(basic_dest);
    if (fSuperFound) super_script = GetScriptForDestination(super_dest);
    if (fBAMFFound) bamf_script = GetScriptForDestination(bamf_dest);

    // Get the amounts that should be paid per address
    CAmount blockValue = GetBlockSubsidy(p_Height, Params().GetConsensus());
    CAmount basic_amount = GetZelnodeSubsidy(p_Height, blockValue, Zelnode::BASIC);
    CAmount super_amount = GetZelnodeSubsidy(p_Height, blockValue, Zelnode::SUPER);
    CAmount bamf_amount = GetZelnodeSubsidy(p_Height, blockValue, Zelnode::BAMF);

    bool fBasicApproved = false;
    bool fSuperApproved = false;
    bool fBAMFApproved = false;

    // Loop through Tx to make sure they all got paid
    for (const auto& out : coinbase.vout) {
        if (fBasicFound)
            if (out.scriptPubKey == basic_script)
                if (out.nValue == basic_amount)
                    fBasicApproved = true;

        if (fSuperFound)
            if (out.scriptPubKey == super_script)
                if (out.nValue == super_amount)
                    fSuperApproved = true;

        if (fBAMFFound)
            if (out.scriptPubKey == bamf_script)
                if (out.nValue == bamf_amount)
                    fBAMFApproved = true;
    }

    bool fFail = false;
    if (fBasicFound && !fBasicApproved) {
        fFail = true;
        error("Invalid block zelnode payee list: Invalid basic payee. Should be paying : %s -> %u", EncodeDestination(basic_dest), basic_amount);
    }

    if (fSuperFound && !fSuperApproved) {
        fFail = true;
        error("Invalid block zelnode payee list: Invalid super payee. Should be paying : %s -> %u", EncodeDestination(super_dest), super_amount);
    }

    if (fBAMFFound && !fBAMFApproved) {
        fFail = true;
        error("Invalid block zelnode payee list: Invalid BAMF payee. Should be paying : %s -> %u", EncodeDestination(bamf_dest), bamf_amount);
    }

    if (p_zelnodeCache) {
        if (fBasicFound)
            p_zelnodeCache->AddPaidNode(basic_out, p_Height);
        if (fSuperFound)
            p_zelnodeCache->AddPaidNode(super_out, p_Height);
        if (fBAMFFound)
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
    bool fBasicFound = true;
    bool fSuperFound = true;
    bool fBAMFFound = true;

    COutPoint basic_out;
    COutPoint super_out;
    COutPoint bamf_out;

    int nTotalPayouts = 3; // Total number of zelnode payments there could be

    if (!g_zelnodeCache.GetNextPayment(basic_dest, BASIC, basic_out)) {
        fBasicFound = false;
        nTotalPayouts--;
    }

    if (!g_zelnodeCache.GetNextPayment(super_dest, SUPER, super_out)) {
        fSuperFound = false;
        nTotalPayouts--;
    }

    if (!g_zelnodeCache.GetNextPayment(bamf_dest, BAMF, bamf_out)) {
        fBAMFFound = false;
        nTotalPayouts--;
    }

    CAmount blockValue = GetBlockSubsidy(pindexPrev->nHeight + 1, Params().GetConsensus());
    CAmount basic_amount = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, Zelnode::BASIC);
    CAmount super_amount = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, Zelnode::SUPER);
    CAmount bamf_amount = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, Zelnode::BAMF);

    if (nTotalPayouts > 0) {
        txNew.vout.resize(nTotalPayouts + 1);
    }

    CAmount nMinerReward = blockValue;
    int currentIndex = 1;
    if (fBasicFound) {
        txNew.vout[currentIndex].scriptPubKey = GetScriptForDestination(basic_dest);
        txNew.vout[currentIndex].nValue = basic_amount;
        nMinerReward -= basic_amount;
        currentIndex++;

        if (payments)
            payments->insert(std::make_pair(Zelnode::BASIC, std::make_pair(GetScriptForDestination(basic_dest), basic_amount)));
    }

    if (fSuperFound) {
        txNew.vout[currentIndex].scriptPubKey = GetScriptForDestination(super_dest);
        txNew.vout[currentIndex].nValue = super_amount;
        nMinerReward -= super_amount;
        currentIndex++;

        if (payments)
            payments->insert(std::make_pair(Zelnode::SUPER, std::make_pair(GetScriptForDestination(super_dest), super_amount)));
    }

    if (fBAMFFound) {
        txNew.vout[currentIndex].scriptPubKey = GetScriptForDestination(bamf_dest);
        txNew.vout[currentIndex].nValue = bamf_amount;
        nMinerReward -= bamf_amount;

        if (payments)
            payments->insert(std::make_pair(Zelnode::BAMF, std::make_pair(GetScriptForDestination(bamf_dest), bamf_amount)));
    }

    txNew.vout[0].nValue = nMinerReward;

    LogPrint("dzelnode","Zelnode Basic payment of %s to %s\n", FormatMoney(basic_amount).c_str(), EncodeDestination(basic_dest).c_str());
    LogPrint("dzelnode","Zelnode Super payment of %s to %s\n", FormatMoney(super_amount).c_str(), EncodeDestination(super_dest).c_str());
    LogPrint("dzelnode","Zelnode BAMF payment of %s to %s\n", FormatMoney(bamf_amount).c_str(), EncodeDestination(bamf_dest).c_str());
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
            error("%s : This should never happen. When undo an update confirm. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.first.hash.GetHex());
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
        g_zelnodeCache.setDirtyOutPoint.insert(item.first);
    }

    bool fUndoExpiredAddedToList = false;
    bool fUndoExpiredAddedToListBasic = false;
    bool fUndoExpiredAddedToListSuper = false;
    bool fUndoExpiredAddedToListBAMF = false;
    for (const auto& item : setUndoExpireConfirm) {
        g_zelnodeCache.mapConfirmedZelnodeData.insert(std::make_pair(item.collateralIn, item));
        g_zelnodeCache.setDirtyOutPoint.insert(item.collateralIn);

        if (g_zelnodeCache.CheckListHas(item)) {
            // already in set, and therefor list. Skip it
            continue;
        } else {
            vecNodesToAdd.emplace_back(item);
            if (item.nTier == Zelnode::BASIC) fUndoExpiredAddedToListBasic = true;
            else if (item.nTier == Zelnode::SUPER) fUndoExpiredAddedToListSuper = true;
            else if (item.nTier == Zelnode::BAMF) fUndoExpiredAddedToListBAMF = true;
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
            }

            // TODO, once we are running smoothly. We should be able to place into a list, sort the list. Add add the nodes in order that is is sorted.
            // TODO, if we do this, we should be able to not sort the list, if we only add new confirmed nodes to it.
            vecNodesToAdd.emplace_back(data);

            if (data.nTier == Zelnode::BASIC) fUndoExpiredAddedToListBasic = true;
            else if (data.nTier == Zelnode::SUPER) fUndoExpiredAddedToListSuper = true;
            else if (data.nTier == Zelnode::BAMF) fUndoExpiredAddedToListBAMF = true;

            g_zelnodeCache.setDirtyOutPoint.insert(item.first);
        } else {
            error("%s : This should never happen. When moving from start map to confirm map. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__,  item.first.hash.GetHex());
        }
    }

    bool fRemoveBasic = false;
    bool fRemoveSuper = false;
    bool fRemoveBAMF = false;
    for (const auto& item : setUndoAddToConfirm) {
        if (g_zelnodeCache.mapConfirmedZelnodeData.count(item)) {
            ZelnodeCacheData data = g_zelnodeCache.mapConfirmedZelnodeData.at(item);

            // Remove from Confirm Tracking
            g_zelnodeCache.mapConfirmedZelnodeData.erase(item);

            // adding it to this set, means that it will go and remove the outpoint from the list, and the set if it is in there
            setRemoveFromList.insert(data.collateralIn);

            if (data.nTier == Zelnode::BASIC) fRemoveBasic = true;
            else if (data.nTier == Zelnode::BASIC) fRemoveSuper = true;
            else if (data.nTier == Zelnode::BASIC) fRemoveBAMF = true;

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

            if (g_zelnodeCache.mapZelnodeList.at(nTier).setConfirmedTxInList.count(item.first)) {

                if (g_zelnodeCache.mapZelnodeList.at(nTier).listConfirmedZelnodes.back().out != item.first) {
                    error("%s : This should never happen. When undoing a paid node. The back most item in the list isn't the correct outpoint. Report this to the dev team to figure out what is happening: %s\n", __func__, item.first.hash.GetHex());
                }

                // The node that we are undoing the paid height on, should always be the last node in the list. So, we need
                // to get the data. Remove the entry from the back of the list, and put it at the front.
                // This allows us to not have to sort() the list afterwards. If this was the only change
                ZelnodeListData old_data = g_zelnodeCache.mapZelnodeList.at(nTier).listConfirmedZelnodes.back();
                g_zelnodeCache.mapZelnodeList.at(nTier).listConfirmedZelnodes.pop_back();
                old_data.nLastPaidHeight = item.second;
                g_zelnodeCache.mapZelnodeList.at(nTier).listConfirmedZelnodes.emplace_front(old_data);
            }
        } else {
            error("%s : This should never happen. When undoing a paid node. ZelnodeData not found. Report this to the dev team to figure out what is happening: %s\n", __func__, item.first.hash.GetHex());
        }
    }

    //! DO ALL REMOVAL FROM THE ITEMS IN THE LIST HERE (using iterators so we can remove items while going over the list a single time
    // Currently only have to do this when moving from CONFIRM->START (undo blocks only)
    if (setRemoveFromList.size()) {
        if (fRemoveBasic) {
            g_zelnodeCache.EraseFromList(setRemoveFromList, Zelnode::BASIC);
        }

        if (fRemoveSuper) {
            g_zelnodeCache.EraseFromList(setRemoveFromList, Zelnode::SUPER);
        }

        if (fRemoveBAMF ) {
            g_zelnodeCache.EraseFromList(setRemoveFromList, Zelnode::BAMF);
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
        if (fRemoveBasic || fUndoExpiredAddedToListBasic || mapPaidNodes.count(BASIC)) {
            g_zelnodeCache.SortList(Zelnode::BASIC);
        }

        if (fRemoveSuper || fUndoExpiredAddedToListSuper || mapPaidNodes.count(SUPER)) {
            g_zelnodeCache.SortList(Zelnode::SUPER);
        }

        if (fRemoveBAMF || fUndoExpiredAddedToListBAMF || mapPaidNodes.count(BAMF)) {
            g_zelnodeCache.SortList(Zelnode::BAMF);
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
    if (nTier == Zelnode::BASIC)
        mapZelnodeList.at(Zelnode::BASIC).listConfirmedZelnodes.sort();
    else if (nTier == Zelnode::SUPER)
        mapZelnodeList.at(Zelnode::SUPER).listConfirmedZelnodes.sort();
    else if (nTier == Zelnode::BAMF)
        mapZelnodeList.at(Zelnode::BAMF).listConfirmedZelnodes.sort();
}

// Needs to be protected by locking cs before calling
bool ZelnodeCache::CheckListHas(const ZelnodeCacheData& p_zelnodeData)
{
    if (p_zelnodeData.nTier == Zelnode::BASIC)
        return mapZelnodeList.at(Zelnode::BASIC).setConfirmedTxInList.count(p_zelnodeData.collateralIn);
    else if (p_zelnodeData.nTier == Zelnode::SUPER)
        return mapZelnodeList.at(Zelnode::SUPER).setConfirmedTxInList.count(p_zelnodeData.collateralIn);
    else if (p_zelnodeData.nTier == Zelnode::BAMF)
        return mapZelnodeList.at(Zelnode::BAMF).setConfirmedTxInList.count(p_zelnodeData.collateralIn);
}

// Needs to be protected by locking cs before calling
bool ZelnodeCache::CheckListSet(const COutPoint& p_OutPoint)
{
    if (mapZelnodeList.at(Zelnode::BASIC).setConfirmedTxInList.count(p_OutPoint)) {
        return true;
    } else if (mapZelnodeList.at(Zelnode::SUPER).setConfirmedTxInList.count(p_OutPoint)) {
        return true;
    } else if (mapZelnodeList.at(Zelnode::BAMF).setConfirmedTxInList.count(p_OutPoint)) {
        return true;
    }

    return false;
}

void ZelnodeCache::InsertIntoList(const ZelnodeCacheData& p_zelnodeData)
{
    ZelnodeListData listData(p_zelnodeData);
    if (p_zelnodeData.nTier == Zelnode::BASIC) {
        mapZelnodeList.at(Zelnode::BASIC).setConfirmedTxInList.insert(p_zelnodeData.collateralIn);
        mapZelnodeList.at(Zelnode::BASIC).listConfirmedZelnodes.emplace_front(listData);
    }
    else if (p_zelnodeData.nTier == Zelnode::SUPER) {
        mapZelnodeList.at(Zelnode::SUPER).setConfirmedTxInList.insert(p_zelnodeData.collateralIn);
        mapZelnodeList.at(Zelnode::SUPER).listConfirmedZelnodes.emplace_front(listData);
    }
    else if (p_zelnodeData.nTier == Zelnode::BAMF) {
        mapZelnodeList.at(Zelnode::BAMF).setConfirmedTxInList.insert(p_zelnodeData.collateralIn);
        mapZelnodeList.at(Zelnode::BAMF).listConfirmedZelnodes.emplace_front(listData);
    }
}

void ZelnodeCache::EraseFromListSet(const COutPoint& p_OutPoint)
{
    if (mapZelnodeList.at(Zelnode::BASIC).setConfirmedTxInList.count(p_OutPoint))
        mapZelnodeList.at(Zelnode::BASIC).setConfirmedTxInList.erase(p_OutPoint);
    else if (mapZelnodeList.at(Zelnode::SUPER).setConfirmedTxInList.count(p_OutPoint))
        mapZelnodeList.at(Zelnode::SUPER).setConfirmedTxInList.erase(p_OutPoint);
    else if (mapZelnodeList.at(Zelnode::BAMF).setConfirmedTxInList.count(p_OutPoint))
        mapZelnodeList.at(Zelnode::BAMF).setConfirmedTxInList.erase(p_OutPoint);
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

void ZelnodeCache::CountNetworks(int& ipv4, int& ipv6, int& onion) {
    for (auto &entry : mapConfirmedZelnodeData) {
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
    }
}
