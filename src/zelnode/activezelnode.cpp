// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "activezelnode.h"
#include "addrman.h"
#include "zelnode/zelnode.h"
#include "zelnode/zelnodeconfig.h"
#include "zelnode/zelnodeman.h"
#include "protocol.h"
#include "zelnode/spork.h"
#include "key_io.h"
#include "zelnode/benchmarks.h"


//
// Bootup the Zelnode, look for a 10000 ZEL input and register on the network
//
void ActiveZelnode::ManageStatus()
{
    std::string errorMessage;

    if (!fZelnode) return;

    if (fDebug) LogPrintf("%s - Begin\n", __func__);

    //need correct blocks to send ping
    if (Params().NetworkID() != CBaseChainParams::REGTEST && !zelnodeSync.IsBlockchainSynced()) {
        status = ACTIVE_ZELNODE_SYNC_IN_PROCESS;
        LogPrintf("%s - %s\n", __func__, GetStatus());
        return;
    }

    if (status == ACTIVE_ZELNODE_SYNC_IN_PROCESS) status = ACTIVE_ZELNODE_INITIAL;

    if (status == ACTIVE_ZELNODE_INITIAL) {
        Zelnode* pzn;
        pzn = zelnodeman.Find(pubKeyZelnode);
        if (pzn != NULL) {
            pzn->Check();
            if (pzn->IsEnabled() && pzn->protocolVersion == PROTOCOL_VERSION) EnableHotColdZelnode(pzn->vin, pzn->addr);
        }
    }

    if (status == ACTIVE_ZELNODE_STARTED) {
        Zelnode* pzn;
        pzn = zelnodeman.Find(pubKeyZelnode);
        if (pzn != NULL) {
            if (!BuildZelnodeBroadcast(errorMessage))
                return;
        }
    }

    if (status != ACTIVE_ZELNODE_STARTED) {
        // Set defaults
        status = ACTIVE_ZELNODE_NOT_CAPABLE;
        notCapableReason = "";

        if (pwalletMain->IsLocked()) {
            notCapableReason = "Wallet is locked.";
            LogPrintf("%s - not capable: %s\n", __func__, notCapableReason);
            return;
        }

        if (pwalletMain->GetBalance() == 0) {
            notCapableReason = "Hot node, waiting for remote activation.";
            LogPrintf("%s - not capable: %s\n", __func__, notCapableReason);
            return;
        }

        if (strZelnodeAddr.empty()) {
            if (!GetLocal(service)) {
                notCapableReason = "Can't detect external address. Please use the zelnodeaddr configuration option.";
                LogPrintf("%s - not capable: %s\n", __func__, notCapableReason);
                return;
            }
        } else {
            service = CService(strZelnodeAddr);
        }

        // The service needs the correct default port to work properly
        if(!ZelnodeBroadcast::CheckDefaultPort(strZelnodeAddr, errorMessage, "ActiveZelnode::ManageStatus()"))
            return;

        LogPrintf("%s - Checking inbound connection to '%s'\n", __func__, service.ToString());

        CNode* pnode = ConnectNode((CAddress)service, NULL, false);
        if (!pnode) {
            notCapableReason = "Could not connect to " + service.ToString();
            LogPrintf("%s - not capable: %s\n", __func__, notCapableReason);
            return;
        }
        pnode->Release();

        // Choose coins to use
        CPubKey pubKeyCollateralAddress;
        CKey keyCollateralAddress;

        if (GetZelNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress)) {
            if (GetInputAge(vin) < ZELNODE_MIN_CONFIRMATIONS) {
                status = ACTIVE_ZELNODE_INPUT_TOO_NEW;
                notCapableReason = strprintf("%s - %d confirmations", GetStatus(), GetInputAge(vin));
                LogPrintf("%s - %s\n", __func__, notCapableReason);
                return;
            }

            LOCK(pwalletMain->cs_wallet);
            pwalletMain->LockCoin(vin.prevout);

            // send to all nodes
            CPubKey pubKeyZelnode;
            CKey keyZelnode;

            if (!obfuScationSigner.SetKey(strZelnodePrivKey, errorMessage, keyZelnode, pubKeyZelnode)) {
                notCapableReason = "Error upon calling SetKey: " + errorMessage;
                LogPrintf("Register::ManageStatus() - %s\n", notCapableReason);
                return;
            }

            ZelnodeBroadcast znb;
            CMutableTransaction mut;
            if (!CreateBroadcast(vin, service, keyCollateralAddress, pubKeyCollateralAddress, keyZelnode, pubKeyZelnode, errorMessage, znb, mut)) {
                notCapableReason = "Error on Register: " + errorMessage;
                LogPrintf("%s - %s\n", __func__, notCapableReason);
                return;
            }

            //send to all peers
            LogPrintf("%s - Relay broadcast vin = %s\n", __func__, vin.ToString());
            znb.Relay();

            LogPrintf("%s - Is capable zelnode!\n", __func__);
            status = ACTIVE_ZELNODE_STARTED;

            return;
        } else {
            notCapableReason = "Could not find suitable coins!";
            LogPrintf("%s - %s\n", __func__, notCapableReason);
            return;
        }
    }

    //send to all peers
    if (!SendZelnodePing(errorMessage)) {
        LogPrintf("%s - Error on Ping: %s\n", __func__, errorMessage);
    }
}


void ActiveZelnode::ManageDeterministricZelnode()
{
    // We only want to run this command on the VPS that has zelnode=1 and is running zelbenchd
    if (!fZelnode)
        return;

    std::string errorMessage;

    // Start confirm transaction
    CMutableTransaction mutTx;
    mutTx.nVersion = ZELNODE_TX_VERSION;

    // Get the current height
    int nHeight = chainActive.Height();

    // Check if zelnode is currently in the start list, if so we will be building the Initial Confirm Transaction
    // If the zelnode is already confirmed check to see if it needs to be re confirmed, if so, Create the Update Transaction
    if (g_zelnodeCache.InStartTracker(activeZelnode.deterministicOutPoint)) {
        // Check if we currently have a tx with the same vin in our mempool
        // If we do, Resend the wallet transactions to our peers
        if (mempool.mapZelnodeTxMempool.count(activeZelnode.deterministicOutPoint)) {
            if (pwalletMain)
                pwalletMain->ResendWalletTransactions(GetAdjustedTime());
            LogPrintf("Zelnode found in start tracker. Skipping confirm transaction creation, because tranasaction already in mempool %s\n", activeZelnode.deterministicOutPoint.ToString());
            return;
        }

        // If we don't have one in our mempool. That means it is time to confirm the zelnode
        if (nHeight - nLastTriedToConfirm > 3) { // Only try this every couple blocks
            activeZelnode.BuildDeterministicConfirmTx(mutTx, ZelnodeUpdateType::INITIAL_CONFIRM);
        } else {
            return;
        }
    } else if (g_zelnodeCache.CheckIfNeedsNextConfirm(activeZelnode.deterministicOutPoint)) {
        activeZelnode.BuildDeterministicConfirmTx(mutTx, ZelnodeUpdateType::UPDATE_CONFIRM);
    } else {
        LogPrintf("Zelnode found nothing to do: %s\n", activeZelnode.deterministicOutPoint.ToString());
        return;
    }

    if (activeZelnode.SignDeterministicConfirmTx(mutTx, errorMessage)) {
        CReserveKey reservekey(pwalletMain);
        CTransaction tx(mutTx);
        CTransaction signedTx;
        if (GetBenchmarkSignedTransaction(tx, signedTx, errorMessage)) {
            CWalletTx walletTx(pwalletMain, signedTx);
            pwalletMain->CommitTransaction(walletTx, reservekey);
            nLastTriedToConfirm = nHeight;
        } else {
            error("Failed to sign benchmarking for zelnode confirm transaction for outpoint %s, Error message: %s", activeZelnode.deterministicOutPoint.ToString(), errorMessage);
            return;
        }
    } else {
        error("Failed to sign zelnode for confirm transaction for outpoint %s, Error message: %s", activeZelnode.deterministicOutPoint.ToString(), errorMessage);
        return;
    }
}

std::string ActiveZelnode::GetStatus()
{
    switch (status) {
        case ACTIVE_ZELNODE_INITIAL:
            return "Node just started, not yet activated";
        case ACTIVE_ZELNODE_SYNC_IN_PROCESS:
            return "Sync in progress. Must wait until sync is complete to start Zelnode";
        case ACTIVE_ZELNODE_INPUT_TOO_NEW:
            return strprintf("Zelnode input must have at least %d confirmations", ZELNODE_MIN_CONFIRMATIONS);
        case ACTIVE_ZELNODE_NOT_CAPABLE:
            return "Not capable zelnode: " + notCapableReason;
        case ACTIVE_ZELNODE_STARTED:
            return "Zelnode successfully started";
        default:
            return "unknown";
    }
}

bool ActiveZelnode::SendZelnodePing(std::string& errorMessage)
{
    if (status != ACTIVE_ZELNODE_STARTED) {
        errorMessage = "Zelnode is not in a running status";
        return false;
    }

    CPubKey pubKeyZelnode;
    CKey keyZelnode;

    if (!obfuScationSigner.SetKey(strZelnodePrivKey, errorMessage, keyZelnode, pubKeyZelnode)) {
        errorMessage = strprintf("Error upon calling SetKey: %s\n", errorMessage);
        return false;
    }

    LogPrintf("%s - Relay Zelnode Ping vin = %s\n", __func__, vin.ToString());

    ZelnodePing znp(vin);
    if (!znp.Sign(keyZelnode, pubKeyZelnode)) {
        errorMessage = "Couldn't sign Zelnode Ping";
        return false;
    }

    // Update lastPing for our zelnode in Zelnode list
    Zelnode* pzn = zelnodeman.Find(vin);
    if (pzn != NULL) {
        if (pzn->IsPingedWithin(ZELNODE_PING_SECONDS, znp.sigTime)) {
            errorMessage = "Too early to send Zelnode Ping";
            return false;
        }

        pzn->lastPing = znp;
        zelnodeman.mapSeenZelnodePing.insert(make_pair(znp.GetHash(), znp));

        //zelnodeman.mapSeenZelnodeBroadcast.lastPing is probably outdated, so we'll update it
        ZelnodeBroadcast znb(*pzn);
        uint256 hash = znb.GetHash();
        if (zelnodeman.mapSeenZelnodeBroadcast.count(hash)) zelnodeman.mapSeenZelnodeBroadcast[hash].lastPing = znp;

        znp.Relay();

        return true;
    } else {
        // Seems like we are trying to send a ping while the Zelnode is not registered in the network
        errorMessage = "Obfuscation Zelnode List doesn't include our Zelnode, shutting down Zelnode pinging service! " + vin.ToString();
        status = ACTIVE_ZELNODE_NOT_CAPABLE;
        notCapableReason = errorMessage;
        return false;
    }
}

bool ActiveZelnode::CreateBroadcast(std::string strService, std::string strKeyZelnode, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, ZelnodeBroadcast &znb, CMutableTransaction& mutTransaction, bool fOffline)
{
    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyZelnode;
    CKey keyZelnode;

    //need correct blocks to send ping
    if (!fOffline && !zelnodeSync.IsBlockchainSynced()) {
        errorMessage = "Sync in progress. Must wait until sync is complete to start Zelnode";
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    if (!obfuScationSigner.SetKey(strKeyZelnode, errorMessage, keyZelnode, pubKeyZelnode)) {
        errorMessage = strprintf("Can't find keys for zelnode %s - %s", strService, errorMessage);
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    std::string strErrorMessage;
    if (!GetZelNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, strTxHash, strOutputIndex, strErrorMessage)) {
        errorMessage = strprintf("Could not allocate vin %s:%s for zelnode %s", strTxHash, strOutputIndex,
                                 strService);
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    CService service = CService(strService);
    // The service needs the correct default port to work properly
    if (!ZelnodeBroadcast::CheckDefaultPort(strService, errorMessage, "ActiveZelnode::CreateBroadcast()"))
        return false;

    addrman.Add(CAddress(service), CNetAddr("127.0.0.1"), 2 * 60 * 60);
    return CreateBroadcast(vin, CService(strService), keyCollateralAddress, pubKeyCollateralAddress, keyZelnode,
                           pubKeyZelnode, errorMessage, znb, mutTransaction);
}

bool ActiveZelnode::CreateBroadcast(CTxIn vin, CService service, CKey key, CPubKey pubKey, CKey keyZelnode,
                                    CPubKey pubKeyZelnode, std::string& errorMessage, ZelnodeBroadcast& znb, CMutableTransaction& mutTransaction)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    ZelnodePing znp(vin);
    if (!znp.Sign(keyZelnode, pubKeyZelnode)) {
        errorMessage = strprintf("Failed to sign ping, vin: %s", vin.ToString());
        LogPrintf("%s -  %s\n", __func__, errorMessage);
        znb = ZelnodeBroadcast();
        return false;
    }

    // Create zelnode transaction
    if (mutTransaction.nType == ZELNODE_START_TX_TYPE) {
        mutTransaction.ip = service.ToStringIP();
        mutTransaction.collateralIn = vin.prevout;
        mutTransaction.collateralPubkey = pubKey;
        mutTransaction.pubKey = pubKeyZelnode;
    } else if (mutTransaction.nType == ZELNODE_CONFIRM_TX_TYPE) {
        mutTransaction.collateralIn = vin.prevout;
        if (mutTransaction.nUpdateType != ZelnodeUpdateType::UPDATE_CONFIRM)
            mutTransaction.nUpdateType = ZelnodeUpdateType::INITIAL_CONFIRM;
    }

    znb = ZelnodeBroadcast(service, vin, pubKey, pubKeyZelnode, PROTOCOL_VERSION);
    znb.lastPing = znp;

    if (!znb.Sign(key)) {
        errorMessage = strprintf("Failed to sign broadcast, vin: %s", vin.ToString());
        LogPrintf("%s -  %s\n", __func__, errorMessage);
        znb = ZelnodeBroadcast();
        return false;
    }

    return true;
}

bool ActiveZelnode::GetZelNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey)
{
    std::string strErrorMessage;
    return GetZelNodeVin(vin, pubkey, secretKey, "", "", strErrorMessage);
}

bool ActiveZelnode::GetZelNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    // Find possible candidates
    TRY_LOCK(pwalletMain->cs_wallet, fWallet);
    if (!fWallet) return false;

    vector<std::pair<COutput, CAmount>> possibleCoins = SelectCoinsZelnode();
    COutput* selectedOutput;

    // Find the vin
    if (!strTxHash.empty()) {
        // Let's find it
        uint256 txHash = uint256S(strTxHash);
        int outputIndex;
        try {
            outputIndex = std::stoi(strOutputIndex.c_str());
        } catch (const std::exception& e) {
            errorMessage = "Failed to convert index to an integer";
            LogPrintf("%s: %s on strOutputIndex\n", __func__, e.what());
            return false;
        }

        bool found = false;
        for (auto& pair : possibleCoins) {
            if (pair.first.tx->GetHash() == txHash && pair.first.i == outputIndex) {
                selectedOutput = &pair.first;
                found = true;
                break;
            }
        }
        if (!found) {
            errorMessage = "Could not find collateral in wallet";
            LogPrintf("%s - Could not locate valid vin\n", __func__);
            return false;
        }
    } else {
        // No output specified,  Select the first one
        if (possibleCoins.size() > 0) {
            selectedOutput = &possibleCoins[0].first;
        } else {
            errorMessage = "No possible coins found for zelnodes";
            LogPrintf("%s - Could not locate specified vin from possible list\n", __func__);
            return false;
        }
    }

    if (selectedOutput->nDepth < ZELNODE_MIN_CONFIRMATION_DETERMINISTIC) {
        errorMessage = strprintf("Zelnode hasn't met confirmation requirement (remaining confirmations required: %d)\n", ZELNODE_MIN_CONFIRMATION_DETERMINISTIC - selectedOutput->nDepth);
        LogPrintf("%s - zelnode hasn't met confirmation requirement (remaining confirmations required: %d)\n", __func__, ZELNODE_MIN_CONFIRMATION_DETERMINISTIC - selectedOutput->nDepth);
        return false;
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}

// Extract Zelnode vin information from output
bool ActiveZelnode::GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;

    CScript pubScript;
    vin = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);

    CKeyID* keyid;
    keyid = boost::get<CKeyID>(&address1);

    if (!keyid) {
        LogPrintf("%s - Address does not refer to a key\n", __func__);
        return false;
    }

    if (!pwalletMain->GetKey(*keyid, secretKey)) {
        LogPrintf("%s - Private key for address is not known\n", __func__);
        return false;
    }

    pubkey = secretKey.GetPubKey();

    return true;
}

// get all possible outputs for running Zelnode
vector<std::pair<COutput, CAmount>> ActiveZelnode::SelectCoinsZelnode()
{
    vector<COutput> vCoins;
    vector<std::pair<COutput, CAmount>> filteredCoins;
    vector<COutPoint> confLockedCoins;

    // Temporary unlock ZN coins from zelnode.conf
    if (GetBoolArg("-znconflock", true)) {
        uint256 znTxHash;
        for (ZelnodeConfig::ZelnodeEntry zelnodeEntry : zelnodeConfig.getEntries()) {
            znTxHash.SetHex(zelnodeEntry.getTxHash());

            int nIndex;
            if(!zelnodeEntry.castOutputIndex(nIndex))
                continue;

            COutPoint outpoint = COutPoint(znTxHash, nIndex);
            confLockedCoins.push_back(outpoint);
            pwalletMain->UnlockCoin(outpoint);
        }
    }

    // Retrieve all possible outputs
    pwalletMain->AvailableCoins(vCoins, true, NULL, false, false, ALL_ZELNODE);

    // Lock ZN coins from zelnode.conf back if they where temporary unlocked
    if (!confLockedCoins.empty()) {
        for (COutPoint outpoint: confLockedCoins)
            pwalletMain->LockCoin(outpoint);
    }

    // Filter
    for (const COutput& out : vCoins) {
        if (out.tx->vout[out.i].nValue == ZELNODE_BASIC_COLLATERAL * COIN) { //exactly
            filteredCoins.push_back(std::make_pair(out, ZELNODE_BASIC_COLLATERAL * COIN));
        }

        else if (out.tx->vout[out.i].nValue == ZELNODE_SUPER_COLLATERAL * COIN) { //exactly
            filteredCoins.push_back(std::make_pair(out, ZELNODE_SUPER_COLLATERAL * COIN));
        }

        else if (out.tx->vout[out.i].nValue == ZELNODE_BAMF_COLLATERAL * COIN) { //exactly
            filteredCoins.push_back(std::make_pair(out, ZELNODE_BAMF_COLLATERAL * COIN));
        }
    }
    return filteredCoins;
}

// when starting a Zelnode, this can enable to run as a hot wallet with no funds
bool ActiveZelnode::EnableHotColdZelnode(CTxIn& newVin, CService& newService)
{
    if (!fZelnode) return false;

    status = ACTIVE_ZELNODE_STARTED;

    //The values below are needed for signing znping messages going forward
    vin = newVin;
    service = newService;

    LogPrintf("%s - Enabled! You may shut down the cold daemon.\n", __func__);

    return true;
}

bool ActiveZelnode::BuildZelnodeBroadcast(std::string& errorMessage) {
    // Choose coins to use
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;

    if (GetZelNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress)) {
        LOCK(pwalletMain->cs_wallet);
        pwalletMain->LockCoin(vin.prevout);

        // send to all nodes
        CPubKey pubKeyZelnode;
        CKey keyZelnode;

        if (!obfuScationSigner.SetKey(strZelnodePrivKey, errorMessage, keyZelnode, pubKeyZelnode)) {
            notCapableReason = "Error upon calling SetKey: " + errorMessage;
            LogPrintf("Register::ManageStatus() - %s\n", notCapableReason);
            return false;
        }

        ZelnodeBroadcast znb;
        CMutableTransaction mut;
        if (!CreateBroadcast(vin, service, keyCollateralAddress, pubKeyCollateralAddress, keyZelnode,
                             pubKeyZelnode, errorMessage, znb, mut)) {
            notCapableReason = "Error on Register: " + errorMessage;
            LogPrintf("%s - %s\n", __func__, notCapableReason);
            return false;
        }

        //send to all peers
        LogPrintf("%s - Relay broadcast vin = %s\n", __func__, vin.ToString());
        znb.Relay();

        return true;
    }
}

bool ActiveZelnode::SignDeterministicStartTx(CMutableTransaction& mutableTransaction, std::string& errorMessage)
{
    if (mutableTransaction.nType != ZELNODE_START_TX_TYPE) {
        errorMessage = "invalid-tx-type";
        return error("%s : %s", __func__, errorMessage);
    }

    CTxIn txin;
    CPubKey pubKeyAddressNew;
    CKey keyAddressNew;
    if (!pwalletMain->GetZelnodeVinAndKeys(txin, pubKeyAddressNew, keyAddressNew, mutableTransaction.collateralIn.hash.GetHex(), std::to_string(mutableTransaction.collateralIn.n))) {
        errorMessage = strprintf("Could not allocate txin %s:%s for zelnode %s", mutableTransaction.collateralIn.hash.GetHex(), std::to_string(mutableTransaction.collateralIn.n), mutableTransaction.ip);
        LogPrintf("zelnode","%s -- %s\n", __func__, errorMessage);
        return false;
    }

    // Set the public key for the zelnode collateral
    mutableTransaction.collateralPubkey = pubKeyAddressNew;

    if (mutableTransaction.nType == ZELNODE_START_TX_TYPE) {
        std::string errorMessage;
        mutableTransaction.sigTime = GetAdjustedTime();

        std::string strMessage = mutableTransaction.GetHash().GetHex();

        if (!obfuScationSigner.SignMessage(strMessage, errorMessage, mutableTransaction.sig, keyAddressNew))
            return error("%s - Error: Sign Zelnode for start transaction %s", __func__, errorMessage);

        if (!obfuScationSigner.VerifyMessage(mutableTransaction.collateralPubkey, mutableTransaction.sig, strMessage, errorMessage))
            return error("%s - Error: Verify Zelnode for start transaction: %s", __func__, errorMessage);

        return true;
    }

    return false;
}

bool ActiveZelnode::SignDeterministicConfirmTx(CMutableTransaction& mutableTransaction, std::string& errorMessage)
{
    std::string strErrorRet;

    if (mutableTransaction.nType != ZELNODE_CONFIRM_TX_TYPE) {
        errorMessage = "invalid-tx-type";
        return error("%s : %s", __func__, errorMessage);
    }

    auto data = g_zelnodeCache.GetZelnodeData(mutableTransaction.collateralIn);

    if (data.IsNull()) {
        errorMessage = "zelnode-data-is-null";
        return error("%s : %s", __func__, errorMessage);
    }

    // We need to sign the mutable transaction
    mutableTransaction.sigTime = GetAdjustedTime();

    std::string strMessage = mutableTransaction.collateralIn.ToString() + std::to_string(mutableTransaction.collateralIn.n) + std::to_string(mutableTransaction.nUpdateType) + std::to_string(mutableTransaction.sigTime);

    // send to all nodes
    CPubKey pubKeyZelnode;
    CKey keyZelnode;

    if (!obfuScationSigner.SetKey(strZelnodePrivKey, errorMessage, keyZelnode, pubKeyZelnode)) {
        notCapableReason = "Error upon calling SetKey: " + errorMessage;
        errorMessage = "unable-set-key";
        return error("%s : %s", __func__, errorMessage);
    }

    if (data.pubKey != pubKeyZelnode) {
        return error("%s - PubKey miss match", __func__);
    }

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage, mutableTransaction.sig, keyZelnode))
        return error("%s - Error: Signing Zelnode %s", __func__, errorMessage);

    if (!obfuScationSigner.VerifyMessage(pubKeyZelnode, mutableTransaction.sig, strMessage, errorMessage))
        return error("%s - Error: Verify Zelnode sig %s", __func__, errorMessage);

    return true;
}

bool ActiveZelnode::BuildDeterministicStartTx(std::string strKeyZelnode, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, CMutableTransaction& mutTransaction)
{
    // wait for reindex and/or import to finish
    if (IsInitialBlockDownload(Params())) {
        errorMessage = "block chain is downloading";
        return false;
    }

    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyZelnode;
    CKey keyZelnode;

    if (!obfuScationSigner.SetKey(strKeyZelnode, errorMessage, keyZelnode, pubKeyZelnode)) {
        errorMessage = strprintf("Can't find keys for zelnode - %s", errorMessage);
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    if (!GetZelNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, strTxHash, strOutputIndex, errorMessage)) {
        if (errorMessage.empty())
            errorMessage = strprintf("Could not allocate vin %s:%s for zelnode", strTxHash, strOutputIndex);
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    mutTransaction.nType = ZELNODE_START_TX_TYPE;

    // Create zelnode transaction
    if (mutTransaction.nType == ZELNODE_START_TX_TYPE) {
        mutTransaction.collateralIn = vin.prevout;
        mutTransaction.collateralPubkey = pubKeyCollateralAddress;
        mutTransaction.pubKey = pubKeyZelnode;
    } else if (mutTransaction.nType == ZELNODE_CONFIRM_TX_TYPE) {
        mutTransaction.collateralIn = vin.prevout;
        if (mutTransaction.nUpdateType != ZelnodeUpdateType::UPDATE_CONFIRM)
            mutTransaction.nUpdateType = ZelnodeUpdateType::INITIAL_CONFIRM;
    }

    return true;
}

void ActiveZelnode::BuildDeterministicConfirmTx(CMutableTransaction& mutTransaction, const int nUpdateType)
{
    CKey keyCollateralAddress;
    CKey keyZelnode;

    mutTransaction.nType = ZELNODE_CONFIRM_TX_TYPE;
    mutTransaction.collateralIn = deterministicOutPoint;
    mutTransaction.nUpdateType = nUpdateType;
}

bool ActiveZelnode::CheckDefaultPort(std::string strService, std::string& strErrorRet, std::string strContext)
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