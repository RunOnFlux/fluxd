// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "activefluxnode.h"
#include "addrman.h"
#include "fluxnode/fluxnode.h"
#include "fluxnode/fluxnodeconfig.h"
#include "protocol.h"

#include "key_io.h"
#include "fluxnode/benchmarks.h"


void ActiveFluxnode::ManageDeterministricFluxnode()
{
    // We only want to run this command on the VPS that has fluxnode=1 and is running fluxbenchd
    if (!fFluxnode)
        return;

    std::string errorMessage;

    // Start confirm transaction
    CMutableTransaction mutTx;

    // Get the current height
    int nHeight = chainActive.Height();

    // Check if fluxnode is currently in the start list, if so we will be building the Initial Confirm Transaction
    // If the fluxnode is already confirmed check to see if it needs to be re confirmed, if so, Create the Update Transaction
    if (g_fluxnodeCache.InStartTracker(activeFluxnode.deterministicOutPoint)) {
        // Check if we currently have a tx with the same vin in our mempool
        // If we do, Resend the wallet transactions to our peers
        if (mempool.mapFluxnodeTxMempool.count(activeFluxnode.deterministicOutPoint)) {
            if (pwalletMain)
                pwalletMain->ResendWalletTransactions(GetAdjustedTime());
            LogPrintf("Fluxnode found in start tracker. Skipping confirm transaction creation, because transaction already in mempool %s\n", activeFluxnode.deterministicOutPoint.ToString());
            return;
        }

        // If we don't have one in our mempool. That means it is time to confirm the fluxnode
        if (nHeight - nLastTriedToConfirm > 3) { // Only try this every couple blocks
            activeFluxnode.BuildDeterministicConfirmTx(mutTx, FluxnodeUpdateType::INITIAL_CONFIRM);
            LogPrintf("Fluxnode found in start tracker. Creating Initial Confirm Transactions %s\n", activeFluxnode.deterministicOutPoint.ToString());
        } else {
            return;
        }
    } else if (g_fluxnodeCache.CheckIfNeedsNextConfirm(activeFluxnode.deterministicOutPoint, nHeight)) {
        activeFluxnode.BuildDeterministicConfirmTx(mutTx, FluxnodeUpdateType::UPDATE_CONFIRM);
        LogPrintf("Time to Confirm Fluxnode reached, Creating Update Confirm Transaction on height: %s for outpoint: %s\n", nHeight, activeFluxnode.deterministicOutPoint.ToString());
    } else {
        LogPrintf("Fluxnode found nothing to do on height: %s for outpoint: %s\n", nHeight, activeFluxnode.deterministicOutPoint.ToString());
        return;
    }

    if (activeFluxnode.SignDeterministicConfirmTx(mutTx, errorMessage)) {
        CReserveKey reservekey(pwalletMain);
        CTransaction tx(mutTx);
        CTransaction signedTx;
        if (GetBenchmarkSignedTransaction(tx, signedTx, errorMessage)) {
            CWalletTx walletTx(pwalletMain, signedTx);
            pwalletMain->CommitTransaction(walletTx, reservekey);
            nLastTriedToConfirm = nHeight;
        } else {
            error("Failed to sign benchmarking for fluxnode confirm transaction for outpoint %s, Error message: %s", activeFluxnode.deterministicOutPoint.ToString(), errorMessage);
            return;
        }
    } else {
        error("Failed to sign fluxnode for confirm transaction for outpoint %s, Error message: %s", activeFluxnode.deterministicOutPoint.ToString(), errorMessage);
        return;
    }
}

bool ActiveFluxnode::GetFluxNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey)
{
    std::string strErrorMessage;
    return GetFluxNodeVin(vin, pubkey, secretKey, "", "", strErrorMessage);
}

bool ActiveFluxnode::GetFluxNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex)  {
        errorMessage = "Couldn't find Flux Node Vin: Wallet is importing or reindexing";
        return false;
    }

    // Find possible candidates
    vector<std::pair<COutput, CAmount>> possibleCoins = SelectCoinsFluxnode();
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
            errorMessage = "No possible coins found for fluxnodes";
            LogPrintf("%s - Could not locate specified vin from possible list\n", __func__);
            return false;
        }
    }

    if (selectedOutput->nDepth < FLUXNODE_MIN_CONFIRMATION_DETERMINISTIC) {
        errorMessage = strprintf("Fluxnode hasn't met confirmation requirement (remaining confirmations required: %d)\n", FLUXNODE_MIN_CONFIRMATION_DETERMINISTIC - selectedOutput->nDepth);
        LogPrintf("%s - fluxnode hasn't met confirmation requirement (remaining confirmations required: %d)\n", __func__, FLUXNODE_MIN_CONFIRMATION_DETERMINISTIC - selectedOutput->nDepth);
        return false;
    }

    // At this point we have a selected output, retrieve the associated info
    return GetVinFromOutput(*selectedOutput, vin, pubkey, secretKey);
}

// Extract Fluxnode vin information from output
bool ActiveFluxnode::GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) {
        LogPrintf("%s: Couldn't get Vin from Output: Wallet is importing or reindexing\n", __func__);
        return false;
    }

    CScript pubScript;
    vin = CTxIn(out.tx->GetHash(), out.i);
    pubScript = out.tx->vout[out.i].scriptPubKey; // the inputs PubKey

    CTxDestination address1;
    ExtractDestination(pubScript, address1);

    if (pubScript.IsPayToScriptHash()) {
        if (!GetKeysForP2SHFluxNode(pubkey, secretKey)) {
            LogPrintf("%s-- Failed to get P2SH keys\n", __func__);
            return false;
        }
        return true;
    }

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

// get all possible outputs for running Fluxnode
vector<std::pair<COutput, CAmount>> ActiveFluxnode::SelectCoinsFluxnode()
{
    static vector<std::pair<COutput, CAmount>> vFilteredStatic;
    static int64_t nLastUpdated;
    int nCurrentTime = GetTime();

    // With large wallets, we don't need to process the fluxnode list that often.
    // Processing the list is doing a lot of calls to the wallet, which can lock it up.
    // For example, starting 100 fluxnodes in the same call with `startfluxnode all false` can cause issues
    if (nLastUpdated > 0 && nLastUpdated + 300 > nCurrentTime) {
        LogPrintf("%s : Using Cache\n", __func__);
        return vFilteredStatic;
    }

    vector<COutput> vCoins;
    vector<std::pair<COutput, CAmount>> filteredCoins;
    vector<COutPoint> confLockedCoins;

    // Temporary unlock ZN coins from fluxnode.conf
    if (GetBoolArg("-znconflock", true)) {
        uint256 znTxHash;
        for (const auto& fluxnodeEntry : fluxnodeConfig.getEntries()) {
            znTxHash.SetHex(fluxnodeEntry.getTxHash());

            int nIndex;
            if(!fluxnodeEntry.castOutputIndex(nIndex))
                continue;
            COutPoint outpoint = COutPoint(znTxHash, nIndex);
            confLockedCoins.push_back(outpoint);
            pwalletMain->UnlockCoin(outpoint);
        }
    }

    // Retrieve all possible outputs
    pwalletMain->AvailableCoins(vCoins, true, NULL, false, false, ALL_FLUXNODE);

    // Lock ZN coins from fluxnode.conf back if they where temporary unlocked
    if (!confLockedCoins.empty()) {
        for (COutPoint& outpoint: confLockedCoins)
            pwalletMain->LockCoin(outpoint);
    }

    int nCurrentHeight = 0;
    {
        LOCK(cs_main);
        nCurrentHeight = chainActive.Height();
    }

    // Build list of valid amounts
    set<CAmount> validFluxnodeCollaterals;
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
        set<CAmount> setTierAmounts = GetCoinAmountsByTier(nCurrentHeight, currentTier);
        validFluxnodeCollaterals.insert(setTierAmounts.begin(), setTierAmounts.end());
    }

    // Filter
    for (const COutput& out : vCoins) {
        if (validFluxnodeCollaterals.count(out.tx->vout[out.i].nValue)) {
            filteredCoins.push_back(std::make_pair(out, out.tx->vout[out.i].nValue));
        }
    }

    LogPrintf("%s : Updating Cache\n", __func__);
    vFilteredStatic = filteredCoins;
    nLastUpdated = GetTime();
    return filteredCoins;
}

bool ActiveFluxnode::SignDeterministicStartTx(CMutableTransaction& mutableTransaction, std::string& errorMessage)
{
    if (mutableTransaction.nType != FLUXNODE_START_TX_TYPE) {
        errorMessage = "invalid-tx-type";
        return error("%s : %s", __func__, errorMessage);
    }

    CTxIn txin;
    CPubKey pubKeyAddressNew;
    CKey keyAddressNew;
    if (!pwalletMain->GetFluxnodeVinAndKeys(txin, pubKeyAddressNew, keyAddressNew, mutableTransaction.collateralIn.hash.GetHex(), std::to_string(mutableTransaction.collateralIn.n))) {
        errorMessage = strprintf("Could not allocate txin %s:%s for fluxnode %s", mutableTransaction.collateralIn.hash.GetHex(), std::to_string(mutableTransaction.collateralIn.n), mutableTransaction.ip);
        LogPrintf("fluxnode","%s -- %s\n", __func__, errorMessage);
        return false;
    }

    // Set the public key for the fluxnode collateral
    mutableTransaction.collateralPubkey = pubKeyAddressNew;

    if (mutableTransaction.nType == FLUXNODE_START_TX_TYPE) {
        std::string errorMessage;
        mutableTransaction.sigTime = GetAdjustedTime();

        std::string strMessage = mutableTransaction.GetHash().GetHex();

        if (!obfuScationSigner.SignMessage(strMessage, errorMessage, mutableTransaction.sig, keyAddressNew))
            return error("%s - Error: Sign Fluxnode for start transaction %s", __func__, errorMessage);

        if (!obfuScationSigner.VerifyMessage(mutableTransaction.collateralPubkey, mutableTransaction.sig, strMessage, errorMessage))
            return error("%s - Error: Verify Fluxnode for start transaction: %s", __func__, errorMessage);

        return true;
    }

    return false;
}

bool ActiveFluxnode::SignDeterministicConfirmTx(CMutableTransaction& mutableTransaction, std::string& errorMessage)
{
    std::string strErrorRet;

    if (mutableTransaction.nType != FLUXNODE_CONFIRM_TX_TYPE) {
        errorMessage = "invalid-tx-type";
        return error("%s : %s", __func__, errorMessage);
    }

    auto data = g_fluxnodeCache.GetFluxnodeData(mutableTransaction.collateralIn);

    if (data.IsNull()) {
        errorMessage = "fluxnode-data-is-null";
        return error("%s : %s", __func__, errorMessage);
    }

    // We need to sign the mutable transaction
    mutableTransaction.sigTime = GetAdjustedTime();

    std::string strMessage = mutableTransaction.collateralIn.ToString() + std::to_string(mutableTransaction.collateralIn.n) + std::to_string(mutableTransaction.nUpdateType) + std::to_string(mutableTransaction.sigTime);

    // send to all nodes
    CPubKey pubKeyFluxnode;
    CKey keyFluxnode;

    if (!obfuScationSigner.SetKey(strFluxnodePrivKey, errorMessage, keyFluxnode, pubKeyFluxnode)) {
        notCapableReason = "Error upon calling SetKey: " + errorMessage;
        errorMessage = "unable-set-key";
        return error("%s : %s", __func__, errorMessage);
    }

    if (data.pubKey != pubKeyFluxnode) {
        return error("%s - PubKey miss match", __func__);
    }

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage, mutableTransaction.sig, keyFluxnode))
        return error("%s - Error: Signing Fluxnode %s", __func__, errorMessage);

    if (!obfuScationSigner.VerifyMessage(pubKeyFluxnode, mutableTransaction.sig, strMessage, errorMessage))
        return error("%s - Error: Verify Fluxnode sig %s", __func__, errorMessage);

    return true;
}

bool ActiveFluxnode::BuildDeterministicStartTx(std::string strKeyFluxnode, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, CMutableTransaction& mutTransaction)
{
    // wait for reindex and/or import to finish
    if (IsInitialBlockDownload(Params())) {
        errorMessage = "block chain is downloading";
        return false;
    }

    CTxIn vin;
    CPubKey pubKeyCollateralAddress;
    CKey keyCollateralAddress;
    CPubKey pubKeyFluxnode;
    CKey keyFluxnode;

    if (!obfuScationSigner.SetKey(strKeyFluxnode, errorMessage, keyFluxnode, pubKeyFluxnode)) {
        errorMessage = strprintf("Can't find keys for fluxnode - %s", errorMessage);
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    if (!GetFluxNodeVin(vin, pubKeyCollateralAddress, keyCollateralAddress, strTxHash, strOutputIndex, errorMessage)) {
        if (errorMessage.empty())
            errorMessage = strprintf("Could not allocate vin %s:%s for fluxnode", strTxHash, strOutputIndex);
        LogPrintf("%s - %s\n", __func__, errorMessage);
        return false;
    }

    // This function is only used by startfluxnode rpc, and will default to always user version 5
    mutTransaction.nVersion = FLUXNODE_TX_VERSION;
    mutTransaction.nType = FLUXNODE_START_TX_TYPE;

    // Create fluxnode transaction
    if (mutTransaction.nType == FLUXNODE_START_TX_TYPE) {
        mutTransaction.collateralIn = vin.prevout;
        mutTransaction.collateralPubkey = pubKeyCollateralAddress;
        mutTransaction.pubKey = pubKeyFluxnode;

    } else if (mutTransaction.nType == FLUXNODE_CONFIRM_TX_TYPE) {
        mutTransaction.collateralIn = vin.prevout;
        if (mutTransaction.nUpdateType != FluxnodeUpdateType::UPDATE_CONFIRM)
            mutTransaction.nUpdateType = FluxnodeUpdateType::INITIAL_CONFIRM;
    }

    return true;
}

void ActiveFluxnode::BuildDeterministicConfirmTx(CMutableTransaction& mutTransaction, const int nUpdateType)
{
    // When we should move to upgraded version for fluxnode transactions
    bool fP2SHNodesActive = NetworkUpgradeActive(chainActive.Height(), Params().GetConsensus(), Consensus::UPGRADE_P2SHNODES);

    // If this is the first confirmation tx we check for INITIAL_CONFIRM, and we must check the started list
    if (nUpdateType == FluxnodeUpdateType::INITIAL_CONFIRM && g_fluxnodeCache.mapStartTxTracker.count(activeFluxnode.deterministicOutPoint)) {
        // Set the active Fluxnode to the correct tx version, so it can create the confirmation transaction with the same version (5 or 6)
        nActiveFluxNodeTxVersion = g_fluxnodeCache.mapStartTxTracker.at(activeFluxnode.deterministicOutPoint).nType;
    }

    // If this is the second confirmation tx we check for UPDATE_CONFIRM, and we must check the confirmed list
    if (nUpdateType == FluxnodeUpdateType::UPDATE_CONFIRM && g_fluxnodeCache.mapConfirmedFluxnodeData.count(activeFluxnode.deterministicOutPoint)) {
        // Set the active Fluxnode to the correct tx version, so it can create the confirmation transaction with the same version (5 or 6)
        nActiveFluxNodeTxVersion = g_fluxnodeCache.mapConfirmedFluxnodeData.at(activeFluxnode.deterministicOutPoint).nType;
    }

    // Enforce a valid fluxnode tx version
    EnforceActiveFluxNodeTxVersion();

    CKey keyCollateralAddress;
    CKey keyFluxnode;
    mutTransaction.nVersion = nActiveFluxNodeTxVersion;

    mutTransaction.nType = FLUXNODE_CONFIRM_TX_TYPE;
    mutTransaction.collateralIn = deterministicOutPoint;
    mutTransaction.nUpdateType = nUpdateType;
}

void ActiveFluxnode::EnforceActiveFluxNodeTxVersion()
{
    // Check for version 5
    if (nActiveFluxNodeTxVersion == FLUXNODE_TX_VERSION) {
        return;
    }

    // Check for version 6
    if (nActiveFluxNodeTxVersion == FLUXNODE_TX_UPGRADEABLE_VERSION) {
        return;
    }

    // Print if it doesn't match
    LogPrintf("%s: nActiveFluxNodeTxVersion not being set to either valid value: Current set to: %d. Setting to 5 by default.\n",
              __func__, nActiveFluxNodeTxVersion);

    // Enforce default version 5 as a last resort
    nActiveFluxNodeTxVersion = FLUXNODE_TX_VERSION;
}