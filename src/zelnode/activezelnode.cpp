// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "activezelnode.h"
#include "addrman.h"
#include "zelnode/zelnode.h"
#include "zelnode/zelnodeconfig.h"
#include "protocol.h"

#include "key_io.h"
#include "zelnode/benchmarks.h"


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
            LogPrintf("Zelnode found in start tracker. Skipping confirm transaction creation, because transaction already in mempool %s\n", activeZelnode.deterministicOutPoint.ToString());
            return;
        }

        // If we don't have one in our mempool. That means it is time to confirm the zelnode
        if (nHeight - nLastTriedToConfirm > 3) { // Only try this every couple blocks
            activeZelnode.BuildDeterministicConfirmTx(mutTx, ZelnodeUpdateType::INITIAL_CONFIRM);
            LogPrintf("Zelnode found in start tracker. Creating Initial Confirm Transactions %s\n", activeZelnode.deterministicOutPoint.ToString());
        } else {
            return;
        }
    } else if (g_zelnodeCache.CheckIfNeedsNextConfirm(activeZelnode.deterministicOutPoint)) {
        activeZelnode.BuildDeterministicConfirmTx(mutTx, ZelnodeUpdateType::UPDATE_CONFIRM);
        LogPrintf("Time to Confirm Zelnode reached, Creating Update Confirm Transaction on height: %s for outpoint: %s\n", nHeight, activeZelnode.deterministicOutPoint.ToString());
    } else {
        LogPrintf("Zelnode found nothing to do on height: %s for outpoint: %s\n", nHeight, activeZelnode.deterministicOutPoint.ToString());
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

    int nCurrentHeight = 0;
    {
        LOCK(cs_main);
        nCurrentHeight = chainActive.Height();
    }

    // Build list of valid amounts
    set<CAmount> validZelnodeCollaterals;
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
        set<CAmount> setTierAmounts = GetCoinAmountsByTier(nCurrentHeight, currentTier);
        validZelnodeCollaterals.insert(setTierAmounts.begin(), setTierAmounts.end());
    }

    // Filter
    for (const COutput& out : vCoins) {
        if (validZelnodeCollaterals.count(out.tx->vout[out.i].nValue)) {
            filteredCoins.push_back(std::make_pair(out, out.tx->vout[out.i].nValue));
        }
    }
    return filteredCoins;
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