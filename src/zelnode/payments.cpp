// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zelnode/payments.h"
#include "addrman.h"
#include "zelnode/zelnodesync.h"
#include "zelnode/zelnodeman.h"
#include "zelnode/obfuscation.h"
#include "zelnode/spork.h"
#include "sync.h"
#include "util.h"
#include "utilmoneystr.h"
#include "key_io.h"
#include <boost/filesystem.hpp>


/** Object for who's going to get paid on which blocks */
Payments zelnodePayments;

CCriticalSection cs_vecPayments;
CCriticalSection cs_mapZelnodeBlocks;
CCriticalSection cs_mapZelnodePayeeVotes;


//
// CZelnodePaymentDB
//

PaymentDB::PaymentDB()
{
    pathDB = GetDataDir() / "zelnodepayments.dat";
    strMagicMessage = "ZelnodePayments";
}

bool PaymentDB::Write(const Payments& objToSave)
{
    int64_t nStart = GetTimeMillis();

    // serialize, checksum data up to that point, then append checksum
    CDataStream ssObj(SER_DISK, CLIENT_VERSION);
    ssObj << strMagicMessage;
    ssObj << FLATDATA(Params().MessageStart()); // network specific magic number
    ssObj << objToSave;
    uint256 hash = Hash(ssObj.begin(), ssObj.end());
    ssObj << hash;

    // open output file, and associate with CAutoFile
    FILE* file = fopen(pathDB.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s : Failed to open file %s", __func__, pathDB.string());

    // Write and commit header, data
    try {
        fileout << ssObj;
    } catch (std::exception& e) {
        return error("%s : Serialize or I/O error - %s", __func__, e.what());
    }
    fileout.fclose();

    LogPrint("zelnode","Written info to zelnodepayments.dat  %dms\n", GetTimeMillis() - nStart);

    return true;
}

PaymentDB::ReadResult PaymentDB::Read(Payments& objToLoad, bool fDryRun)
{
    int64_t nStart = GetTimeMillis();
    // open input file, and associate with CAutoFile
    FILE* file = fopen(pathDB.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        error("%s : Failed to open file %s", __func__, pathDB.string());
        return FileError;
    }

    // use file size to size memory buffer
    int fileSize = boost::filesystem::file_size(pathDB);
    int dataSize = fileSize - sizeof(uint256);
    // Don't try to resize to a negative number if file is small
    if (dataSize < 0)
        dataSize = 0;
    vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        filein.read((char*)&vchData[0], dataSize);
        filein >> hashIn;
    } catch (std::exception& e) {
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return HashReadError;
    }
    filein.fclose();

    CDataStream ssObj(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    uint256 hashTmp = Hash(ssObj.begin(), ssObj.end());
    if (hashIn != hashTmp) {
        error("%s : Checksum mismatch, data corrupted", __func__);
        return IncorrectHash;
    }

    unsigned char pchMsgTmp[4];
    std::string strMagicMessageTmp;
    try {
        // de-serialize file header (zelnode cache file specific magic message) and ..
        ssObj >> strMagicMessageTmp;

        // ... verify the message matches predefined one
        if (strMagicMessage != strMagicMessageTmp) {
            error("%s : Invalid zelnode payment cache magic message", __func__);
            return IncorrectMagicMessage;
        }


        // de-serialize file header (network specific magic number) and ..
        ssObj >> FLATDATA(pchMsgTmp);

        // ... verify the network matches ours
        if (memcmp(pchMsgTmp, Params().MessageStart(), sizeof(pchMsgTmp))) {
            error("%s : Invalid network magic number", __func__);
            return IncorrectMagicNumber;
        }

        // de-serialize data into CZelnodePayments object
        ssObj >> objToLoad;
    } catch (std::exception& e) {
        objToLoad.Clear();
        error("%s : Deserialize or I/O error - %s", __func__, e.what());
        return IncorrectFormat;
    }

    LogPrint("zelnode","Loaded info from zelnodepayments.dat  %dms\n", GetTimeMillis() - nStart);
    LogPrint("zelnode","  %s\n", objToLoad.ToString());
    if (!fDryRun) {
        LogPrint("zelnode","Zelnode payments manager - cleaning....\n");
        objToLoad.CleanPaymentList();
        LogPrint("zelnode","Zelnode payments manager - result:\n");
        LogPrint("zelnode","  %s\n", objToLoad.ToString());
    }

    return Ok;
}

void DumpZelnodePayments()
{
    int64_t nStart = GetTimeMillis();

    PaymentDB paymentdb;
    Payments tempPayments;

    LogPrint("zelnode","Verifying zelnodpayments.dat format...\n");
    PaymentDB::ReadResult readResult = paymentdb.Read(tempPayments, true);
    // there was an error and it was not an error on file opening => do not proceed
    if (readResult == PaymentDB::FileError)
        LogPrint("zelnode","Missing budgets file - zelnodepayments.dat, will try to recreate\n");
    else if (readResult != PaymentDB::Ok) {
        LogPrint("zelnode","Error reading zelnodepayments.dat: ");
        if (readResult == PaymentDB::IncorrectFormat)
            LogPrint("zelnode","magic is ok but data has invalid format, will try to recreate\n");
        else {
            LogPrint("zelnode","file format is unknown or invalid, please fix it manually\n");
            return;
        }
    }
    LogPrint("zelnode","Writting info to zelnodepayments.dat...\n");
    paymentdb.Write(zelnodePayments);

    LogPrint("zelnode","Payment dump finished  %dms\n", GetTimeMillis() - nStart);
}

bool IsBlockValueValid(const CBlock& block, CAmount nExpectedValue, CAmount nMinted)
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (pindexPrev == NULL) return true;

    int nHeight = 0;
    if (pindexPrev->GetBlockHash() == block.hashPrevBlock) {
        nHeight = pindexPrev->nHeight + 1;
    } else { //out of order
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi != mapBlockIndex.end() && (*mi).second)
            nHeight = (*mi).second->nHeight + 1;
    }

    if (nHeight == 0) {
        LogPrint("zelnode","%s : WARNING: Couldn't find previous block\n", __func__);
    }


    if (!zelnodeSync.IsSynced()) {
        if (nMinted > nExpectedValue) {
            return false;
        }

    } else {

        if (nMinted > nExpectedValue) {
            return false;
        }
    }

    return true;
}

bool IsBlockPayeeValid(const CBlock& block, int nBlockHeight)
{
    if (!zelnodeSync.IsSynced()) { //there is no budget data to use to check anything -- find the longest chain
        LogPrint("zelnode", "Client not synced, skipping block payee checks\n");
        return true;
    }

    const CTransaction& txNew = block.vtx[0]; // Get the coinbase transaction from the block

    //check for zelnode payee
    if (zelnodePayments.IsTransactionValid(txNew, nBlockHeight))
        return true;

    LogPrint("zelnode","Invalid zn payment detected %s\n", txNew.ToString().c_str());

    if (IsSporkActive(SPORK_1_ZELNODE_PAYMENT_ENFORCEMENT))
        return false;

    LogPrint("zelnode","Zelnode payment enforcement is disabled, accepting block\n");

    return true;
}


void FillBlockPayee(CMutableTransaction& txNew, CAmount nFees, std::map<int, std::pair<CScript, CAmount>>* payments)
{
    zelnodePayments.FillBlockPayee(txNew, nFees, payments);
}

std::string GetRequiredPaymentsString(int nBlockHeight)
{
    return zelnodePayments.GetRequiredPaymentsString(nBlockHeight);
}

void Payments::FillBlockPayee(CMutableTransaction& txNew, int64_t nFees, std::map<int, std::pair<CScript, CAmount>>* payments)
{
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (!pindexPrev) return;

    bool hasBasicPayment = true;
    bool hasSuperPayment = true;
    bool hasBAMFPayment = true;

    CScript basicPayee;
    CScript superPayee;
    CScript BAMFPayee;

    int nTotalPayouts = 3; // Total number of zelnode payments there could be

    //spork
    if (!zelnodePayments.GetBlockBasicPayee(pindexPrev->nHeight + 1, basicPayee)) {
        //no zelnode detected
        Zelnode winningBasicNode;
        if (zelnodeman.GetCurrentZelnode(winningBasicNode, Zelnode::BASIC, 1)) {
            basicPayee = GetScriptForDestination(winningBasicNode.pubKeyCollateralAddress.GetID());
        } else {
            LogPrint("zelnode","CreateNewBlock: Failed to detect Basic zelnode to pay\n");
            hasBasicPayment = false;
            nTotalPayouts--;
        }
    }

    if (!zelnodePayments.GetBlockSuperPayee(pindexPrev->nHeight + 1, superPayee)) {
        //no zelnode detected
        Zelnode winningSuperNode;
        if (zelnodeman.GetCurrentZelnode(winningSuperNode, Zelnode::SUPER, 1)) {
            superPayee = GetScriptForDestination(winningSuperNode.pubKeyCollateralAddress.GetID());
        } else {
            LogPrint("zelnode","CreateNewBlock: Failed to detect Super zelnode to pay\n");
            hasSuperPayment = false;
            nTotalPayouts--;
        }
    }

    if (!zelnodePayments.GetBlockBAMFPayee(pindexPrev->nHeight + 1, BAMFPayee)) {
        //no zelnode detected
        Zelnode winningBAMFNode;
        if (zelnodeman.GetCurrentZelnode(winningBAMFNode, Zelnode::BAMF, 1)) {
            BAMFPayee = GetScriptForDestination(winningBAMFNode.pubKeyCollateralAddress.GetID());
        } else {
            LogPrint("zelnode","CreateNewBlock: Failed to detect BAMF zelnode to pay\n");
            hasBAMFPayment = false;
            nTotalPayouts--;
        }
    }

    CAmount blockValue = GetBlockSubsidy(pindexPrev->nHeight + 1, Params().GetConsensus());
    CAmount basicZelnodePayment = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, Zelnode::BASIC);
    CAmount superZelnodePayment = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, Zelnode::SUPER);
    CAmount BAMFZelnodePayment = GetZelnodeSubsidy(pindexPrev->nHeight + 1, blockValue, Zelnode::BAMF);

    if (nTotalPayouts > 0) {
        txNew.vout.resize(nTotalPayouts + 1);
    }

    CAmount nMinerReward = blockValue;
    int currentIndex = 1;
    if (hasBasicPayment) {
        txNew.vout[currentIndex].scriptPubKey = basicPayee;
        txNew.vout[currentIndex].nValue = basicZelnodePayment;
        nMinerReward -= basicZelnodePayment;
        currentIndex++;

        if (payments)
            payments->insert(std::make_pair(Zelnode::BASIC, std::make_pair(basicPayee, basicZelnodePayment)));
    }

    if (hasSuperPayment) {
        txNew.vout[currentIndex].scriptPubKey = superPayee;
        txNew.vout[currentIndex].nValue = superZelnodePayment;
        nMinerReward -= superZelnodePayment;
        currentIndex++;

        if (payments)
            payments->insert(std::make_pair(Zelnode::SUPER, std::make_pair(superPayee, superZelnodePayment)));
    }

    if (hasBAMFPayment) {
        txNew.vout[currentIndex].scriptPubKey = BAMFPayee;
        txNew.vout[currentIndex].nValue = BAMFZelnodePayment;
        nMinerReward -= BAMFZelnodePayment;

        if (payments)
            payments->insert(std::make_pair(Zelnode::BAMF, std::make_pair(BAMFPayee, BAMFZelnodePayment)));
    }

    txNew.vout[0].nValue = nMinerReward;

    CTxDestination basicaddress1;
    ExtractDestination(basicPayee, basicaddress1);

    CTxDestination superaddress1;
    ExtractDestination(superPayee, superaddress1);

    CTxDestination BAMFaddress1;
    ExtractDestination(BAMFPayee, BAMFaddress1);

    LogPrint("zelnode","Zelnode Basic payment of %s to %s\n", FormatMoney(basicZelnodePayment).c_str(), EncodeDestination(basicaddress1).c_str());
    LogPrint("zelnode","Zelnode Super payment of %s to %s\n", FormatMoney(superZelnodePayment).c_str(), EncodeDestination(superaddress1).c_str());
    LogPrint("zelnode","Zelnode BAMF payment of %s to %s\n", FormatMoney(BAMFZelnodePayment).c_str(), EncodeDestination(BAMFaddress1).c_str());
}


int Payments::GetMinZelnodePaymentsProto()
{
    return MIN_PEER_PROTO_VERSION_ZELNODE;
}

void Payments::ProcessMessageZelnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv)
{
    if (!zelnodeSync.IsBlockchainSynced()) return;

    if (strCommand == "znget") { //Zelnode Payments Request Sync

        int nCountNeeded;
        vRecv >> nCountNeeded;

        if (Params().NetworkID() == CBaseChainParams::MAIN) {
            if (pfrom->HasFulfilledRequest("znget")) {
                LogPrintf("%s : znget - peer already asked me for the list\n", __func__);
                Misbehaving(pfrom->GetId(), 20);
                return;
            }
        }

        pfrom->FulfilledRequest("znget");
        zelnodePayments.Sync(pfrom, nCountNeeded);
        LogPrint("zelnodepayments", "znget - Sent Zelnode winners to peer %i\n", pfrom->GetId());
    } else if (strCommand == "znw") { //Zelnode Payments Declare Winner

        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION_ZELNODE) return;

        PaymentWinner winner;
        vRecv >> winner;

        int nHeight;
        {
            TRY_LOCK(cs_main, locked);
            if (!locked || chainActive.Tip() == NULL) return;
            nHeight = chainActive.Tip()->nHeight;
        }

        int nFirstBlock = nHeight - (zelnodeman.CountEnabled() * 1.25);
        if (winner.nBlockHeight < nFirstBlock || winner.nBlockHeight > nHeight + 20) {
            LogPrint("zelnodepayments", "znw - winner out of range - FirstBlock %d Height %d bestHeight %d\n", nFirstBlock, winner.nBlockHeight, nHeight);
            return;
        }

        // Check to make sure the voter is a valid voter
        std::string strError = "";
        if (!winner.IsValid(pfrom, strError)) {
            if(strError != "") LogPrint("zelnodepayments","znw - invalid message - %s\n", strError);
            return;
        }

        if (zelnodePayments.mapZelnodePayeeVotes.count(winner.GetHash())) {
            LogPrint("zelnodepayments", "znw - Already seen - %s bestHeight %d\n", winner.GetHash().ToString().c_str(), nHeight);
            LogPrint("zelnodepayments", "znw - Winner: %s\n", winner.ToString());
            zelnodeSync.AddedZelnodeWinner(winner.GetHash());
            return;
        }

        // Check to make sure the voter hasn't voted before
        if (!zelnodePayments.CanVote(winner)) {
            LogPrint("zelnodepayments","znw - zelnode already voted - %s\n", winner.vinZelnode.prevout.ToString());
            return;
        }

        if (!winner.SignatureValid()) {
            if (zelnodeSync.IsSynced()) {
                LogPrintf("%s : znw - invalid signature\n", __func__);
                Misbehaving(pfrom->GetId(), 20);
            }
            // it could just be a non-synced zelnode
            zelnodeman.AskForZN(pfrom, winner.vinZelnode);
            return;
        }

        CTxDestination address1;
        ExtractDestination(winner.payee, address1);

        LogPrint("zelnodepayments", "znw - winning vote - Addr %s Height %d bestHeight %d - %s\n", EncodeDestination(address1).c_str(), winner.nBlockHeight, nHeight, winner.vinZelnode.prevout.ToString());

        if (zelnodePayments.AddWinningZelnode(winner, winner.tier)) {
            winner.Relay();
            zelnodeSync.AddedZelnodeWinner(winner.GetHash());
        }
    }
}

bool PaymentWinner::Sign(CKey& keyZelnode, CPubKey& pubKeyZelnode)
{
    std::string errorMessage;

    std::string strMessage = vinZelnode.prevout.ToString() + std::to_string(nBlockHeight) + payee.ToString();

    if (!obfuScationSigner.SignMessage(strMessage, errorMessage, vchSig, keyZelnode)) {
        LogPrint("zelnode","%s - Error: %s\n", __func__, errorMessage.c_str());
        return false;
    }

    if (!obfuScationSigner.VerifyMessage(pubKeyZelnode, vchSig, strMessage, errorMessage)) {
        LogPrint("zelnode","%s - Error: %s\n", __func__, errorMessage.c_str());
        return false;
    }

    return true;
}

bool Payments::GetBlockBasicPayee(int nBlockHeight, CScript& payee)
{
    if (mapZelnodeBlocks.count(nBlockHeight)) {
        return mapZelnodeBlocks[nBlockHeight].GetBasicPayee(payee);
    }

    return false;
}

bool Payments::GetBlockSuperPayee(int nBlockHeight, CScript& payee)
{
    if (mapZelnodeBlocks.count(nBlockHeight)) {
        return mapZelnodeBlocks[nBlockHeight].GetSuperPayee(payee);
    }

    return false;
}

bool Payments::GetBlockBAMFPayee(int nBlockHeight, CScript& payee)
{
    if (mapZelnodeBlocks.count(nBlockHeight)) {
        return mapZelnodeBlocks[nBlockHeight].GetBAMFPayee(payee);
    }

    return false;
}

// Is this zelnode scheduled to get paid soon?
// -- Only look ahead up to 8 blocks to allow for propagation of the latest 2 winners
bool Payments::IsScheduled(Zelnode& zelnode, int nNotBlockHeight)
{
    LOCK(cs_mapZelnodeBlocks);

    int nHeight;
    {
        TRY_LOCK(cs_main, locked);
        if (!locked || chainActive.Tip() == NULL) return false;
        nHeight = chainActive.Tip()->nHeight;
    }

    CScript mnpayee;
    mnpayee = GetScriptForDestination(zelnode.pubKeyCollateralAddress.GetID());

    CScript payee;
    for (int64_t h = nHeight; h <= nHeight + 8; h++) {
        if (h == nNotBlockHeight) continue;
        if (mapZelnodeBlocks.count(h)) {
            if (zelnode.IsBasic()) {
                if (mapZelnodeBlocks[h].GetBasicPayee(payee)) {
                    if (mnpayee == payee) {
                        return true;
                    }
                }
            } else if (zelnode.IsSuper()) {
                if (mapZelnodeBlocks[h].GetSuperPayee(payee)) {
                    if (mnpayee == payee) {
                        return true;
                    }
                }
            } else if (zelnode.IsBAMF()) {
                if (mapZelnodeBlocks[h].GetBAMFPayee(payee)) {
                    if (mnpayee == payee) {
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

bool Payments::AddWinningZelnode(PaymentWinner& winnerIn, int nNodeTier)
{
    uint256 blockHash = uint256();
    if (!GetBlockHash(blockHash, winnerIn.nBlockHeight - 100)) {
        return false;
    }

    if (nNodeTier != Zelnode::BASIC && nNodeTier != Zelnode::SUPER && nNodeTier != Zelnode::BAMF)
        return false;

    {
        LOCK2(cs_mapZelnodePayeeVotes, cs_mapZelnodeBlocks);

        if (mapZelnodePayeeVotes.count(winnerIn.GetHash())) {
            return false;
        }

        mapZelnodePayeeVotes[winnerIn.GetHash()] = winnerIn;

        if (!mapZelnodeBlocks.count(winnerIn.nBlockHeight)) {
            ZelnodeBlockPayees blockPayees(winnerIn.nBlockHeight);
            mapZelnodeBlocks[winnerIn.nBlockHeight] = blockPayees;
        }
    }

    mapZelnodeBlocks[winnerIn.nBlockHeight].AddPayee(winnerIn.payee, 1, nNodeTier);

    return true;
}

bool ZelnodeBlockPayees::IsTransactionValid(const CTransaction& txNew)
{
    LOCK(cs_vecPayments);

    bool fKamiookaUpgradeActive = NetworkUpgradeActive(chainActive.Height(), Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA);

    int nMaxBasicSignatures = 0;
    int nMaxSuperSignatures = 0;
    int nMaxBAMFSignatures = 0;

    std::string strBasicPayeesPossible = "";
    std::string strSuperPayeesPossible = "";
    std::string strBAMFPayeesPossible = "";

    bool fBasicSigCountFound = false;
    bool fSuperSigCountFound = false;
    bool fBAMFSigCountFound = false;

    ZelnodePayee selectedBasicPayee;
    ZelnodePayee selectedSuperPayee;
    ZelnodePayee selectedBAMFPayee;

    CAmount nReward = GetBlockSubsidy(nBlockHeight, Params().GetConsensus());
    CAmount requiredBasicZelnodePayment = GetZelnodeSubsidy(nBlockHeight, nReward, Zelnode::BASIC);
    CAmount requiredSuperZelnodePayment = GetZelnodeSubsidy(nBlockHeight, nReward, Zelnode::SUPER);
    CAmount requiredBAMFZelnodePayment = GetZelnodeSubsidy(nBlockHeight, nReward, Zelnode::BAMF);

    // Get the required amount of signatures based on if the upgrade is active or not
    int nSignaturesRequired = fKamiookaUpgradeActive ? ZNPAYMENTS_SIGNATURES_REQUIRED_AFTER_UPGRADE : ZNPAYMENTS_SIGNATURES_REQUIRED;

    for (ZelnodePayee& payee : vecBasicPayments)
        if (payee.nVotes >= nMaxBasicSignatures) {
            nMaxBasicSignatures = payee.nVotes;
            selectedBasicPayee = payee;
        }

    for (ZelnodePayee& payee : vecSuperPayments)
        if (payee.nVotes >= nMaxSuperSignatures) {
            nMaxSuperSignatures = payee.nVotes;
            selectedSuperPayee = payee;
        }

    for (ZelnodePayee& payee : vecBAMFPayments)
        if (payee.nVotes >= nMaxBAMFSignatures) {
            nMaxBAMFSignatures = payee.nVotes;
            selectedBAMFPayee = payee;
        }

    if (fKamiookaUpgradeActive) {
        fBasicSigCountFound = nMaxBasicSignatures >= nSignaturesRequired;
        fSuperSigCountFound = nMaxSuperSignatures >= nSignaturesRequired;
        fBAMFSigCountFound = nMaxBAMFSignatures >= nSignaturesRequired;
    }

    if (fKamiookaUpgradeActive) {
        // If we don't have at least 6 signatures on each payee tier, follow the longest chain.
        if (!fBasicSigCountFound && !fSuperSigCountFound && !fBAMFSigCountFound)
            return true;
    }

    if (!fKamiookaUpgradeActive) {
        // if we don't have at least 16 signatures on a payee, approve whichever is the longest chain
        if (nMaxBasicSignatures < nSignaturesRequired || nMaxSuperSignatures < nSignaturesRequired || nMaxBAMFSignatures < nSignaturesRequired)
            return true;
    }

    bool fFoundBasic = false;
    if(!fKamiookaUpgradeActive || fBasicSigCountFound) {
        for (CTxOut out : txNew.vout) {
            if (selectedBasicPayee.scriptPubKey == out.scriptPubKey) {
                if (out.nValue == requiredBasicZelnodePayment)
                    fFoundBasic = true;
                else
                    LogPrint("zelnode", "Basic Zelnode payment is not the correct amount. Paid=%s Shouldbe=%s\n",
                             FormatMoney(out.nValue).c_str(), FormatMoney(requiredBasicZelnodePayment).c_str());
            }
        }

        if (selectedBasicPayee.nVotes >= nSignaturesRequired) {
            if (!fFoundBasic) {
                CTxDestination address1;
                ExtractDestination(selectedBasicPayee.scriptPubKey, address1);

                if (strBasicPayeesPossible == "") {
                    strBasicPayeesPossible += EncodeDestination(address1);
                } else {
                    strBasicPayeesPossible += "," + EncodeDestination(address1);
                }
            }
        }
    }

    bool fFoundSuper = false;
    if(!fKamiookaUpgradeActive || fSuperSigCountFound) {
        for (CTxOut out : txNew.vout) {
            if (selectedSuperPayee.scriptPubKey == out.scriptPubKey) {
                if (out.nValue == requiredSuperZelnodePayment)
                    fFoundSuper = true;
                else
                    LogPrint("zelnode", "Super Zelnode payment is not the correct amount. Paid=%s Shouldbe=%s\n",
                             FormatMoney(out.nValue).c_str(), FormatMoney(requiredSuperZelnodePayment).c_str());
            }
        }

        if (selectedSuperPayee.nVotes >= nSignaturesRequired) {
            if (!fFoundSuper) {

                CTxDestination address1;
                ExtractDestination(selectedSuperPayee.scriptPubKey, address1);

                if (strSuperPayeesPossible == "") {
                    strSuperPayeesPossible += EncodeDestination(address1);
                } else {
                    strSuperPayeesPossible += "," + EncodeDestination(address1);
                }
            }
        }
    }

    bool fFoundBAMF = false;
    if(!fKamiookaUpgradeActive || fBAMFSigCountFound) {
        for (CTxOut out : txNew.vout) {
            if (selectedBAMFPayee.scriptPubKey == out.scriptPubKey) {
                if (out.nValue == requiredBAMFZelnodePayment)
                    fFoundBAMF = true;
                else
                    LogPrint("zelnode", "BAMF Zelnode payment is not the correct amount. Paid=%s Shouldbe=%s\n",
                             FormatMoney(out.nValue).c_str(), FormatMoney(requiredBAMFZelnodePayment).c_str());
            }
        }

        if (selectedBAMFPayee.nVotes >= nSignaturesRequired) {
            if (fFoundBAMF && fFoundSuper && fFoundBAMF) {
                if (!fKamiookaUpgradeActive)
                    return true;
            }

            CTxDestination address1;
            ExtractDestination(selectedBAMFPayee.scriptPubKey, address1);

            if (strBAMFPayeesPossible == "") {
                strBAMFPayeesPossible += EncodeDestination(address1);
            } else {
                strBAMFPayeesPossible += "," + EncodeDestination(address1);
            }
        }
    }

    if (fKamiookaUpgradeActive) {
        bool fFail = false;
        if (fBasicSigCountFound && !fFoundBasic) {
            LogPrint("zelnode","%s- Missing required Basic payment of %s to %s\n", __func__, FormatMoney(requiredBasicZelnodePayment).c_str(), strBasicPayeesPossible.c_str());
            fFail = true;
        }
        if (fSuperSigCountFound && !fFoundSuper) {
            LogPrint("zelnode","%s- Missing required Super payment of %s to %s\n", __func__, FormatMoney(requiredSuperZelnodePayment).c_str(), strSuperPayeesPossible.c_str());
            fFail = true;
        }
        if (fBAMFSigCountFound && !fFoundBAMF) {
            LogPrint("zelnode","%s- Missing required BAMF payment of %s to %s\n", __func__, FormatMoney(requiredBAMFZelnodePayment).c_str(), strBAMFPayeesPossible.c_str());
            fFail = true;
        }
        return !fFail;
    }

    // TODO, once upgrade is complete remove
    if (!fFoundBasic) LogPrint("zelnode","%s- Missing required Basic payment of %s to %s\n", __func__, FormatMoney(requiredBasicZelnodePayment).c_str(), strBasicPayeesPossible.c_str());
    if (!fFoundSuper) LogPrint("zelnode","%s- Missing required Super payment of %s to %s\n", __func__, FormatMoney(requiredSuperZelnodePayment).c_str(), strSuperPayeesPossible.c_str());
    if (!fFoundBAMF) LogPrint("zelnode","%s- Missing required BAMF payment of %s to %s\n", __func__, FormatMoney(requiredBAMFZelnodePayment).c_str(), strBAMFPayeesPossible.c_str());

    return false;
}

std::string ZelnodeBlockPayees::GetRequiredPaymentsString()
{
    LOCK(cs_vecPayments);

    std::string ret = "Unknown";

    for (ZelnodePayee& payee : vecBasicPayments) {
        CTxDestination address1;
        ExtractDestination(payee.scriptPubKey, address1);

        if (ret != "Unknown") {
            ret += ",Basic|" + EncodeDestination(address1) + ":" + std::to_string(payee.nVotes);
        } else {
            ret = "Basic|" + EncodeDestination(address1) + ":" + std::to_string(payee.nVotes);
        }
    }

    for (ZelnodePayee& payee : vecSuperPayments) {
        CTxDestination address1;
        ExtractDestination(payee.scriptPubKey, address1);

        if (ret != "Unknown") {
            ret += ",Super|" + EncodeDestination(address1) + ":" + std::to_string(payee.nVotes);
        } else {
            ret = "Super|" + EncodeDestination(address1) + ":" + std::to_string(payee.nVotes);
        }
    }

    for (ZelnodePayee& payee : vecBAMFPayments) {
        CTxDestination address1;
        ExtractDestination(payee.scriptPubKey, address1);

        if (ret != "Unknown") {
            ret += ",BAMF|" + EncodeDestination(address1) + ":" + std::to_string(payee.nVotes);
        } else {
            ret = "BAMF|" + EncodeDestination(address1) + ":" + std::to_string(payee.nVotes);
        }
    }

    return ret;
}

std::string Payments::GetRequiredPaymentsString(int nBlockHeight)
{
    LOCK(cs_mapZelnodeBlocks);

    if (mapZelnodeBlocks.count(nBlockHeight)) {
        return mapZelnodeBlocks[nBlockHeight].GetRequiredPaymentsString();
    }

    return "Unknown";
}

bool Payments::IsTransactionValid(const CTransaction& txNew, int nBlockHeight)
{
    LOCK(cs_mapZelnodeBlocks);

    if (mapZelnodeBlocks.count(nBlockHeight)) {
        return mapZelnodeBlocks[nBlockHeight].IsTransactionValid(txNew);
    }

    return true;
}

void Payments::CleanPaymentList()
{
    LOCK2(cs_mapZelnodePayeeVotes, cs_mapZelnodeBlocks);

    int nHeight;
    {
        TRY_LOCK(cs_main, locked);
        if (!locked || chainActive.Tip() == NULL) return;
        nHeight = chainActive.Tip()->nHeight;
    }

    //keep up to five cycles for historical sake
    int nLimit = std::max(int(zelnodeman.size() * 1.25), 1000);

    std::map<uint256, PaymentWinner>::iterator it = mapZelnodePayeeVotes.begin();
    while (it != mapZelnodePayeeVotes.end()) {
        PaymentWinner winner = (*it).second;

        if (nHeight - winner.nBlockHeight > nLimit) {
            LogPrint("zelnodepayments", "%s - Removing old Zelnode payment - block %d\n", __func__, winner.nBlockHeight);
            zelnodeSync.mapSeenSyncZNW.erase((*it).first);
            mapZelnodePayeeVotes.erase(it++);
            mapZelnodeBlocks.erase(winner.nBlockHeight);
        } else {
            ++it;
        }
    }
}

bool PaymentWinner::IsValid(CNode* pnode, std::string& strError)
{
    bool fKamiookaUpgradeActive = NetworkUpgradeActive(nBlockHeight, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA);

    Zelnode* pzn = zelnodeman.Find(vinZelnode);

    if (!pzn) {
        strError = strprintf("Unknown Zelnode %s", vinZelnode.prevout.hash.ToString());
        LogPrint("zelnode","%s - hash: %s prevout: %s\n", __func__, strError, vinZelnode.ToString());
        zelnodeman.AskForZN(pnode, vinZelnode);
        return false;
    }

    if (pzn->protocolVersion < MIN_PEER_PROTO_VERSION_ZELNODE) {
        strError = strprintf("Zelnode protocol too old %d - req %d", pzn->protocolVersion, MIN_PEER_PROTO_VERSION_ZELNODE);
        LogPrint("zelnode","%s - %s\n", __func__, strError);
        return false;
    }

    int n = zelnodeman.GetZelnodeRank(vinZelnode, nBlockHeight - 100, MIN_PEER_PROTO_VERSION_ZELNODE);

    if (n > ZNPAYMENTS_SIGNATURES_TOTAL) {
        //It's common to have zelnodes mistakenly think they are in the top 10
        // We don't want to print all of these messages, or punish them unless they're way off
        if (n > ZNPAYMENTS_SIGNATURES_TOTAL * 2) {
            strError = strprintf("Zelnode not in the top %d (%d)", ZNPAYMENTS_SIGNATURES_TOTAL * 2, n);
            LogPrint("zelnode","%s - %s\n", __func__, strError);
        }
        return false;
    }

    if (tier < Zelnode::NONE || tier > Zelnode::BAMF) {
        strError = strprintf("Zelnode winner tier is %s", TierToString(tier));
        LogPrint("zelnode","%s - %s\n", __func__, strError);
        return false;
    }

    if (tier == Zelnode::NONE && IsSporkActive(SPORK_2_ZELNODE_UPGRADE_VOTE_ENFORCEMENT)) {
        strError = strprintf("Zelnode winner tier is %s and %s is active", TierToString(tier), sporkManager.GetSporkNameByID(SPORK_2_ZELNODE_UPGRADE_VOTE_ENFORCEMENT));
        LogPrint("zelnode","%s - %s\n", __func__, strError);
        return false;
    }

    if (fKamiookaUpgradeActive) {
        if (pzn->tier != tier) {
            strError = strprintf("Received zelnode payment winner, but the zelnode is voting for the wrong tier. Zelnode Tier %s, Payment Winner Tier %s", TierToString(pzn->tier), TierToString(tier));
            LogPrint("zelnode", "%s - %s\n", __func__, strError);
            return false;
        }
    }

    return true;
}

bool Payments::ProcessBlock(int nBlockHeight)
{
    if (!fZelnode) return false;

    //reference node - hybrid mode

    bool fKamiookaUpgradeActive = NetworkUpgradeActive(nBlockHeight, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA);

    int n = zelnodeman.GetZelnodeRank(activeZelnode.vin, nBlockHeight - 100, MIN_PEER_PROTO_VERSION_ZELNODE);

    if (n == -1) {
        LogPrint("zelnodepayments", "%s - Unknown Zelnode\n", __func__);
        return false;
    }

    if (n > ZNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrint("zelnodepayments", "%s - Zelnode not in the top %d (%d)\n", __func__, ZNPAYMENTS_SIGNATURES_TOTAL, n);
        return false;
    }

    if (nBlockHeight <= nLastBlockHeight) return false;

    LogPrint("zelnode","%s Start nHeight %d - vin %s. \n", __func__, nBlockHeight, activeZelnode.vin.prevout.hash.ToString());

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    int nBasicCount = 0;
    int nSuperCount = 0;
    int nBAMFCount = 0;


    auto activeNode = zelnodeman.Find(activeZelnode.pubKeyZelnode);
    vector<Zelnode*> vpzn = zelnodeman.GetNextZelnodeInQueueForPayment(nBlockHeight, true, nBasicCount, nSuperCount, nBAMFCount);

    for (Zelnode * pzn : vpzn) {
        PaymentWinner newWinner(activeZelnode.vin);
        if (pzn != NULL) {
            LogPrint("zelnode", "%s Found by FindOldestNotInVec \n", __func__);

            newWinner.nBlockHeight = nBlockHeight;
            if (fKamiookaUpgradeActive) {
                if (activeNode == NULL || activeNode->tier != pzn->tier)
                    continue;
            }
            newWinner.tier = pzn->tier;

            CScript payee = GetScriptForDestination(pzn->pubKeyCollateralAddress.GetID());
            newWinner.AddPayee(payee);

            CTxDestination address1;
            ExtractDestination(payee, address1);

            LogPrint("zelnode", "%s %s Winner payee %s nHeight %d. \n", __func__, TierToString(newWinner.tier), EncodeDestination(address1).c_str(),
                     newWinner.nBlockHeight);
        } else {
            LogPrint("zelnode", "%s Failed to find zelnode to pay\n", __func__);
        }

        std::string errorMessage;
        CPubKey pubKeyZelnode;
        CKey keyZelnode;

        if (!obfuScationSigner.SetKey(strZelnodePrivKey, errorMessage, keyZelnode, pubKeyZelnode)) {
            LogPrint("zelnode", "%s - Error upon calling SetKey: %s\n", __func__, errorMessage.c_str());
            continue;
        }

        if (!pzn) {
            LogPrint("zelnode", "%s - Zelnode was NULL continue through the process\n", __func__);
            continue;
        }

        if (newWinner.tier == Zelnode::NONE) {
            LogPrint("zelnode", "%s - Zelnode vote doesn't contain a tier\n", __func__);
            continue;
        }

        LogPrint("zelnode", "%s - Signing Winner\n", __func__);
        if (newWinner.Sign(keyZelnode, pubKeyZelnode)) {
            LogPrint("zelnode", "%s - AddWinningZelnode\n", __func__);

            if (AddWinningZelnode(newWinner, newWinner.tier)) {
                newWinner.Relay();
                nLastBlockHeight = nBlockHeight;
            }
        }
    }

    return false;
}

void PaymentWinner::Relay()
{
    CInv inv(MSG_ZELNODE_WINNER, GetHash());
    RelayInv(inv);
}

bool PaymentWinner::SignatureValid()
{
    Zelnode* pzn = zelnodeman.Find(vinZelnode);

    if (pzn != NULL) {
        std::string strMessage = vinZelnode.prevout.ToString() + std::to_string(nBlockHeight) + payee.ToString();

        std::string errorMessage = "";
        if (!obfuScationSigner.VerifyMessage(pzn->pubKeyZelnode, vchSig, strMessage, errorMessage)) {
            return error("%s - Got bad Zelnode address signature %s\n", __func__, vinZelnode.prevout.hash.ToString());
        }

        return true;
    }

    return false;
}

void Payments::Sync(CNode* node, int nCountNeeded)
{
    LOCK(cs_mapZelnodePayeeVotes);

    int nHeight;
    {
        TRY_LOCK(cs_main, locked);
        if (!locked || chainActive.Tip() == NULL) return;
        nHeight = chainActive.Tip()->nHeight;
    }

    int nCount = (zelnodeman.CountEnabled() * 1.25);
    if (nCountNeeded > nCount) nCountNeeded = nCount;

    int nInvCount = 0;
    std::map<uint256, PaymentWinner>::iterator it = mapZelnodePayeeVotes.begin();
    while (it != mapZelnodePayeeVotes.end()) {
        PaymentWinner winner = (*it).second;
        if (winner.nBlockHeight >= nHeight - nCountNeeded && winner.nBlockHeight <= nHeight + 20) {
            node->PushInventory(CInv(MSG_ZELNODE_WINNER, winner.GetHash()));
            nInvCount++;
        }
        ++it;
    }
    node->PushMessage("ssc", ZELNODE_SYNC_MNW, nInvCount);
}

std::string Payments::ToString() const
{
    std::ostringstream info;

    info << "Votes: " << mapZelnodePayeeVotes.size() << ", Blocks: " << (int)mapZelnodeBlocks.size();

    return info.str();
}

int Payments::GetOldestBlock()
{
    LOCK(cs_mapZelnodeBlocks);

    int nOldestBlock = std::numeric_limits<int>::max();

    std::map<int, ZelnodeBlockPayees>::iterator it = mapZelnodeBlocks.begin();
    while (it != mapZelnodeBlocks.end()) {
        if ((*it).first < nOldestBlock) {
            nOldestBlock = (*it).first;
        }
        it++;
    }

    return nOldestBlock;
}

int Payments::GetNewestBlock()
{
    LOCK(cs_mapZelnodeBlocks);

    int nNewestBlock = 0;

    std::map<int, ZelnodeBlockPayees>::iterator it = mapZelnodeBlocks.begin();
    while (it != mapZelnodeBlocks.end()) {
        if ((*it).first > nNewestBlock) {
            nNewestBlock = (*it).first;
        }
        it++;
    }

    return nNewestBlock;
}





