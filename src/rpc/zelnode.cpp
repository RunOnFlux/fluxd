// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2018-2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "zelnode/activezelnode.h"
#include "db.h"
#include "init.h"
#include "main.h"
#include "zelnode/zelnodeconfig.h"
#include "rpc/server.h"
#include "utilmoneystr.h"
#include "key_io.h"
#include "zelnode/benchmarks.h"
#include "util.h"

#include <univalue.h>

#include <boost/tokenizer.hpp>
#include <fstream>
#include <consensus/validation.h>
#include <undo.h>

#define MICRO 0.000001
#define MILLI 0.001

UniValue rebuildzelnodedb(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() > 0)
        throw runtime_error(
                "rebuildzelnodedb \n"
                "\nRescans the blockchain from the start of the zelnode transactions to rebuild the zelnodedb\n"
                "\nNote: This call can take minutes to complete\n"

                "\nExamples:\n"
                + HelpExampleCli("rebuildzelnodedb", "")
                + HelpExampleRpc("rebuildzelnodedb", "")
        );
    {
        LOCK2(cs_main, g_fluxnodeCache.cs);

        int nCurrentHeight = chainActive.Height();

        g_fluxnodeCache.SetNull();
        g_fluxnodeCache.InitMapFluxnodeList();

        delete pFluxnodeDB;
        pFluxnodeDB = NULL;
        pFluxnodeDB = new CDeterministicFluxnodeDB(0, false, true);

        CBlockIndex *rescanIndex = nullptr;

        rescanIndex = chainActive[Params().GetConsensus().vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight - 10];

        const int nTotalBlocks = nCurrentHeight - rescanIndex->nHeight;

        int nPrintTrigger = 0;
        int nPercent = 0;
        std::set<COutPoint> setSpentOutPoints;
        CFluxnodeTxBlockUndo fluxnodeTxBlockUndo;

        // Main benchmarks
        static int64_t nTimeLoadBlock = 0;
        static int64_t nTimeAddPaidNode = 0;
        static int64_t nTimeLoopTx = 0;
        static int64_t nTimeUndoData = 0;
        static int64_t nTimeWriteUndo = 0;
        static int64_t nTimeFlush = 0;
        static int64_t nTimeTotal = 0;
        static int64_t nBlocksTotal = 0;

        // Inner Tx loop benchmarks
        static int64_t nLoopSpentOutputs = 0;
        static int64_t nLoopFetchTx = 0;
        static int64_t nAddStart = 0;
        static int64_t nAddNewConfirm = 0;
        static int64_t nAddUpdateConfirm = 0;


        while (rescanIndex) {
            if (nPrintTrigger <= 0) {
                nPercent = (nTotalBlocks - (nCurrentHeight - rescanIndex->nHeight)) * 100 / nTotalBlocks;
                std::cout << "     " << _("Fluxnode blocks") << " | " << nCurrentHeight - rescanIndex->nHeight - nTotalBlocks << " / ~" << nTotalBlocks << " (" << nPercent << "%)" << std::endl;
                LogPrintf("Fluxnode blocks %d / %d (%d percent)\n", (nTotalBlocks - (nCurrentHeight - rescanIndex->nHeight)), nTotalBlocks, nPercent);

                LogPrint("bench", "Read block : [%.2fs (%.2fms/blk)]\n", nTimeLoadBlock * MICRO, nTimeLoadBlock * MILLI / nBlocksTotal);
                LogPrint("bench", "dpaidNode : [%.2fs (%.2fms/blk)]\n", nTimeAddPaidNode * MICRO, nTimeAddPaidNode * MILLI / nBlocksTotal);
                LogPrint("bench", "LoopTx : [%.2fs (%.2fms/blk)]\n", nTimeLoopTx * MICRO, nTimeLoopTx * MILLI / nBlocksTotal);
                LogPrint("bench", "Undo : [%.2fs (%.2fms/blk)]\n", nTimeUndoData * MICRO, nTimeUndoData * MILLI / nBlocksTotal);
                LogPrint("bench", "Write Undo : [%.2fs (%.2fms/blk)]\n", nTimeWriteUndo * MICRO, nTimeUndoData * MILLI  / nBlocksTotal);
                LogPrint("bench", "Flush : [%.2fs (%.2fms/blk)]\n", nTimeFlush * MICRO, nTimeFlush * MILLI  / nBlocksTotal);

                LogPrint("bench", "nLoopSpentOutputs : [%.2fs (%.2fms/blk)]\n", nLoopSpentOutputs * MICRO, nLoopSpentOutputs * MILLI  / nBlocksTotal);
                LogPrint("bench", "nLoopFetchTx : [%.2fs (%.2fms/blk)]\n", nLoopFetchTx * MICRO, nLoopFetchTx * MILLI  / nBlocksTotal);
                LogPrint("bench", "nAddStart : [%.2fs (%.2fms/blk)]\n", nAddStart * MICRO, nAddStart * MILLI  / nBlocksTotal);
                LogPrint("bench", "nAddNewConfirm : [%.2fs (%.2fms/blk)]\n", nAddNewConfirm * MICRO, nAddNewConfirm * MILLI  / nBlocksTotal);
                LogPrint("bench", "nAddUpdateConfirm : [%.2fs (%.2fms/blk)]\n", nAddUpdateConfirm * MICRO, nAddUpdateConfirm * MILLI  / nBlocksTotal);

                nPrintTrigger = 10000;
            }
            nPrintTrigger--;

            fluxnodeTxBlockUndo.SetNull();
            setSpentOutPoints.clear();

            FluxnodeCache fluxnodeCache;
            CBlock block;

            int64_t nTimeStart = GetTimeMicros();
            ReadBlockFromDisk(block, rescanIndex, Params().GetConsensus());
            nBlocksTotal++;

            int64_t nTime1 = GetTimeMicros(); nTimeLoadBlock += nTime1 - nTimeStart;

            // Add paidnode info
            if (rescanIndex->nHeight >= Params().StartFluxnodePayments()) {
                CTxDestination t_dest;
                COutPoint t_out;
                for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
                    if (g_fluxnodeCache.GetNextPayment(t_dest, currentTier, t_out)) {
                        fluxnodeCache.AddPaidNode(currentTier, t_out, rescanIndex->nHeight);
                    }
                }
            }

            int64_t nTime2 = GetTimeMicros(); nTimeAddPaidNode += nTime2 - nTime1;

            for (const auto& tx : block.vtx) {

                int64_t nLoopStart = GetTimeMicros();

                if (!tx.IsCoinBase() && !tx.IsFluxnodeTx()) {
                    for (const auto &input : tx.vin) {
                        setSpentOutPoints.insert(input.prevout);
                    }
                }

                int64_t nLoop1 = GetTimeMicros(); nLoopSpentOutputs += nLoop1 - nLoopStart;

                if (tx.IsFluxnodeTx()) {
                    int nTier = 0;
                    CTransaction get_tx;
                    uint256 block_hash;
                    if (GetTransaction(tx.collateralOut.hash, get_tx, Params().GetConsensus(), block_hash,
                                       true)) {

                        if (!GetCoinTierFromAmount(rescanIndex->nHeight, get_tx.vout[tx.collateralOut.n].nValue, nTier)) {
                            return error("Failed to get tier from amount. This shouldn't happen tx = %s", tx.collateralOut.ToFullString());
                        }

                    } else {
                        return error("Failed to find tx: %s", tx.collateralOut.ToFullString());
                    }

                    int64_t nLoop2 = GetTimeMicros(); nLoopFetchTx += nLoop2 - nLoop1;

                    if (tx.nType == FLUXNODE_START_TX_TYPE) {

                        // Add new Fluxnode Start Tx into local cache
                        fluxnodeCache.AddNewStart(tx, rescanIndex->nHeight, nTier, get_tx.vout[tx.collateralOut.n].nValue);
                        int64_t nLoop3 = GetTimeMicros(); nAddStart += nLoop3 - nLoop2;

                    } else if (tx.nType == FLUXNODE_CONFIRM_TX_TYPE) {
                        if (tx.nUpdateType == FluxnodeUpdateType::INITIAL_CONFIRM) {

                            fluxnodeCache.AddNewConfirm(tx, rescanIndex->nHeight);
                            int64_t nLoop4 = GetTimeMicros(); nAddNewConfirm += nLoop4 - nLoop2;
                        } else if (tx.nUpdateType == FluxnodeUpdateType::UPDATE_CONFIRM) {
                            fluxnodeCache.AddUpdateConfirm(tx, rescanIndex->nHeight);
                            FluxnodeCacheData global_data = g_fluxnodeCache.GetFluxnodeData(tx.collateralOut);
                            if (global_data.IsNull()) {
                                return error("Failed to find global data on update confirm tx, %s",
                                             tx.GetHash().GetHex());
                            }
                            fluxnodeTxBlockUndo.mapUpdateLastConfirmHeight.insert(
                                    std::make_pair(tx.collateralOut,
                                                   global_data.nLastConfirmedBlockHeight));
                            fluxnodeTxBlockUndo.mapLastIpAddress.insert(std::make_pair(tx.collateralOut, global_data.ip));
                            int64_t nLoop5 = GetTimeMicros(); nAddUpdateConfirm += nLoop5 - nLoop2;
                        }
                    }
                }
            }

            int64_t nTime3 = GetTimeMicros(); nTimeLoopTx += nTime3 - nTime2;

            // Update the temp cache with the set of started outpoints that have now expired from the dos list
            GetUndoDataForExpiredFluxnodeDosScores(fluxnodeTxBlockUndo, rescanIndex->nHeight);
            fluxnodeCache.AddExpiredDosTx(fluxnodeTxBlockUndo, rescanIndex->nHeight);

            // Update the temp cache with the set of confirmed outpoints that have now expired
            GetUndoDataForExpiredConfirmFluxnodes(fluxnodeTxBlockUndo, rescanIndex->nHeight, setSpentOutPoints);
            fluxnodeCache.AddExpiredConfirmTx(fluxnodeTxBlockUndo);

            // Update the block undo, with the paid nodes last paid height.
            GetUndoDataForPaidFluxnodes(fluxnodeTxBlockUndo, fluxnodeCache);

            // Check for Start tx that are going to expire
            fluxnodeCache.CheckForExpiredStartTx(rescanIndex->nHeight);

            int64_t nTime4 = GetTimeMicros(); nTimeUndoData += nTime4 - nTime3;

            if (fluxnodeTxBlockUndo.vecExpiredDosData.size() ||
                fluxnodeTxBlockUndo.vecExpiredConfirmedData.size() ||
                fluxnodeTxBlockUndo.mapUpdateLastConfirmHeight.size() ||
                fluxnodeTxBlockUndo.mapLastPaidHeights.size()) {
                if (!pFluxnodeDB->WriteBlockUndoFluxnodeData(block.GetHash(), fluxnodeTxBlockUndo))
                    return error("Failed to write fluxnodetx undo data");
            }

            int64_t nTime5 = GetTimeMicros(); nTimeWriteUndo += nTime5 - nTime4;

            assert(fluxnodeCache.Flush());

            int64_t nTime6 = GetTimeMicros(); nTimeFlush += nTime6 - nTime5;

            rescanIndex = chainActive.Next(rescanIndex);
        }
        g_fluxnodeCache.DumpFluxnodeCache();
    }

    return true;
}

UniValue rebuildfluxnodedb(const UniValue& params, bool fHelp) {
    return rebuildzelnodedb(params, fHelp);
}

UniValue createzelnodekey(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "createzelnodekey\n"
                "\nCreate a new zelnode private key\n"

                "\nResult:\n"
                "\"key\"    (string) Fluxnode private key\n"

                "\nExamples:\n" +
                HelpExampleCli("createzelnodekey", "") + HelpExampleRpc("createzelnodekey", ""));

    CKey secret;
    secret.MakeNewKey(false);
    return EncodeSecret(secret);
}

UniValue createfluxnodekey(const UniValue& params, bool fHelp)
{
    return createzelnodekey(params, fHelp);

}
UniValue createsporkkeys(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "createsporkkeys\n"
                "\nCreate a set of private and public keys used for sporks\n"

                "\nResult:\n"
                "\"pubkey\"    (string) Spork public key\n"
                "\"privkey\"    (string) Spork private key\n"

                "\nExamples:\n" +
                HelpExampleCli("createsporkkeys", "") + HelpExampleRpc("createsporkkeys", ""));

    CKey secret;
    secret.MakeNewKey(false);

    CPubKey pubKey = secret.GetPubKey();

    std::string str;
    for (int i = 0; i < pubKey.size(); i++) {
        str += pubKey[i];
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("pubkey", HexStr(str)));
    ret.push_back(Pair("privkey", EncodeSecret(secret)));
    return ret;
}

UniValue getzelnodeoutputs(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "getzelnodeoutputs\n"
                "\nPrint all zelnode transaction outputs\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"txhash\": \"xxxx\",    (string) output transaction hash\n"
                "    \"outputidx\": n       (numeric) output index number\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodeoutputs", "") + HelpExampleRpc("getzelnodeoutputs", ""));

    // Find possible candidates
    vector<std::pair<COutput, CAmount>> possibleCoins = activeFluxnode.SelectCoinsFluxnode();

    UniValue ret(UniValue::VARR);
    for (auto& pair : possibleCoins) {
        COutput out = pair.first;
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("txhash", out.tx->GetHash().ToString()));
        obj.push_back(Pair("outputidx", out.i));
        obj.push_back(Pair("ZEL Amount", pair.second / COIN));
        obj.push_back(Pair("Confirmations", pair.first.nDepth));
        ret.push_back(obj);
    }

    return ret;
}

UniValue getfluxnodeoutputs(const UniValue& params, bool fHelp)
{
    return getzelnodeoutputs(params, fHelp);
}

UniValue createconfirmationtransaction(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "createconfirmationtransaction\n"
                "\nCreate a new confirmation transaction and return the raw hex\n"

                "\nResult:\n"
                "    \"hex\": \"xxxx\",    (string) output transaction hex\n"

                "\nExamples:\n" +
                HelpExampleCli("createconfirmationtransaction", "") + HelpExampleRpc("createconfirmationtransaction", ""));

    if (!fFluxnode) throw runtime_error("This is not a Flux Node");

    std::string errorMessage;
    CMutableTransaction mutTx;
    mutTx.nVersion = FLUXNODE_TX_VERSION;

    activeFluxnode.BuildDeterministicConfirmTx(mutTx, FluxnodeUpdateType::UPDATE_CONFIRM);

    if (!activeFluxnode.SignDeterministicConfirmTx(mutTx, errorMessage)) {
        throw runtime_error(strprintf("Failed to sign new confirmation transaction: %s\n", errorMessage));
    }

    CTransaction tx(mutTx);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;
    return HexStr(ss.begin(), ss.end());
}

UniValue startzelnode(const UniValue& params, bool fHelp)
{

    std::string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();


    if (IsFluxnodeTransactionsActive()) {
        if (fHelp || params.size() < 2 || params.size() > 3 ||
            (params.size() == 2 && (strCommand != "all")) ||
            (params.size() == 3 && strCommand != "alias"))
            throw runtime_error(
                    "startzelnode \"all|alias\" lockwallet ( \"alias\" )\n"
                    "\nAttempts to start one or more zelnode(s)\n"

                    "\nArguments:\n"
                    "1. set         (string, required) Specify which set of zelnode(s) to start.\n"
                    "2. lockwallet  (boolean, required) Lock wallet after completion.\n"
                    "3. alias       (string) Fluxnode alias. Required if using 'alias' as the set.\n"

                    "\nResult: (for 'local' set):\n"
                    "\"status\"     (string) Fluxnode status message\n"

                    "\nResult: (for other sets):\n"
                    "{\n"
                    "  \"overall\": \"xxxx\",     (string) Overall status message\n"
                    "  \"detail\": [\n"
                    "    {\n"
                    "      \"node\": \"xxxx\",    (string) Node name or alias\n"
                    "      \"result\": \"xxxx\",  (string) 'success' or 'failed'\n"
                    "      \"error\": \"xxxx\"    (string) Error message, if failed\n"
                    "    }\n"
                    "    ,...\n"
                    "  ]\n"
                    "}\n"

                    "\nExamples:\n" +
                    HelpExampleCli("startzelnode", "\"alias\" \"0\" \"my_zn\"") + HelpExampleRpc("startzelnode", "\"alias\" \"0\" \"my_zn\""));


        if (IsInitialBlockDownload(Params())) {
            throw runtime_error("Chain is still syncing, please wait until chain is synced\n");
        }

        bool fLock = (params[1].get_str() == "true" ? true : false);

        EnsureWalletIsUnlocked();

        bool fAlias = false;
        std::string alias = "";
        if (params.size() == 3) {
            fAlias = true;
            alias = params[2].get_str();
        }

        bool found = false;
        int successful = 0;
        int failed = 0;

        UniValue resultsObj(UniValue::VARR);

        for (FluxnodeConfig::FluxnodeEntry zne : fluxnodeConfig.getEntries()) {
            UniValue fluxnodeEntry(UniValue::VOBJ);

            if (fAlias && zne.getAlias() == alias) {
                found = true;
            } else if (fAlias) {
                continue;
            }

            std::string errorMessage;
            CMutableTransaction mutTransaction;

            int32_t index;
            zne.castOutputIndex(index);
            COutPoint outpoint = COutPoint(uint256S(zne.getTxHash()), index);

            fluxnodeEntry.push_back(Pair("outpoint", outpoint.ToString()));
            fluxnodeEntry.push_back(Pair("alias", zne.getAlias()));

            bool fChecked = false;
            if (mempool.mapFluxnodeTxMempool.count(outpoint)) {
                fluxnodeEntry.push_back(Pair("result", "failed"));
                fluxnodeEntry.push_back(Pair("reason", "Mempool already has a zelnode transaction using this outpoint"));
            } else if (g_fluxnodeCache.InStartTracker(outpoint)) {
                fluxnodeEntry.push_back(Pair("result", "failed"));
                fluxnodeEntry.push_back(Pair("reason", "Fluxnode already started, waiting to be confirmed"));
            } else if (g_fluxnodeCache.InDoSTracker(outpoint)) {
                fluxnodeEntry.push_back(Pair("result", "failed"));
                fluxnodeEntry.push_back(Pair("reason", "Fluxnode already started then not confirmed, in DoS tracker. Must wait until out of DoS tracker to start"));
            } else if (g_fluxnodeCache.InConfirmTracker(outpoint)) {
                fluxnodeEntry.push_back(Pair("result", "failed"));
                fluxnodeEntry.push_back(Pair("reason", "Fluxnode already confirmed and in zelnode list"));
            } else {
                fChecked = true;
            }

            if (!fChecked) {
                resultsObj.push_back(fluxnodeEntry);

                if (fAlias)
                    return resultsObj;
                else
                    continue;
            }

            mutTransaction.nVersion = FLUXNODE_TX_VERSION;

            bool result = activeFluxnode.BuildDeterministicStartTx(zne.getPrivKey(), zne.getTxHash(), zne.getOutputIndex(), errorMessage, mutTransaction);

            fluxnodeEntry.push_back(Pair("transaction_built", result ? "successful" : "failed"));

            if (result) {
                CReserveKey reservekey(pwalletMain);
                std::string errorMessage;

                bool fSigned = false;
                if (activeFluxnode.SignDeterministicStartTx(mutTransaction, errorMessage)) {
                    CTransaction tx(mutTransaction);
                    fSigned = true;

                    CWalletTx walletTx(pwalletMain, tx);
                    CValidationState state;
                    bool fCommited = pwalletMain->CommitTransaction(walletTx, reservekey, &state);
                    fluxnodeEntry.push_back(Pair("transaction_commited", fCommited ? "successful" : "failed"));
                    if (fCommited) {
                        successful++;
                    } else {
                        errorMessage = state.GetRejectReason();
                        failed++;
                    }
                } else {
                    failed++;
                }
                fluxnodeEntry.push_back(Pair("transaction_signed", fSigned ? "successful" : "failed"));
                fluxnodeEntry.push_back(Pair("errorMessage", errorMessage));
            } else {
                failed++;
                fluxnodeEntry.push_back(Pair("errorMessage", errorMessage));
            }

            resultsObj.push_back(fluxnodeEntry);

            if (fAlias && found) {
                break;
            }
        }

        UniValue statusObj(UniValue::VOBJ);
        if (!found && fAlias) {
            failed++;
            statusObj.push_back(Pair("result", "failed"));
            statusObj.push_back(Pair("error", "could not find alias in config. Verify with list-conf."));
            resultsObj.push_back(statusObj);
        }

        if (fLock)
            pwalletMain->Lock();

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d fluxnodes, failed to start %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }
    return NullUniValue;
}

UniValue startfluxnode(const UniValue& params, bool fHelp) {
    return startzelnode(params, fHelp);
}

UniValue startdeterministiczelnode(const UniValue& params, bool fHelp)
{
    if (!IsFluxnodeTransactionsActive()) {
        throw runtime_error("deterministic fluxnodes transactions is not active yet");
    }

    std::string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp || params.size() != 2)
        throw runtime_error(
                "startdeterministiczelnode alias_name lockwallet\n"
                "\nAttempts to start one fluxnode\n"

                "\nArguments:\n"
                "1. set         (string, required) Specify which set of fluxnode(s) to start.\n"
                "2. lockwallet  (boolean, required) Lock wallet after completion.\n"
                "3. alias       (string) Fluxnode alias. Required if using 'alias' as the set.\n"

                "\nResult: (for 'local' set):\n"
                "\"status\"     (string) Fluxnode status message\n"

                "\nResult: (for other sets):\n"
                "{\n"
                "  \"overall\": \"xxxx\",     (string) Overall status message\n"
                "  \"detail\": [\n"
                "    {\n"
                "      \"node\": \"xxxx\",    (string) Node name or alias\n"
                "      \"result\": \"xxxx\",  (string) 'success' or 'failed'\n"
                "      \"error\": \"xxxx\"    (string) Error message, if failed\n"
                "    }\n"
                "    ,...\n"
                "  ]\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("startdeterministiczelnode", "\"alias_name\" false ") + HelpExampleRpc("startdeterministiczelnode", "\"alias_name\" false"));

    bool fLock = (params[1].get_str() == "true" ? true : false);

    EnsureWalletIsUnlocked();

    std::string alias = params[0].get_str();

    bool found = false;
    int successful = 0;
    int failed = 0;

    UniValue resultsObj(UniValue::VARR);
    UniValue statusObj(UniValue::VOBJ);
    statusObj.push_back(Pair("alias", alias));

    for (FluxnodeConfig::FluxnodeEntry zne : fluxnodeConfig.getEntries()) {
        if (zne.getAlias() == alias) {
            found = true;
            std::string errorMessage;

            CMutableTransaction mutTransaction;

            int32_t index;
            zne.castOutputIndex(index);
            UniValue returnObj(UniValue::VOBJ);
            COutPoint outpoint = COutPoint(uint256S(zne.getTxHash()), index);
            if (mempool.mapFluxnodeTxMempool.count(outpoint)) {
                returnObj.push_back(Pair("result", "failed"));
                returnObj.push_back(Pair("reason", "Mempool already has a fluxnode transaction using this outpoint"));
                return returnObj;
            } else if (g_fluxnodeCache.InStartTracker(outpoint)) {
                returnObj.push_back(Pair("result", "failed"));
                returnObj.push_back(Pair("reason", "Fluxnode already started, waiting to be confirmed"));
                return returnObj;
            } else if (g_fluxnodeCache.InDoSTracker(outpoint)) {
                returnObj.push_back(Pair("result", "failed"));
                returnObj.push_back(Pair("reason", "Fluxnode already started then not confirmed, in DoS tracker. Must wait until out of DoS tracker to start"));
                return returnObj;
            } else if (g_fluxnodeCache.InConfirmTracker(outpoint)) {
                returnObj.push_back(Pair("result", "failed"));
                returnObj.push_back(Pair("reason", "Fluxnode already confirmed and in fluxnode list"));
                return returnObj;
            }

            mutTransaction.nVersion = FLUXNODE_TX_VERSION;

            bool result = activeFluxnode.BuildDeterministicStartTx(zne.getPrivKey(), zne.getTxHash(), zne.getOutputIndex(), errorMessage, mutTransaction);

            statusObj.push_back(Pair("result", result ? "successful" : "failed"));

            if (result) {
                CReserveKey reservekey(pwalletMain);
                std::string errorMessage;

                if (activeFluxnode.SignDeterministicStartTx(mutTransaction, errorMessage)) {
                    CTransaction tx(mutTransaction);

                    CWalletTx walletTx(pwalletMain, tx);
                    pwalletMain->CommitTransaction(walletTx, reservekey);
                    successful++;
                } else {
                    failed++;
                    statusObj.push_back(Pair("errorMessage", errorMessage));
                }
            } else {
                failed++;
                statusObj.push_back(Pair("errorMessage", errorMessage));
            }
            break;
        }
    }

    if (!found) {
        failed++;
        statusObj.push_back(Pair("result", "failed"));
        statusObj.push_back(Pair("error", "could not find alias in config. Verify with listzelnodeconf."));
    }

    resultsObj.push_back(statusObj);

    if (fLock)
        pwalletMain->Lock();

    UniValue returnObj(UniValue::VOBJ);
    returnObj.push_back(Pair("overall", strprintf("Successfully started %d fluxnodes, failed to start %d, total %d", successful, failed, successful + failed)));
    returnObj.push_back(Pair("detail", resultsObj));

    return returnObj;
}

UniValue startdeterministicfluxnode(const UniValue& params, bool fHelp)
{
    return startdeterministiczelnode(params, fHelp);
}

void GetDeterministicListData(UniValue& listData, const std::string& strFilter, const Tier tier) {
    int count = 0;
    for (const auto& item : g_fluxnodeCache.mapFluxnodeList.at(tier).listConfirmedFluxnodes) {

        auto data = g_fluxnodeCache.GetFluxnodeData(item.out);

        UniValue info(UniValue::VOBJ);

        if (!data.IsNull()) {
            std::string strTxHash = data.collateralIn.GetTxHash();


            CTxDestination payment_destination;
            if (IsAP2SHFluxNodePublicKey(data.collateralPubkey)) {
                GetFluxNodeP2SHDestination(pcoinsTip, data.collateralIn, payment_destination);
            } else {
                payment_destination = data.collateralPubkey.GetID();
            }


            if (strFilter != "" && strTxHash.find(strFilter) == string::npos && HexStr(data.pubKey).find(strFilter) &&
                data.ip.find(strFilter) && EncodeDestination(payment_destination).find(strFilter) == string::npos)
                continue;

            std::string strHost = data.ip;
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("txhash", strTxHash));
            info.push_back(std::make_pair("outidx", data.collateralIn.GetTxIndex()));
            info.push_back(std::make_pair("ip", data.ip));
            info.push_back(std::make_pair("network", strNetwork));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            info.push_back(std::make_pair("tier", data.TierToString()));
            info.push_back(std::make_pair("payment_address", EncodeDestination(payment_destination)));
            info.push_back(std::make_pair("pubkey", HexStr(data.pubKey)));
            if (chainActive.Height() >= data.nAddedBlockHeight)
                info.push_back(std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
            else
                info.push_back(std::make_pair("activesince", 0));
            if (chainActive.Height() >= data.nLastPaidHeight)
                info.push_back(std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
            else
                info.push_back(std::make_pair("lastpaid", 0));

            if (data.nCollateral > 0) {
                info.push_back(std::make_pair("amount", FormatMoney(data.nCollateral)));
            }

            info.push_back(std::make_pair("rank", count++));

            listData.push_back(info);
        }
    }
}

UniValue viewdeterministiczelnodelist(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
                "viewdeterministicfluxnodelist ( \"filter\" )\n"
                "\nView the list of deterministric fluxnode(s)\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"collateral\": n,                       (string) Collateral transaction\n"
                "    \"txhash\": \"hash\",                    (string) Collateral transaction hash\n"
                "    \"outidx\": n,                           (numeric) Collateral transaction output index\n"
                "    \"ip\": \"address\"                      (string) IP address\n"
                "    \"network\": \"network\"                 (string) Network type (IPv4, IPv6, onion)\n"
                "    \"added_height\": \"height\"             (string) Block height when fluxnode was added\n"
                "    \"confirmed_height\": \"height\"         (string) Block height when fluxnode was confirmed\n"
                "    \"last_confirmed_height\": \"height\"    (string) Last block height when fluxnode was confirmed\n"
                "    \"last_paid_height\": \"height\"         (string) Last block height when fluxnode was paid\n"
                "    \"tier\": \"type\",                      (string) Tier (CUMULUS/NIMBUS/STRATUS)\n"
                "    \"payment_address\": \"addr\",           (string) Fluxnode ZEL address\n"
                "    \"pubkey\": \"key\",                     (string) Fluxnode public key used for message broadcasting\n"
                "    \"activesince\": ttt,                    (numeric) The time in seconds since epoch (Jan 1 1970 GMT) fluxnode has been active\n"
                "    \"lastpaid\": ttt,                       (numeric) The time in seconds since epoch (Jan 1 1970 GMT) fluxnode was last paid\n"
                "    \"rank\": n                              (numberic) rank\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("viewdeterministiczelnodelist", ""));

    if (IsInitialBlockDownload(Params())) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Wait until chain is synced closer to tip");
    }

    // Get filter if any
    std::string strFilter = "";
    if (params.size() == 1) strFilter = params[0].get_str();

    // Create empty list
    UniValue deterministicList(UniValue::VARR);

    // Fill list
    for (int currentTier = CUMULUS; currentTier != LAST; currentTier++)
    {
        GetDeterministicListData(deterministicList, strFilter, (Tier)currentTier);
    }

    // Return list
    return deterministicList;
}

UniValue listzelnodes(const UniValue& params, bool fHelp)
{
    return viewdeterministiczelnodelist(params, fHelp);
}

UniValue listfluxnodes(const UniValue& params, bool fHelp)
{
    return viewdeterministiczelnodelist(params, fHelp);
}

UniValue viewdeterministicfluxnodelist(const UniValue& params, bool fHelp)
{
    return viewdeterministiczelnodelist(params, fHelp);
}

UniValue getdoslist(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
                "getdoslist\n"
                "\nGet a list of all fluxnodes in the DOS list\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"collateral\": \"hash\",  (string) Collateral transaction hash\n"
                "    \"added_height\": n,   (numeric) Height the fluxnode start transaction was added to the chain\n"
                "    \"payment_address\": \"xxx\",   (string) The payment address associated with the fluxnode\n"
                "    \"eligible_in\": n,     (numeric) The amount of blocks before the fluxnode is eligible to be started again\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("getdoslist", "") + HelpExampleRpc("getdoslist", ""));

    if (IsDFluxnodeActive()) {
        UniValue wholelist(UniValue::VARR);

        std::map<int, std::vector<UniValue>> mapOrderedDosList;

        for (const auto& item : g_fluxnodeCache.mapStartTxDosTracker) {

            // Get the data from the item in the map of dox tracking
            const FluxnodeCacheData data = item.second;

            CTxDestination payment_destination;
            if (IsAP2SHFluxNodePublicKey(data.collateralPubkey)) {
                GetFluxNodeP2SHDestination(pcoinsTip, data.collateralIn, payment_destination);
            } else {
                payment_destination = data.collateralPubkey.GetID();
            }

            UniValue info(UniValue::VOBJ);

            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("payment_address", EncodeDestination(payment_destination)));

            int nCurrentHeight = chainActive.Height();
            int nEligibleIn = FLUXNODE_DOS_REMOVE_AMOUNT - (nCurrentHeight - data.nAddedBlockHeight);
            info.push_back(std::make_pair("eligible_in",  nEligibleIn));

            if (data.nCollateral > 0) {
                info.push_back(std::make_pair("amount", FormatMoney(data.nCollateral)));
            }

            mapOrderedDosList[nEligibleIn].emplace_back(info);
        }

        if (mapOrderedDosList.size()) {
            for (int i = 0; i < FLUXNODE_DOS_REMOVE_AMOUNT + 1; i++) {
                if (mapOrderedDosList.count(i)) {
                    for (const auto& item : mapOrderedDosList.at(i)) {
                        wholelist.push_back(item);
                    }
                }
            }
        }

        return wholelist;
    }

    return NullUniValue;
}

UniValue getstartlist(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
                "getstartlist\n"
                "\nGet a list of all fluxnodes in the start list\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"collateral\": \"hash\",  (string) Collateral transaction hash\n"
                "    \"added_height\": n,   (numeric) Height the fluxnode start transaction was added to the chain\n"
                "    \"payment_address\": \"xxx\",   (string) The payment address associated with the fluxnode\n"
                "    \"expires_in\": n,     (numeric) The amount of blocks before the start transaction expires, unless a confirmation transaction is added to a block\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("getstartlist", "") + HelpExampleRpc("getstartlist", ""));

    if (IsDFluxnodeActive()) {
        UniValue wholelist(UniValue::VARR);

        std::map<int, std::vector<UniValue>> mapOrderedStartList;

        for (const auto& item : g_fluxnodeCache.mapStartTxTracker) {

            // Get the data from the item in the map of dox tracking
            const FluxnodeCacheData data = item.second;

            CTxDestination payment_destination;
            if (IsAP2SHFluxNodePublicKey(data.collateralPubkey)) {
                GetFluxNodeP2SHDestination(pcoinsTip, data.collateralIn, payment_destination);
            } else {
                payment_destination = data.collateralPubkey.GetID();
            }

            UniValue info(UniValue::VOBJ);

            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("payment_address", EncodeDestination(payment_destination)));

            int nCurrentHeight = chainActive.Height();
            int nExpiresIn = FLUXNODE_START_TX_EXPIRATION_HEIGHT - (nCurrentHeight - data.nAddedBlockHeight);

            info.push_back(std::make_pair("expires_in",  nExpiresIn));

            if (data.nCollateral > 0) {
                info.push_back(std::make_pair("amount", FormatMoney(data.nCollateral)));
            }

            mapOrderedStartList[nExpiresIn].emplace_back(info);
        }

        if (mapOrderedStartList.size()) {
            for (int i = 0; i < FLUXNODE_START_TX_EXPIRATION_HEIGHT + 1; i++) {
                if (mapOrderedStartList.count(i)) {
                    for (const auto& item : mapOrderedStartList.at(i)) {
                        wholelist.push_back(item);
                    }
                }
            }
        }

        return wholelist;
    }

    return NullUniValue;
}

UniValue getzelnodestatus (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "getzelnodestatus\n"
                "\nPrint zelnode status\n"

                "\nResult:\n"
                "{\n"
                "  \"status\": \"xxxx\",                    (string) Fluxnode status\n"
                "  \"collateral\": n,                       (string) Collateral transaction\n"
                "  \"txhash\": \"xxxx\",                    (string) Collateral transaction hash\n"
                "  \"outidx\": n,                           (numeric) Collateral transaction output index number\n"
                "  \"ip\": \"xxxx\",                        (string) Fluxnode network address\n"
                "  \"network\": \"network\",                (string) Network type (IPv4, IPv6, onion)\n"
                "  \"added_height\": \"height\",            (string) Block height when fluxnode was added\n"
                "  \"confirmed_height\": \"height\",        (string) Block height when fluxnode was confirmed\n"
                "  \"last_confirmed_height\": \"height\",   (string) Last block height when fluxnode was confirmed\n"
                "  \"last_paid_height\": \"height\",        (string) Last block height when fluxnode was paid\n"
                "  \"tier\": \"type\",                      (string) Tier (CUMULUS/NIMBUS/STRATUS)\n"
                "  \"payment_address\": \"xxxx\",           (string) ZEL address for fluxnode payments\n"
                "  \"pubkey\": \"key\",                     (string) Fluxnode public key used for message broadcasting\n"
                "  \"activesince\": ttt,                    (numeric) The time in seconds since epoch (Jan 1 1970 GMT) fluxnode has been active\n"
                "  \"lastpaid\": ttt,                       (numeric) The time in seconds since epoch (Jan 1 1970 GMT) fluxnode was last paid\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodestatus", "") + HelpExampleRpc("getzelnodestatus", ""));

    if (!fFluxnode) throw runtime_error("This is not a Flux Node");

    if (IsDFluxnodeActive()) {
        int nLocation = FLUXNODE_TX_ERROR;
        auto data = g_fluxnodeCache.GetFluxnodeData(activeFluxnode.deterministicOutPoint, &nLocation);

        UniValue info(UniValue::VOBJ);

        if (data.IsNull()) {
            info.push_back(std::make_pair("status", "expired"));
            info.push_back(std::make_pair("collateral", activeFluxnode.deterministicOutPoint.ToFullString()));
        } else {
            std::string strTxHash = data.collateralIn.GetTxHash();
            std::string strHost = data.ip;
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            info.push_back(std::make_pair("status", FluxnodeLocationToString(nLocation)));
            info.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
            info.push_back(std::make_pair("txhash", strTxHash));
            info.push_back(std::make_pair("outidx", data.collateralIn.GetTxIndex()));
            info.push_back(std::make_pair("ip", data.ip));
            info.push_back(std::make_pair("network", strNetwork));
            info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
            info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
            info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
            info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
            info.push_back(std::make_pair("tier", data.TierToString()));
            info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
            info.push_back(std::make_pair("pubkey", HexStr(data.pubKey)));
            if (chainActive.Height() >= data.nAddedBlockHeight)
                info.push_back(std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
            else
                info.push_back(std::make_pair("activesince", 0));
            if (chainActive.Height() >= data.nLastPaidHeight)
                info.push_back(std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
            else
                info.push_back(std::make_pair("lastpaid", 0));

            if (data.nCollateral > 0) {
                info.push_back(std::make_pair("amount", FormatMoney(data.nCollateral)));
            }
        }

        return info;
    }

    return NullUniValue;

}

UniValue getfluxnodestatus (const UniValue& params, bool fHelp)
{
    return getzelnodestatus (params, fHelp);
}

UniValue zelnodecurrentwinner (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "zelnodecurrentwinner\n"
                "\nGet current zelnode winner\n"

                "\nResult:\n"
                "{\n"
                "  \"protocol\": xxxx,        (numeric) Protocol version\n"
                "  \"txhash\": \"xxxx\",      (string) Collateral transaction hash\n"
                "  \"pubkey\": \"xxxx\",      (string) ZN Public key\n"
                "  \"lastseen\": xxx,       (numeric) Time since epoch of last seen\n"
                "  \"activeseconds\": xxx,  (numeric) Seconds ZN has been active\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("zelnodecurrentwinner", "") + HelpExampleRpc("zelnodecurrentwinner", ""));

    if (IsDFluxnodeActive()) {
        UniValue ret(UniValue::VOBJ);

        for (int currentTier = CUMULUS; currentTier != LAST; currentTier++) {
            CTxDestination dest;
            COutPoint outpoint;
            string strWinner = TierToString(currentTier) + " Winner";
            if (g_fluxnodeCache.GetNextPayment(dest, currentTier, outpoint)) {
                UniValue obj(UniValue::VOBJ);
                auto data = g_fluxnodeCache.GetFluxnodeData(outpoint);
                obj.push_back(std::make_pair("collateral", data.collateralIn.ToFullString()));
                obj.push_back(std::make_pair("ip", data.ip));
                obj.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
                obj.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
                obj.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
                obj.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
                obj.push_back(std::make_pair("tier", TierToString(data.nTier)));
                obj.push_back(std::make_pair("payment_address", EncodeDestination(dest)));
                ret.push_back(std::make_pair(strWinner, obj));
            }
        }

        return ret;
    }

    return NullUniValue;
}

UniValue fluxnodecurrentwinner (const UniValue& params, bool fHelp)
{
    return zelnodecurrentwinner (params, fHelp);
}

UniValue getzelnodecount (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
                "getzelnodecount\n"
                "\nGet zelnode count values\n"

                "\nResult:\n"
                "{\n"
                "  \"total\": n,        (numeric) Total fluxnodes\n"
                "  \"stable\": n,       (numeric) Stable count\n"
                "  \"enabled\": n,      (numeric) Enabled fluxnodes\n"
                "  \"inqueue\": n       (numeric) Fluxnodes in queue\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodecount", "") + HelpExampleRpc("getzelnodecount", ""));

    UniValue obj(UniValue::VOBJ);

    if (IsDFluxnodeActive())
    {
        int ipv4 = 0, ipv6 = 0, onion = 0, nTotal = 0;
        std::vector<int> vNodeCount(GetNumberOfTiers());
        {
            LOCK(g_fluxnodeCache.cs);

            g_fluxnodeCache.CountNetworks(ipv4, ipv6, onion, vNodeCount);

            nTotal = g_fluxnodeCache.mapConfirmedFluxnodeData.size();
        }

        obj.push_back(Pair("total", nTotal));
        obj.push_back(Pair("stable", nTotal));

        std::map<int,pair<string,string> > words;
        words.insert(make_pair(0, make_pair("basic-enabled", "cumulus-enabled")));
        words.insert(make_pair(1, make_pair("super-enabled", "nimbus-enabled")));
        words.insert(make_pair(2, make_pair("bamf-enabled", "stratus-enabled")));
        for (int i = 0; i < vNodeCount.size(); i++) {
            if (words.count(i)) {
                obj.push_back(Pair(words.at(i).first, vNodeCount[i]));
            } else {
                obj.push_back(Pair("unnamed-enabled", vNodeCount[i]));
            }
        }

        for (int i = 0; i < vNodeCount.size(); i++) {
            if (words.count(i)) {
                obj.push_back(Pair(words.at(i).second, vNodeCount[i]));
            } else {
                obj.push_back(Pair("unnamed-enabled", vNodeCount[i]));
            }
        }

        obj.push_back(Pair("ipv4", ipv4));
        obj.push_back(Pair("ipv6", ipv6));
        obj.push_back(Pair("onion", onion));

        return obj;
    }

    return NullUniValue;
}

UniValue getfluxnodecount (const UniValue& params, bool fHelp)
{
    return getzelnodecount (params, fHelp);
}

UniValue getmigrationcount (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
                "getmigrationcount\n"
                "\nGet fluxnode migration count values\n"

                "\nResult:\n"
                "{\n"
                "  \"total-old\": n,        (numeric) Total fluxnodes\n"
                "  \"total-new\": n,        (numeric) Total fluxnodes\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getmigrationcount", "") + HelpExampleRpc("getmigrationcount", ""));

    if (IsDFluxnodeActive())
    {
        int nTotalOld = 0;
        int nTotalNew = 0;
        std::vector<int> vOldNodeCount(GetNumberOfTiers());
        std::vector<int> vNewNodeCount(GetNumberOfTiers());
        {
            LOCK(g_fluxnodeCache.cs);
            g_fluxnodeCache.CountMigration(nTotalOld, nTotalNew,vOldNodeCount, vNewNodeCount);
        }

        std::map<int,pair<string,string> > words;
        words.insert(make_pair(0, make_pair("basic-enabled", "cumulus-enabled")));
        words.insert(make_pair(1, make_pair("super-enabled", "nimbus-enabled")));
        words.insert(make_pair(2, make_pair("bamf-enabled", "stratus-enabled")));

        UniValue oldTierCount(UniValue::VOBJ);
        oldTierCount.pushKV("total-old", nTotalOld);
        for (int i = 0; i < vOldNodeCount.size(); i++) {
            if (words.count(i)) {
                oldTierCount.push_back(Pair(words.at(i).second + "-old", vOldNodeCount[i]));
            } else {
                oldTierCount.push_back(Pair("unnamed-enabled-old", vOldNodeCount[i]));
            }
        }

        UniValue newTierCount(UniValue::VOBJ);
        newTierCount.pushKV("total-new", nTotalNew);
        for (int i = 0; i < vNewNodeCount.size(); i++) {
            if (words.count(i)) {
                newTierCount.push_back(Pair(words.at(i).second + "-new", vNewNodeCount[i]));
            } else {
                newTierCount.push_back(Pair("unnamed-enabled-new", vNewNodeCount[i]));
            }
        }

        UniValue result(UniValue::VARR);

        result.push_back(oldTierCount);
        result.push_back(newTierCount);
        return result;
    }

    return NullUniValue;
}

UniValue listzelnodeconf (const UniValue& params, bool fHelp)
{
    std::string strFilter = "";

    if (params.size() == 1) strFilter = params[0].get_str();

    if (fHelp || (params.size() > 1))
        throw runtime_error(
                "listzelnodeconf ( \"filter\" )\n"
                "\nPrint fluxnode.conf in JSON format\n"

                "\nArguments:\n"
                "1. \"filter\"    (string, optional) Filter search text. Partial match on alias, address, txHash, or status.\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"alias\": \"xxxx\",                       (string) fluxnode alias\n"
                "    \"status\": \"xxxx\",                      (string) fluxnode status\n"
                "    \"collateral\": n,                         (string) Collateral transaction\n"
                "    \"txHash\": \"xxxx\",                      (string) transaction hash\n"
                "    \"outputIndex\": n,                        (numeric) transaction output index\n"
                "    \"privateKey\": \"xxxx\",                  (string) fluxnode private key\n"
                "    \"address\": \"xxxx\",                     (string) fluxnode IP address\n"
                "    \"ip\": \"xxxx\",                          (string) Fluxnode network address\n"
                "    \"network\": \"network\",                  (string) Network type (IPv4, IPv6, onion)\n"
                "    \"added_height\": \"height\",              (string) Block height when fluxnode was added\n"
                "    \"confirmed_height\": \"height\",          (string) Block height when fluxnode was confirmed\n"
                "    \"last_confirmed_height\": \"height\",     (string) Last block height when fluxnode was confirmed\n"
                "    \"last_paid_height\": \"height\",          (string) Last block height when fluxnode was paid\n"
                "    \"tier\": \"type\",                        (string) Tier (CUMULUS/NIMBUS/STRATUS)\n"
                "    \"payment_address\": \"xxxx\",             (string) ZEL address for fluxnode payments\n"
                "    \"activesince\": ttt,                      (numeric) The time in seconds since epoch (Jan 1 1970 GMT) fluxnode has been active\n"
                "    \"lastpaid\": ttt,                         (numeric) The time in seconds since epoch (Jan 1 1970 GMT) fluxnode was last paid\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("listzelnodeconf", "") + HelpExampleRpc("listzelnodeconf", ""));

    std::vector<FluxnodeConfig::FluxnodeEntry> fluxnodeEntries;
    fluxnodeEntries = fluxnodeConfig.getEntries();

    UniValue ret(UniValue::VARR);

    for (FluxnodeConfig::FluxnodeEntry fluxnode : fluxnodeEntries) {
        if (IsDFluxnodeActive()) {
            int nIndex;
            if (!fluxnode.castOutputIndex(nIndex))
                continue;
            COutPoint out = COutPoint(uint256S(fluxnode.getTxHash()), uint32_t(nIndex));

            int nLocation = FLUXNODE_TX_ERROR;
            auto data = g_fluxnodeCache.GetFluxnodeData(out, &nLocation);

            UniValue info(UniValue::VOBJ);
            info.push_back(Pair("alias", fluxnode.getAlias()));
            info.push_back(Pair("status", FluxnodeLocationToString(nLocation)));
            info.push_back(Pair("collateral", out.ToFullString()));
            info.push_back(Pair("txHash", fluxnode.getTxHash()));
            info.push_back(Pair("outputIndex", fluxnode.getOutputIndex()));
            info.push_back(Pair("privateKey", fluxnode.getPrivKey()));
            info.push_back(Pair("address", fluxnode.getIp()));

            if (data.IsNull()) {
                info.push_back(std::make_pair("ip", "UNKNOWN"));
                info.push_back(std::make_pair("network", "UNKOWN"));
                info.push_back(std::make_pair("added_height", 0));
                info.push_back(std::make_pair("confirmed_height", 0));
                info.push_back(std::make_pair("last_confirmed_height", 0));
                info.push_back(std::make_pair("last_paid_height", 0));
                info.push_back(std::make_pair("tier", "UNKNOWN"));
                info.push_back(std::make_pair("payment_address", "UNKNOWN"));
                info.push_back(std::make_pair("activesince", 0));
                info.push_back(std::make_pair("lastpaid", 0));
            } else {
                std::string strHost = data.ip;
                CNetAddr node = CNetAddr(strHost, false);
                std::string strNetwork = GetNetworkName(node.GetNetwork());
                info.push_back(std::make_pair("ip", data.ip));
                info.push_back(std::make_pair("network", strNetwork));
                info.push_back(std::make_pair("added_height", data.nAddedBlockHeight));
                info.push_back(std::make_pair("confirmed_height", data.nConfirmedBlockHeight));
                info.push_back(std::make_pair("last_confirmed_height", data.nLastConfirmedBlockHeight));
                info.push_back(std::make_pair("last_paid_height", data.nLastPaidHeight));
                info.push_back(std::make_pair("tier", TierToString(data.nTier)));
                info.push_back(std::make_pair("payment_address", EncodeDestination(data.collateralPubkey.GetID())));
                if (chainActive.Height() >= data.nAddedBlockHeight)
                    info.push_back(
                            std::make_pair("activesince", std::to_string(chainActive[data.nAddedBlockHeight]->nTime)));
                else
                    info.push_back(std::make_pair("activesince", 0));
                if (chainActive.Height() >= data.nLastPaidHeight)
                    info.push_back(
                            std::make_pair("lastpaid", std::to_string(chainActive[data.nLastPaidHeight]->nTime)));
                else
                    info.push_back(std::make_pair("lastpaid", 0));
            }

            ret.push_back(info);
            continue;
        }
    }

    return ret;
}

UniValue listfluxnodeconf (const UniValue& params, bool fHelp)
{
    return listzelnodeconf (params, fHelp);
}

UniValue getbenchmarks(const UniValue& params, bool fHelp)
{
    if (!fFluxnode) throw runtime_error("This is not a Flux Node");

    if (fHelp || params.size() != 0)
        throw runtime_error(
                "getbenchmarks\n"
                "\nCommand to test node benchmarks\n"

                "\nExamples:\n" +
                HelpExampleCli("getbenchmarks", "") + HelpExampleRpc("getbenchmarks", ""));

    return GetBenchmarks();
}

UniValue getbenchstatus(const UniValue& params, bool fHelp)
{
    if (!fFluxnode) throw runtime_error("This is not a Flux Node");

    if (fHelp || params.size() != 0)
        throw runtime_error(
                "getbenchstatus\n"
                "\nCommand to get status of zelbenchd\n"

                "\nExamples:\n" +
                HelpExampleCli("getbenchstatus", "") + HelpExampleRpc("getbenchstatus", ""));

    return GetZelBenchdStatus();
}


UniValue stopzelbenchd(const UniValue& params, bool fHelp)
{
    if (!fFluxnode) throw runtime_error("This is not a Flux Node");

    if (fHelp || params.size() != 0)
        throw runtime_error(
                "stopzelbenchd\n"
                "\nStop zelbenchd\n"

                "\nExamples:\n" +
                HelpExampleCli("stopzelbenchd", "") + HelpExampleRpc("stopzelbenchd", ""));

    if (IsZelBenchdRunning()) {
        StopZelBenchd();
        return "Stopping process";
    }

    return "Not running";
}

UniValue startzelbenchd(const UniValue& params, bool fHelp)
{
    if (!fFluxnode) throw runtime_error("This is not a Flux Node");

    if (fHelp || params.size() != 0)
        throw runtime_error(
                "startzelbenchd\n"
                "\nStart zelbenchd\n"

                "\nExamples:\n" +
                HelpExampleCli("startzelbenchd", "") + HelpExampleRpc("startzelbenchd", ""));

    if (!IsZelBenchdRunning()) {
        StartZelBenchd();
        return "Starting process";
    }

    return "Already running";
}




static const CRPCCommand commands[] =
        { //  category              name                      actor (function)         okSafeMode
                //  --------------------- ------------------------  -----------------------  ----------
                { "fluxnode",   "createzelnodekey",       &createzelnodekey,       false  },
                { "fluxnode",   "getzelnodeoutputs",      &getzelnodeoutputs,      false  },
                { "fluxnode",   "startzelnode",           &startzelnode,           false  },
                { "fluxnode",   "listzelnodes",           &listzelnodes,           false  },
                { "fluxnode",   "getdoslist",             &getdoslist,             false  },
                { "fluxnode",   "getstartlist",           &getstartlist,           false  },
                { "fluxnode",   "getzelnodecount",        &getzelnodecount,        false  },
                { "fluxnode",   "getmigrationcount",      &getmigrationcount,        false },
                { "fluxnode",   "zelnodecurrentwinner",   &zelnodecurrentwinner,   false  }, /* uses wallet if enabled */
                { "fluxnode",   "getzelnodestatus",       &getzelnodestatus,       false  },
                { "fluxnode",   "listzelnodeconf",        &listzelnodeconf,        false  },
                { "hidden",     "rebuildzelnodedb",       &rebuildzelnodedb,       false  },

                { "fluxnode",   "startdeterministiczelnode", &startdeterministiczelnode, false },
                { "fluxnode",   "viewdeterministiczelnodelist", &viewdeterministiczelnodelist, false },

                { "fluxnode",   "createfluxnodekey",      &createfluxnodekey,      false  },
                { "fluxnode",   "getfluxnodeoutputs",     &getfluxnodeoutputs,     false  },
                { "fluxnode",   "startfluxnode",          &startfluxnode,          false  },
                { "fluxnode",   "listfluxnodes",          &listfluxnodes,          false  },
                { "fluxnode",   "getfluxnodecount",       &getfluxnodecount,       false  },
                { "fluxnode",   "fluxnodecurrentwinner",  &fluxnodecurrentwinner,  false  }, /* uses wallet if enabled */
                { "fluxnode",   "getfluxnodestatus",      &getfluxnodestatus,      false  },
                { "fluxnode",   "listfluxnodeconf",       &listfluxnodeconf,       false  },
                { "hidden",     "rebuildfluxnodedb",      &rebuildfluxnodedb,      false  },

                { "fluxnode",   "startdeterministicfluxnode", &startdeterministicfluxnode, false },
                { "fluxnode",   "viewdeterministicfluxnodelist", &viewdeterministicfluxnodelist, false },

                { "benchmarks", "getbenchmarks",         &getbenchmarks,           false  },
                { "benchmarks", "getbenchstatus",        &getbenchstatus,          false  },
                { "benchmarks", "stopzelbenchd",        &stopzelbenchd,          false  },
                { "benchmarks", "startzelbenchd",       &startzelbenchd,         false  },

                /** Not shown in help menu */
                { "hidden",     "createsporkkeys",        &createsporkkeys,         false  },
                { "hidden",     "createconfirmationtransaction",        &createconfirmationtransaction,         false  }




        };


void RegisterFluxnodeRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
