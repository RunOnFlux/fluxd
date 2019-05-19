// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2018-2019 The Zel developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zelnode/activezelnode.h"
#include "db.h"
#include "init.h"
#include "main.h"
#include "zelnode/payments.h"
#include "zelnode/zelnodeconfig.h"
#include "zelnode/zelnodeman.h"
#include "zelnode/spork.h"
#include "rpc/server.h"
#include "utilmoneystr.h"
#include "key_io.h"
#include "zelnode/benchmarks.h"
#include "util.h"

#include <univalue.h>

#include <boost/tokenizer.hpp>
#include <fstream>

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

UniValue createzelnodekey(const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "createzelnodekey\n"
                "\nCreate a new zelnode private key\n"

                "\nResult:\n"
                "\"key\"    (string) Zelnode private key\n"

                "\nExamples:\n" +
                HelpExampleCli("createzelnodekey", "") + HelpExampleRpc("createzelnodekey", ""));

    CKey secret;
    secret.MakeNewKey(false);
    return EncodeSecret(secret);
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
    vector<std::pair<COutput, CAmount>> possibleCoins = activeZelnode.SelectCoinsZelnode();

    UniValue ret(UniValue::VARR);
    for (auto& pair : possibleCoins) {
        COutput out = pair.first;
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("txhash", out.tx->GetHash().ToString()));
        obj.push_back(Pair("outputidx", out.i));
        obj.push_back(Pair("ZEL Amount", pair.second / COIN));
        ret.push_back(obj);
    }

    return ret;
}

UniValue startzelnode(const UniValue& params, bool fHelp)
{
    std::string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();

    if (fHelp || params.size() < 2 || params.size() > 3 ||
        (params.size() == 2 && (strCommand != "local" && strCommand != "all" && strCommand != "many" && strCommand != "missing" && strCommand != "disabled")) ||
        (params.size() == 3 && strCommand != "alias"))
        throw runtime_error(
                "startzelnode \"local|all|missing|disabled|alias\" lockwallet ( \"alias\" )\n"
                "\nAttempts to start one or more zelnode(s)\n"

                "\nArguments:\n"
                "1. set         (string, required) Specify which set of zelnode(s) to start.\n"
                "2. lockwallet  (boolean, required) Lock wallet after completion.\n"
                "3. alias       (string) Zelnode alias. Required if using 'alias' as the set.\n"

                "\nResult: (for 'local' set):\n"
                "\"status\"     (string) Zelnode status message\n"

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

    bool fLock = (params[1].get_str() == "true" ? true : false);

    EnsureWalletIsUnlocked();

    if (strCommand == "local") {
        if (!fZelnode) throw runtime_error("you must set zelnode=1 in the configuration\n");

        if (activeZelnode.status != ACTIVE_ZELNODE_STARTED) {
            activeZelnode.status = ACTIVE_ZELNODE_INITIAL; // TODO: consider better way
            activeZelnode.ManageStatus();
            if (fLock)
                pwalletMain->Lock();
        }

        return activeZelnode.GetStatus();
    }

    if (strCommand == "all" || strCommand == "missing" || strCommand == "disabled") {
        if ((strCommand == "missing" || strCommand == "disabled") &&
            (zelnodeSync.RequestedZelnodeAssets <= ZELNODE_SYNC_LIST ||
                zelnodeSync.RequestedZelnodeAssets == ZELNODE_SYNC_FAILED)) {
            throw runtime_error("You can't use this command until zelnode list is synced\n");
        }

        std::vector<ZelnodeConfig::ZelnodeEntry> znEntries;
        znEntries = zelnodeConfig.getEntries();

        int successful = 0;
        int failed = 0;

        UniValue resultsObj(UniValue::VARR);

        for (ZelnodeConfig::ZelnodeEntry zne : zelnodeConfig.getEntries()) {
            std::string errorMessage;
            int nIndex;
            if(!zne.castOutputIndex(nIndex))
                continue;
            CTxIn vin = CTxIn(uint256S(zne.getTxHash()), uint32_t(nIndex));
            Zelnode* pzn = zelnodeman.Find(vin);
            ZelnodeBroadcast znb;

            if (pzn != NULL) {
                if (strCommand == "missing") continue;
                if (strCommand == "disabled" && pzn->IsEnabled()) continue;
            }

            bool result = activeZelnode.CreateBroadcast(zne.getIp(), zne.getPrivKey(), zne.getTxHash(), zne.getOutputIndex(), errorMessage, znb);

            UniValue statusObj(UniValue::VOBJ);
            statusObj.push_back(Pair("alias", zne.getAlias()));
            statusObj.push_back(Pair("result", result ? "success" : "failed"));

            if (result) {
                successful++;
                zelnodeman.UpdateZelnodeList(znb);
                znb.Relay();
                statusObj.push_back(Pair("error", ""));
            } else {
                failed++;
                statusObj.push_back(Pair("error", errorMessage));
            }

            resultsObj.push_back(statusObj);
        }

        if (fLock)
            pwalletMain->Lock();

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d zelnodes, failed to start %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }

    if (strCommand == "alias") {
        std::string alias = params[2].get_str();

        bool found = false;
        int successful = 0;
        int failed = 0;

        UniValue resultsObj(UniValue::VARR);
        UniValue statusObj(UniValue::VOBJ);
        statusObj.push_back(Pair("alias", alias));

        for (ZelnodeConfig::ZelnodeEntry zne : zelnodeConfig.getEntries()) {
                        if (zne.getAlias() == alias) {
                            found = true;
                            std::string errorMessage;
                            ZelnodeBroadcast znb;

                            bool result = activeZelnode.CreateBroadcast(zne.getIp(), zne.getPrivKey(), zne.getTxHash(), zne.getOutputIndex(), errorMessage, znb);

                            statusObj.push_back(Pair("result", result ? "successful" : "failed"));

                            if (result) {
                                successful++;
                                zelnodeman.UpdateZelnodeList(znb);
                                znb.Relay();
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
            statusObj.push_back(Pair("error", "could not find alias in config. Verify with list-conf."));
        }

        resultsObj.push_back(statusObj);

        if (fLock)
            pwalletMain->Lock();

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully started %d zelnodes, failed to start %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }
    return NullUniValue;
}

UniValue znsync(const UniValue& params, bool fHelp)
{
    std::string strMode;
    if (params.size() == 1)
        strMode = params[0].get_str();

    if (fHelp || params.size() != 1 || (strMode != "status" && strMode != "reset")) {
        throw runtime_error(
                "znsync \"status|reset\"\n"
                "\nReturns the sync status or resets sync.\n"

                "\nArguments:\n"
                "1. \"mode\"    (string, required) either 'status' or 'reset'\n"

                "\nResult ('status' mode):\n"
                "{\n"
                "  \"IsBlockchainSynced\": true|false,    (boolean) 'true' if blockchain is synced\n"
                "  \"lastZelnodeList\": xxxx,        (numeric) Timestamp of last ZN list message\n"
                "  \"lastZelnodeWinner\": xxxx,      (numeric) Timestamp of last ZN winner message\n"
                "  \"lastFailure\": xxxx,           (numeric) Timestamp of last failed sync\n"
                "  \"nCountFailures\": n,           (numeric) Number of failed syncs (total)\n"
                "  \"sumZelnodeList\": n,        (numeric) Number of ZN list messages (total)\n"
                "  \"sumZelnodeWinner\": n,      (numeric) Number of ZN winner messages (total)\n"
                "  \"countZelnodeList\": n,      (numeric) Number of ZN list messages (local)\n"
                "  \"countZelnodeWinner\": n,    (numeric) Number of ZN winner messages (local)\n"
                "  \"RequestedZelnodeAssets\": n, (numeric) Status code of last sync phase\n"
                "  \"RequestedZelnodeAttempt\": n, (numeric) Status code of last sync attempt\n"
                "  \"Status\": xxxx,               (string) Status as a string \n"
                "}\n"

                "\nResult ('reset' mode):\n"
                "\"status\"     (string) 'success'\n"

                "\nExamples:\n" +
                HelpExampleCli("znsync", "\"status\"") + HelpExampleRpc("znsync", "\"status\""));
    }

    if (strMode == "status") {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("IsBlockchainSynced", zelnodeSync.IsBlockchainSynced()));
        obj.push_back(Pair("lastZelnodeList", zelnodeSync.lastZelnodeList));
        obj.push_back(Pair("lastZelnodeWinner", zelnodeSync.lastZelnodeWinner));
        obj.push_back(Pair("lastFailure", zelnodeSync.lastFailure));
        obj.push_back(Pair("nCountFailures", zelnodeSync.nCountFailures));
        obj.push_back(Pair("sumZelnodeList", zelnodeSync.sumZelnodeList));
        obj.push_back(Pair("sumZelnodeWinner", zelnodeSync.sumZelnodeWinner));
        obj.push_back(Pair("countZelnodeList", zelnodeSync.countZelnodeList));
        obj.push_back(Pair("countZelnodeWinner", zelnodeSync.countZelnodeWinner));
        obj.push_back(Pair("RequestedZelnodeAssets", zelnodeSync.RequestedZelnodeAssets));
        obj.push_back(Pair("RequestedZelnodeAttempt", zelnodeSync.RequestedZelnodeAttempt));
        obj.push_back(Pair("Status", zelnodeSync.GetSyncStatus()));

        return obj;
    }

    if (strMode == "reset") {
        zelnodeSync.Reset();
        zelnodeman.Clear();
        return "success";
    }
    return "failure";
}

UniValue listzelnodes(const UniValue& params, bool fHelp)
{
    std::string strFilter = "";

    if (params.size() == 1) strFilter = params[0].get_str();

    if (fHelp || (params.size() > 1))
        throw runtime_error(
                "listzelnodes ( \"filter\" )\n"
                "\nGet a ranked list of zelnodes\n"

                "\nArguments:\n"
                "1. \"filter\"    (string, optional) Filter search text. Partial match by txhash, status, or addr.\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"rank\": n,           (numeric) Zelnode Rank (or 0 if not enabled)\n"
                "    \"txhash\": \"hash\",  (string) Collateral transaction hash\n"
                "    \"outidx\": n,         (numeric) Collateral transaction output index\n"
                "    \"pubkey\": \"key\",   (string) Zelnode public key used for message broadcasting\n"
                "    \"status\": s,         (string) Status (ENABLED/EXPIRED/REMOVE/etc)\n"
                "    \"addr\": \"addr\",    (string) Zelnode ZEL address\n"
                "    \"version\": v,        (numeric) Zelnode protocol version\n"
                "    \"lastseen\": ttt,     (numeric) The time in seconds since epoch (Jan 1 1970 GMT) of the last seen\n"
                "    \"activetime\": ttt,   (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode has been active\n"
                "    \"lastpaid\": ttt,     (numeric) The time in seconds since epoch (Jan 1 1970 GMT) zelnode was last paid\n"
                "    \"tier\": \"type\",    (string) Tier (BASIC/SUPER/BAMF)\n"
                "    \"ip\": \"address\"    (string) IP address\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("listzelnodes", "") + HelpExampleRpc("listzelnodes", ""));

    UniValue ret(UniValue::VARR);
    int nHeight;
    {
        LOCK(cs_main);
        CBlockIndex* pindex = chainActive.Tip();
        if(!pindex) return 0;
        nHeight = pindex->nHeight;
    }

    std::vector<pair<int, Zelnode> > vBasicZelnodeRanks = zelnodeman.GetZelnodeRanks(Zelnode::BASIC, nHeight);
    for(PAIRTYPE(int, Zelnode) & s : vBasicZelnodeRanks) {
                    UniValue obj(UniValue::VOBJ);
                    std::string strVin = s.second.vin.prevout.ToString();
                    std::string strTxHash = s.second.vin.prevout.hash.ToString();
                    uint32_t oIdx = s.second.vin.prevout.n;

                    Zelnode* zn = zelnodeman.Find(s.second.vin);

                    if (zn != NULL) {
                        if (strFilter != "" && strTxHash.find(strFilter) == string::npos &&
                            zn->Status().find(strFilter) == string::npos &&
                            EncodeDestination(zn->pubKeyCollateralAddress.GetID()).find(strFilter) == string::npos) continue;

                        std::string strStatus = zn->Status();
                        std::string strTier = zn->Tier();
                        std::string strHost;
                        int port;
                        SplitHostPort(zn->addr.ToString(), port, strHost);
                        CNetAddr node = CNetAddr(strHost, false);
                        std::string strNetwork = GetNetworkName(node.GetNetwork());

                        obj.push_back(Pair("rank", (strStatus == "ENABLED" ? s.first : 0)));
                        obj.push_back(Pair("network", strNetwork));
                        obj.push_back(Pair("txhash", strTxHash));
                        obj.push_back(Pair("outidx", (uint64_t)oIdx));
                        obj.push_back(Pair("pubkey", HexStr(zn->pubKeyZelnode)));
                        obj.push_back(Pair("status", strStatus));
                        obj.push_back(Pair("addr", EncodeDestination(zn->pubKeyCollateralAddress.GetID())));
                        obj.push_back(Pair("version", zn->protocolVersion));
                        obj.push_back(Pair("lastseen", (int64_t)zn->lastPing.sigTime));
                        obj.push_back(Pair("activetime", (int64_t)(zn->lastPing.sigTime - zn->sigTime)));
                        obj.push_back(Pair("lastpaid", (int64_t)zn->GetLastPaid()));
                        obj.push_back(Pair("tier", strTier));
                        obj.push_back(Pair("ipaddress", zn->addr.ToStringIPPort()));

                        ret.push_back(obj);
                    }
                }

    std::vector<pair<int, Zelnode> > vSuperZelnodeRanks = zelnodeman.GetZelnodeRanks(Zelnode::SUPER, nHeight);
    for(PAIRTYPE(int, Zelnode) & s : vSuperZelnodeRanks) {
        UniValue obj(UniValue::VOBJ);
        std::string strVin = s.second.vin.prevout.ToString();
        std::string strTxHash = s.second.vin.prevout.hash.ToString();
        uint32_t oIdx = s.second.vin.prevout.n;

        Zelnode* zn = zelnodeman.Find(s.second.vin);

        if (zn != NULL) {
            if (strFilter != "" && strTxHash.find(strFilter) == string::npos &&
                zn->Status().find(strFilter) == string::npos &&
                    EncodeDestination(zn->pubKeyCollateralAddress.GetID()).find(strFilter) == string::npos) continue;

            std::string strStatus = zn->Status();
            std::string strTier = zn->Tier();
            std::string strHost;
            int port;
            SplitHostPort(zn->addr.ToString(), port, strHost);
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            obj.push_back(Pair("rank", (strStatus == "ENABLED" ? s.first : 0)));
            obj.push_back(Pair("network", strNetwork));
            obj.push_back(Pair("txhash", strTxHash));
            obj.push_back(Pair("outidx", (uint64_t)oIdx));
            obj.push_back(Pair("pubkey", HexStr(zn->pubKeyZelnode)));
            obj.push_back(Pair("status", strStatus));
            obj.push_back(Pair("addr", EncodeDestination(zn->pubKeyCollateralAddress.GetID())));
            obj.push_back(Pair("version", zn->protocolVersion));
            obj.push_back(Pair("lastseen", (int64_t)zn->lastPing.sigTime));
            obj.push_back(Pair("activetime", (int64_t)(zn->lastPing.sigTime - zn->sigTime)));
            obj.push_back(Pair("lastpaid", (int64_t)zn->GetLastPaid()));
            obj.push_back(Pair("tier", strTier));
            obj.push_back(Pair("ipaddress", zn->addr.ToStringIPPort()));

            ret.push_back(obj);
        }
    }

    std::vector<pair<int, Zelnode> > vBAMFZelnodeRanks = zelnodeman.GetZelnodeRanks(Zelnode::BAMF, nHeight);
    for(PAIRTYPE(int, Zelnode) & s : vBAMFZelnodeRanks) {
        UniValue obj(UniValue::VOBJ);
        std::string strVin = s.second.vin.prevout.ToString();
        std::string strTxHash = s.second.vin.prevout.hash.ToString();
        uint32_t oIdx = s.second.vin.prevout.n;

        Zelnode* zn = zelnodeman.Find(s.second.vin);

        if (zn != NULL) {
            if (strFilter != "" && strTxHash.find(strFilter) == string::npos &&
                zn->Status().find(strFilter) == string::npos &&
                EncodeDestination(zn->pubKeyCollateralAddress.GetID()).find(strFilter) == string::npos) continue;

            std::string strStatus = zn->Status();
            std::string strTier = zn->Tier();
            std::string strHost;
            int port;
            SplitHostPort(zn->addr.ToString(), port, strHost);
            CNetAddr node = CNetAddr(strHost, false);
            std::string strNetwork = GetNetworkName(node.GetNetwork());

            obj.push_back(Pair("rank", (strStatus == "ENABLED" ? s.first : 0)));
            obj.push_back(Pair("network", strNetwork));
            obj.push_back(Pair("txhash", strTxHash));
            obj.push_back(Pair("outidx", (uint64_t)oIdx));
            obj.push_back(Pair("pubkey", HexStr(zn->pubKeyZelnode)));
            obj.push_back(Pair("status", strStatus));
            obj.push_back(Pair("addr", EncodeDestination(zn->pubKeyCollateralAddress.GetID())));
            obj.push_back(Pair("version", zn->protocolVersion));
            obj.push_back(Pair("lastseen", (int64_t)zn->lastPing.sigTime));
            obj.push_back(Pair("activetime", (int64_t)(zn->lastPing.sigTime - zn->sigTime)));
            obj.push_back(Pair("lastpaid", (int64_t)zn->GetLastPaid()));
            obj.push_back(Pair("tier", strTier));
            obj.push_back(Pair("ipaddress", zn->addr.ToStringIPPort()));

            ret.push_back(obj);
        }
    }

    return ret;
}

UniValue getzelnodestatus (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "getzelnodestatus\n"
                "\nPrint zelnode status\n"

                "\nResult:\n"
                "{\n"
                "  \"txhash\": \"xxxx\",      (string) Collateral transaction hash\n"
                "  \"outputidx\": n,        (numeric) Collateral transaction output index number\n"
                "  \"netaddr\": \"xxxx\",     (string) Zelnode network address\n"
                "  \"addr\": \"xxxx\",        (string) ZEL address for zelnode payments\n"
                "  \"status\": \"xxxx\",      (string) Zelnode status\n"
                "  \"message\": \"xxxx\"      (string) Zelnode status message\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodestatus", "") + HelpExampleRpc("getzelnodestatus", ""));

    if (!fZelnode) throw runtime_error("This is not a zelnode");

    Zelnode* pmn = zelnodeman.Find(activeZelnode.vin);

    if (pmn) {
        UniValue mnObj(UniValue::VOBJ);
        mnObj.push_back(Pair("txhash", activeZelnode.vin.prevout.hash.ToString()));
        mnObj.push_back(Pair("outputidx", (uint64_t)activeZelnode.vin.prevout.n));
        mnObj.push_back(Pair("netaddr", activeZelnode.service.ToString()));
        mnObj.push_back(Pair("addr", EncodeDestination(pmn->pubKeyCollateralAddress.GetID())));
        mnObj.push_back(Pair("status", activeZelnode.status));
        mnObj.push_back(Pair("message", activeZelnode.GetStatus()));
        return mnObj;
    }
    throw runtime_error("Zelnode not found in the list of available zelnodes. Current status: "
                        + activeZelnode.GetStatus());
}

UniValue zelnodedebug (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() != 0))
        throw runtime_error(
                "zelnodedebug\n"
                "\nPrint zelnode status\n"

                "\nResult:\n"
                "\"status\"     (string) Zelnode status message\n"

                "\nExamples:\n" +
                HelpExampleCli("zelnodedebug", "") + HelpExampleRpc("zelnodedebug", ""));

    if (activeZelnode.status != ACTIVE_ZELNODE_INITIAL || !zelnodeSync.IsSynced())
        return activeZelnode.GetStatus();

    CTxIn vin = CTxIn();
    CPubKey pubkey;
    CKey key;
    if (!activeZelnode.GetZelNodeVin(vin, pubkey, key))
        throw runtime_error("Missing zelnode input, please look at the documentation for instructions on zelnode creation\n");
    else
        return activeZelnode.GetStatus();
}

/*
    Used for updating/reading spork settings on the network
*/
UniValue spork(const UniValue& params, bool fHelp)
{
    if (params.size() == 1 && params[0].get_str() == "show") {
        UniValue ret(UniValue::VOBJ);
        for (int nSporkID = SPORK_START; nSporkID <= SPORK_END; nSporkID++) {
            if (sporkManager.GetSporkNameByID(nSporkID) != "Unknown")
                ret.push_back(Pair(sporkManager.GetSporkNameByID(nSporkID), GetSporkValue(nSporkID)));
        }
        return ret;
    } else if (params.size() == 1 && params[0].get_str() == "active") {
        UniValue ret(UniValue::VOBJ);
        for (int nSporkID = SPORK_START; nSporkID <= SPORK_END; nSporkID++) {
            if (sporkManager.GetSporkNameByID(nSporkID) != "Unknown")
                ret.push_back(Pair(sporkManager.GetSporkNameByID(nSporkID), IsSporkActive(nSporkID)));
        }
        return ret;
    } else if (params.size() == 2) {
        int nSporkID = sporkManager.GetSporkIDByName(params[0].get_str());
        if (nSporkID == -1) {
            return "Invalid spork name";
        }

        // SPORK VALUE
        int64_t nValue = params[1].get_int64();

        //broadcast new spork
        if (sporkManager.UpdateSpork(nSporkID, nValue)) {
            return "success";
        } else {
            return "failure";
        }
    }

    throw runtime_error(
            "spork \"name\" ( value )\n"
            "\nReturn spork values or their active state.\n"

            "\nArguments:\n"
            "1. \"name\"        (string, required)  \"show\" to show values, \"active\" to show active state.\n"
            "                       When set up as a spork signer, the name of the spork can be used to update it's value.\n"
            "2. value           (numeric, required when updating a spork) The new value for the spork.\n"

            "\nResult (show):\n"
            "{\n"
            "  \"spork_name\": nnn      (key/value) Key is the spork name, value is it's current value.\n"
            "  ,...\n"
            "}\n"

            "\nResult (active):\n"
            "{\n"
            "  \"spork_name\": true|false      (key/value) Key is the spork name, value is a boolean for it's active state.\n"
            "  ,...\n"
            "}\n"

            "\nResult (name):\n"
            " \"success|failure\"       (string) Wither or not the update succeeded.\n"

            "\nExamples:\n" +
            HelpExampleCli("spork", "show") + HelpExampleRpc("spork", "show"));
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

    Zelnode basicWinner;
    Zelnode superWinner;
    Zelnode bamfWinner;

    UniValue ret(UniValue::VOBJ);
    if (zelnodeman.GetCurrentZelnode(basicWinner, Zelnode::BASIC, 1)) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("protocol", (int64_t)basicWinner.protocolVersion));
        obj.push_back(Pair("txhash", basicWinner.vin.prevout.hash.ToString()));
        obj.push_back(Pair("pubkey", EncodeDestination(basicWinner.pubKeyCollateralAddress.GetID())));
        obj.push_back(Pair("lastseen", (basicWinner.lastPing == ZelnodePing()) ? basicWinner.sigTime : (int64_t)basicWinner.lastPing.sigTime));
        obj.push_back(Pair("activeseconds", (basicWinner.lastPing == ZelnodePing()) ? 0 : (int64_t)(basicWinner.lastPing.sigTime - basicWinner.sigTime)));
        ret.push_back(Pair("Basic Winner", obj));
    }
    if (zelnodeman.GetCurrentZelnode(superWinner, Zelnode::SUPER, 1)) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("protocol", (int64_t)superWinner.protocolVersion));
        obj.push_back(Pair("txhash", superWinner.vin.prevout.hash.ToString()));
        obj.push_back(Pair("pubkey", EncodeDestination(superWinner.pubKeyCollateralAddress.GetID())));
        obj.push_back(Pair("lastseen", (superWinner.lastPing == ZelnodePing()) ? superWinner.sigTime : (int64_t)superWinner.lastPing.sigTime));
        obj.push_back(Pair("activeseconds", (superWinner.lastPing == ZelnodePing()) ? 0 : (int64_t)(superWinner.lastPing.sigTime - superWinner.sigTime)));
        ret.push_back(Pair("Super Winner", obj));
    }
    if (zelnodeman.GetCurrentZelnode(bamfWinner, Zelnode::BAMF, 1)) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("protocol", (int64_t)bamfWinner.protocolVersion));
        obj.push_back(Pair("txhash", bamfWinner.vin.prevout.hash.ToString()));
        obj.push_back(Pair("pubkey", EncodeDestination(bamfWinner.pubKeyCollateralAddress.GetID())));
        obj.push_back(Pair("lastseen", (bamfWinner.lastPing == ZelnodePing()) ? bamfWinner.sigTime : (int64_t)bamfWinner.lastPing.sigTime));
        obj.push_back(Pair("activeseconds", (bamfWinner.lastPing == ZelnodePing()) ? 0 : (int64_t)(bamfWinner.lastPing.sigTime - bamfWinner.sigTime)));
        ret.push_back(Pair("BAMF Winner", obj));
    }

    if (ret.size())
        return ret;

    throw runtime_error("unknown");
}

UniValue getzelnodecount (const UniValue& params, bool fHelp)
{
    if (fHelp || (params.size() > 0))
        throw runtime_error(
                "getzelnodecount\n"
                "\nGet zelnode count values\n"

                "\nResult:\n"
                "{\n"
                "  \"total\": n,        (numeric) Total zelnodes\n"
                "  \"stable\": n,       (numeric) Stable count\n"
                "  \"enabled\": n,      (numeric) Enabled zelnodes\n"
                "  \"inqueue\": n       (numeric) Zelnodes in queue\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodecount", "") + HelpExampleRpc("getzelnodecount", ""));

    UniValue obj(UniValue::VOBJ);
    int nBasicCount = 0;
    int nSuperCount = 0;
    int nBAMFCount = 0;
    int ipv4 = 0, ipv6 = 0, onion = 0;

    if (chainActive.Tip())
        zelnodeman.GetNextZelnodeInQueueForPayment(chainActive.Tip()->nHeight, true, nBasicCount, nSuperCount, nBAMFCount);

    int basicCount = zelnodeman.CountEnabled(-1, Zelnode::BASIC);
    int superCount = zelnodeman.CountEnabled(-1, Zelnode::SUPER);
    int bamfCount = zelnodeman.CountEnabled(-1, Zelnode::BAMF);

    zelnodeman.CountNetworks(MIN_PEER_PROTO_VERSION_ZELNODE, ipv4, ipv6, onion);

    obj.push_back(Pair("total", zelnodeman.size()));
    obj.push_back(Pair("stable", zelnodeman.stable_size()));
    obj.push_back(Pair("basic-enabled", basicCount));
    obj.push_back(Pair("super-enabled", superCount));
    obj.push_back(Pair("bamf-enabled", bamfCount));
    obj.push_back(Pair("basic-inqueue", nBasicCount));
    obj.push_back(Pair("super-inqueue", nSuperCount));
    obj.push_back(Pair("bamf-inqueue", nBAMFCount));
    obj.push_back(Pair("ipv4", ipv4));
    obj.push_back(Pair("ipv6", ipv6));
    obj.push_back(Pair("onion", onion));

    return obj;
}

UniValue getzelnodewinners (const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
                "getzelnodewinners ( blocks \"filter\" )\n"
                "\nPrint the zelnode winners for the last n blocks\n"

                "\nArguments:\n"
                "1. blocks      (numeric, optional) Number of previous blocks to show (default: 10)\n"
                "2. filter      (string, optional) Search filter matching ZN address\n"

                "\nResult (single winner):\n"
                "[\n"
                "  {\n"
                "    \"nHeight\": n,           (numeric) block height\n"
                "    \"winner\": {\n"
                "      \"address\": \"xxxx\",    (string) ZEL ZN Address\n"
                "      \"nVotes\": n,          (numeric) Number of votes for winner\n"
                "    }\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nResult (multiple winners):\n"
                "[\n"
                "  {\n"
                "    \"nHeight\": n,           (numeric) block height\n"
                "    \"winner\": [\n"
                "      {\n"
                "        \"address\": \"xxxx\",  (string) ZEL ZN Address\n"
                "        \"nVotes\": n,        (numeric) Number of votes for winner\n"
                "      }\n"
                "      ,...\n"
                "    ]\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodewinners", "") + HelpExampleRpc("getzelnodewinners", ""));

    int nHeight;
    {
        LOCK(cs_main);
        CBlockIndex* pindex = chainActive.Tip();
        if(!pindex) return 0;
        nHeight = pindex->nHeight;
    }

    int nLast = 10;
    std::string strFilter = "";

    if (params.size() >= 1)
        nLast = atoi(params[0].get_str());

    if (params.size() == 2)
        strFilter = params[1].get_str();

    UniValue ret(UniValue::VARR);

    for (int i = nHeight - nLast; i < nHeight + 20; i++) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("nHeight", i));

        std::string strPayment = GetRequiredPaymentsString(i);
        if (strFilter != "" && strPayment.find(strFilter) == std::string::npos) continue;

        if (strPayment.find(',') != std::string::npos) {
            UniValue winner(UniValue::VARR);
            boost::char_separator<char> sep(",");
            boost::tokenizer< boost::char_separator<char> > tokens(strPayment, sep);
            for (const string& t : tokens) {
                            UniValue addr(UniValue::VOBJ);
                            std::size_t barpos = t.find('|');
                            std::size_t pos = t.find(':');
                            std::string strTier = t.substr(0,barpos);
                            std::string strAddress = t.substr(barpos+1,pos - (barpos+1));
                            uint64_t nVotes = atoi(t.substr(pos+1));
                            addr.push_back(Pair("tier", strTier));
                            addr.push_back(Pair("address", strAddress));
                            addr.push_back(Pair("nVotes", nVotes));
                            winner.push_back(addr);
                        }
            obj.push_back(Pair("winner", winner));
        } else if (strPayment.find("Unknown") == std::string::npos) {
            UniValue winner(UniValue::VOBJ);
            std::size_t barpos = strPayment.find("|");
            std::size_t pos = strPayment.find(":");
            std::string strTier = strPayment.substr(0,barpos);
            std::string strAddress = strPayment.substr(barpos+1,pos - (barpos+1));
            uint64_t nVotes = atoi(strPayment.substr(pos+1));
            winner.push_back(Pair("tier", strTier));
            winner.push_back(Pair("address", strAddress));
            winner.push_back(Pair("nVotes", nVotes));
            obj.push_back(Pair("winner", winner));
        } else {
            UniValue winner(UniValue::VOBJ);
            winner.push_back(Pair("address", strPayment));
            winner.push_back(Pair("nVotes", 0));
            obj.push_back(Pair("winner", winner));
        }

        ret.push_back(obj);
    }

    return ret;
}

UniValue getzelnodescores (const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
                "getzelnodescores ( blocks )\n"
                "\nPrint list of winning zelnodes by score\n"

                "\nArguments:\n"
                "1. blocks      (numeric, optional) Show the last n blocks (default 10)\n"

                "\nResult:\n"
                "{\n"
                "  xxxx: \"xxxx\"   (numeric : string) Block height : Zelnode hash\n"
                "  ,...\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getzelnodescores", "") + HelpExampleRpc("getzelnodescores", ""));

    int nLast = 10;

    if (params.size() == 1) {
        try {
            nLast = std::stoi(params[0].get_str());
        } catch (const std::invalid_argument&) {
            throw runtime_error("Exception on param 2");
        }
    }
    UniValue obj(UniValue::VOBJ);

    std::vector<Zelnode> vBasicZelnodes = zelnodeman.GetFullZelnodeVector(Zelnode::BASIC);
    std::vector<Zelnode> vSuperZelnodes = zelnodeman.GetFullZelnodeVector(Zelnode::SUPER);
    std::vector<Zelnode> vBAMFZelnodes = zelnodeman.GetFullZelnodeVector(Zelnode::BAMF);
    for (int nHeight = chainActive.Tip()->nHeight - nLast; nHeight < chainActive.Tip()->nHeight + 20; nHeight++) {
        uint256 nHigh = uint256();
        Zelnode* pBestBasicZelnode = NULL;
        Zelnode* pBestSuperZelnode = NULL;
        Zelnode* pBestBAMFZelnode = NULL;
        for (Zelnode& zn : vBasicZelnodes) {
                        uint256 n = zn.CalculateScore(1, nHeight - 100);
                        if (n > nHigh) {
                            nHigh = n;
                            pBestBasicZelnode = &zn;
                        }
                    }
        nHigh = uint256();
        for (Zelnode& zn : vSuperZelnodes) {
            uint256 n = zn.CalculateScore(1, nHeight - 100);
            if (n > nHigh) {
                nHigh = n;
                pBestSuperZelnode = &zn;
            }
        }
        nHigh = uint256();
        for (Zelnode& zn : vBAMFZelnodes) {
            uint256 n = zn.CalculateScore(1, nHeight - 100);
            if (n > nHigh) {
                nHigh = n;
                pBestBAMFZelnode = &zn;
            }
        }
        if (pBestBasicZelnode)
            obj.push_back(Pair(strprintf("Basic: %d", nHeight), pBestBasicZelnode->vin.prevout.hash.ToString().c_str()));
        if (pBestSuperZelnode)
            obj.push_back(Pair(strprintf("Super: %d", nHeight), pBestSuperZelnode->vin.prevout.hash.ToString().c_str()));
        if (pBestBAMFZelnode)
            obj.push_back(Pair(strprintf("BAMF: %d", nHeight), pBestBAMFZelnode->vin.prevout.hash.ToString().c_str()));
    }

    return obj;
}

UniValue listzelnodeconf (const UniValue& params, bool fHelp)
{
    std::string strFilter = "";

    if (params.size() == 1) strFilter = params[0].get_str();

    if (fHelp || (params.size() > 1))
        throw runtime_error(
                "listzelnodeconf ( \"filter\" )\n"
                "\nPrint zelnode.conf in JSON format\n"

                "\nArguments:\n"
                "1. \"filter\"    (string, optional) Filter search text. Partial match on alias, address, txHash, or status.\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"alias\": \"xxxx\",        (string) zelnode alias\n"
                "    \"address\": \"xxxx\",      (string) zelnode IP address\n"
                "    \"privateKey\": \"xxxx\",   (string) zelnode private key\n"
                "    \"txHash\": \"xxxx\",       (string) transaction hash\n"
                "    \"outputIndex\": n,       (numeric) transaction output index\n"
                "    \"status\": \"xxxx\"        (string) zelnode status\n"
                "  }\n"
                "  ,...\n"
                "]\n"

                "\nExamples:\n" +
                HelpExampleCli("listzelnodeconf", "") + HelpExampleRpc("listzelnodeconf", ""));

    std::vector<ZelnodeConfig::ZelnodeEntry> zelnodeEntries;
    zelnodeEntries = zelnodeConfig.getEntries();

    UniValue ret(UniValue::VARR);

    for (ZelnodeConfig::ZelnodeEntry zelnode : zelnodeEntries) {
        int nIndex;
        if(!zelnode.castOutputIndex(nIndex))
            continue;
        CTxIn vin = CTxIn(uint256S(zelnode.getTxHash()), uint32_t(nIndex));
        Zelnode* pzelnode = zelnodeman.Find(vin);

        std::string strStatus = pzelnode ? pzelnode->Status() : "MISSING";

        if (strFilter != "" && zelnode.getAlias().find(strFilter) == string::npos &&
            zelnode.getIp().find(strFilter) == string::npos &&
            zelnode.getTxHash().find(strFilter) == string::npos &&
            strStatus.find(strFilter) == string::npos) continue;

        UniValue object(UniValue::VOBJ);
        object.push_back(Pair("alias", zelnode.getAlias()));
        object.push_back(Pair("address", zelnode.getIp()));
        object.push_back(Pair("privateKey", zelnode.getPrivKey()));
        object.push_back(Pair("txHash", zelnode.getTxHash()));
        object.push_back(Pair("outputIndex", zelnode.getOutputIndex()));
        object.push_back(Pair("status", strStatus));
        ret.push_back(object);
    }

    return ret;
}

UniValue createzelnodebroadcast(const UniValue& params, bool fHelp)
{
    string strCommand;
    if (params.size() >= 1)
        strCommand = params[0].get_str();
    if (fHelp || (strCommand != "alias" && strCommand != "all") || (strCommand == "alias" && params.size() < 2))
        throw runtime_error(
                "createzelnodebroadcast \"command\" ( \"alias\")\n"
                "\nCreates a zelnode broadcast message for one or all zelnodes configured in zelnode.conf\n" +
                HelpRequiringPassphrase() + "\n"

                                            "\nArguments:\n"
                                            "1. \"command\"      (string, required) \"alias\" for single zelnode, \"all\" for all zelnodes\n"
                                            "2. \"alias\"        (string, required if command is \"alias\") Alias of the zelnode\n"

                                            "\nResult (all):\n"
                                            "{\n"
                                            "  \"overall\": \"xxx\",        (string) Overall status message indicating number of successes.\n"
                                            "  \"detail\": [                (array) JSON array of broadcast objects.\n"
                                            "    {\n"
                                            "      \"alias\": \"xxx\",      (string) Alias of the zelnode.\n"
                                            "      \"success\": true|false, (boolean) Success status.\n"
                                            "      \"hex\": \"xxx\"         (string, if success=true) Hex encoded broadcast message.\n"
                                            "      \"error_message\": \"xxx\"   (string, if success=false) Error message, if any.\n"
                                            "    }\n"
                                            "    ,...\n"
                                            "  ]\n"
                                            "}\n"

                                            "\nResult (alias):\n"
                                            "{\n"
                                            "  \"alias\": \"xxx\",      (string) Alias of the zelnode.\n"
                                            "  \"success\": true|false, (boolean) Success status.\n"
                                            "  \"hex\": \"xxx\"         (string, if success=true) Hex encoded broadcast message.\n"
                                            "  \"error_message\": \"xxx\"   (string, if success=false) Error message, if any.\n"
                                            "}\n"

                                            "\nExamples:\n" +
                HelpExampleCli("createzelnodebroadcast", "alias myzn1") + HelpExampleRpc("createzelnodebroadcast", "alias myzn1"));

    EnsureWalletIsUnlocked();

    if (strCommand == "alias")
    {
        // wait for reindex and/or import to finish
        if (fImporting || fReindex)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wait for reindex and/or import to finish");

        std::string alias = params[1].get_str();
        bool found = false;

        std::vector<ZelnodeConfig::ZelnodeEntry> zelnodeEntries;
        zelnodeEntries = zelnodeConfig.getEntries();

        UniValue statusObj(UniValue::VOBJ);
        statusObj.push_back(Pair("alias", alias));

        for (ZelnodeConfig::ZelnodeEntry zelnodeEntry : zelnodeEntries) {
            if(zelnodeEntry.getAlias() == alias) {
                found = true;
                std::string errorMessage;
                ZelnodeBroadcast zelnodeBroadcast;

                bool success = activeZelnode.CreateBroadcast(zelnodeEntry.getIp(), zelnodeEntry.getPrivKey(), zelnodeEntry.getTxHash(), zelnodeEntry.getOutputIndex(), errorMessage, zelnodeBroadcast, true);

                statusObj.push_back(Pair("success", success));
                if(success) {
                    CDataStream ssZelnode(SER_NETWORK, PROTOCOL_VERSION);
                    ssZelnode << zelnodeBroadcast;
                    statusObj.push_back(Pair("hex", HexStr(ssZelnode.begin(), ssZelnode.end())));
                } else {
                    statusObj.push_back(Pair("error_message", errorMessage));
                }
                break;
            }
        }

        if(!found) {
            statusObj.push_back(Pair("success", false));
            statusObj.push_back(Pair("error_message", "Could not find alias in config. Verify with listzelnodeconf."));
        }

        return statusObj;

    }

    if (strCommand == "all")
    {
        // wait for reindex and/or import to finish
        if (fImporting || fReindex)
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Wait for reindex and/or import to finish");

        std::vector<ZelnodeConfig::ZelnodeEntry> zelnodeEntries;
        zelnodeEntries = zelnodeConfig.getEntries();

        int successful = 0;
        int failed = 0;

        UniValue resultsObj(UniValue::VARR);

        for (ZelnodeConfig::ZelnodeEntry zelnodeEntry : zelnodeEntries) {
            std::string errorMessage;

            CTxIn vin = CTxIn(uint256S(zelnodeEntry.getTxHash()), uint32_t(atoi(zelnodeEntry.getOutputIndex().c_str())));
            ZelnodeBroadcast zelnodeBroadcast;

            bool success = activeZelnode.CreateBroadcast(zelnodeEntry.getIp(), zelnodeEntry.getPrivKey(), zelnodeEntry.getTxHash(), zelnodeEntry.getOutputIndex(), errorMessage, zelnodeBroadcast, true);

            UniValue statusObj(UniValue::VOBJ);
            statusObj.push_back(Pair("alias", zelnodeEntry.getAlias()));
            statusObj.push_back(Pair("success", success));

            if(success) {
                successful++;
                CDataStream ssZelnodeBroadcast(SER_NETWORK, PROTOCOL_VERSION);
                ssZelnodeBroadcast << zelnodeBroadcast;
                statusObj.push_back(Pair("hex", HexStr(ssZelnodeBroadcast.begin(), ssZelnodeBroadcast.end())));
            } else {
                failed++;
                statusObj.push_back(Pair("error_message", errorMessage));
            }

            resultsObj.push_back(statusObj);
        }

        UniValue returnObj(UniValue::VOBJ);
        returnObj.push_back(Pair("overall", strprintf("Successfully created broadcast messages for %d zelnodes, failed to create %d, total %d", successful, failed, successful + failed)));
        returnObj.push_back(Pair("detail", resultsObj));

        return returnObj;
    }
    return NullUniValue;
}


UniValue decodezelnodebroadcast(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "decodezelnodebroadcast \"hexstring\"\n"
                "\nCommand to decode zelnode broadcast messages\n"

                "\nArgument:\n"
                "1. \"hexstring\"        (string) The hex encoded zelnode broadcast message\n"

                "\nResult:\n"
                "{\n"
                "  \"vin\": \"xxxx\"                (string) The unspent output which is holding the zelnode collateral\n"
                "  \"addr\": \"xxxx\"               (string) IP address of the zelnode\n"
                "  \"pubkeycollateral\": \"xxxx\"   (string) Collateral address's public key\n"
                "  \"pubkeyzelnode\": \"xxxx\"   (string) Zelnode's public key\n"
                "  \"vchsig\": \"xxxx\"             (string) Base64-encoded signature of this message (verifiable via pubkeycollateral)\n"
                "  \"sigtime\": \"nnn\"             (numeric) Signature timestamp\n"
                "  \"protocolversion\": \"nnn\"     (numeric) Zelnodes's protocol version\n"
                "  \"lastping\" : {                 (object) JSON object with information about the zelnode's last ping\n"
                "      \"vin\": \"xxxx\"            (string) The unspent output of the zelnode which is signing the message\n"
                "      \"blockhash\": \"xxxx\"      (string) Current chaintip blockhash minus 12\n"
                "      \"sigtime\": \"nnn\"         (numeric) Signature time for this ping\n"
                "      \"vchsig\": \"xxxx\"         (string) Base64-encoded signature of this ping (verifiable via pubkeyzelnode)\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("decodezelnodebroadcast", "hexstring") + HelpExampleRpc("decodezelnodebroadcast", "hexstring"));

    ZelnodeBroadcast zelnodeBroadcast;

    if (!DecodeHexZelnodeBroadcast(zelnodeBroadcast, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Zelnode broadcast message decode failed");

    if(!zelnodeBroadcast.VerifySignature())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Zelnode broadcast signature verification failed");

    UniValue resultObj(UniValue::VOBJ);

    resultObj.push_back(Pair("vin", zelnodeBroadcast.vin.prevout.ToString()));
    resultObj.push_back(Pair("addr", zelnodeBroadcast.addr.ToString()));
    resultObj.push_back(Pair("pubkeycollateral", EncodeDestination(zelnodeBroadcast.pubKeyCollateralAddress.GetID())));
    resultObj.push_back(Pair("pubkeyzelnode", EncodeDestination(zelnodeBroadcast.pubKeyZelnode.GetID())));
    resultObj.push_back(Pair("vchsig", EncodeBase64(&zelnodeBroadcast.sig[0], zelnodeBroadcast.sig.size())));
    resultObj.push_back(Pair("sigtime", zelnodeBroadcast.sigTime));
    resultObj.push_back(Pair("protocolversion", zelnodeBroadcast.protocolVersion));
    resultObj.push_back(Pair("nlastdsq", zelnodeBroadcast.nLastDsq));

    UniValue lastPingObj(UniValue::VOBJ);
    lastPingObj.push_back(Pair("vin", zelnodeBroadcast.lastPing.vin.prevout.ToString()));
    lastPingObj.push_back(Pair("blockhash", zelnodeBroadcast.lastPing.blockHash.ToString()));
    lastPingObj.push_back(Pair("sigtime", zelnodeBroadcast.lastPing.sigTime));
    lastPingObj.push_back(Pair("vchsig", EncodeBase64(&zelnodeBroadcast.lastPing.vchSig[0], zelnodeBroadcast.lastPing.vchSig.size())));

    resultObj.push_back(Pair("lastping", lastPingObj));

    return resultObj;
}

UniValue relayzelnodebroadcast(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "relayzelnodebroadcast \"hexstring\"\n"
                "\nCommand to relay zelnode broadcast messages\n"

                "\nArguments:\n"
                "1. \"hexstring\"        (string) The hex encoded zelnode broadcast message\n"

                "\nExamples:\n" +
                HelpExampleCli("relayzelnodebroadcast", "hexstring") + HelpExampleRpc("relayzelnodebroadcast", "hexstring"));


    ZelnodeBroadcast zelnodeBroadcast;

    if (!DecodeHexZelnodeBroadcast(zelnodeBroadcast, params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Zelnode broadcast message decode failed");

    if(!zelnodeBroadcast.VerifySignature())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Zelnode broadcast signature verification failed");

    zelnodeman.UpdateZelnodeList(zelnodeBroadcast);
    zelnodeBroadcast.Relay();

    return strprintf("Zelnode broadcast sent (service %s, vin %s)", zelnodeBroadcast.addr.ToString(), zelnodeBroadcast.vin.ToString());
}

UniValue getnodebenchmarks(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
                "getnodebenchmarks\n"
                "\nCommand to test node benchmarks\n"

                "\nExamples:\n" +
                HelpExampleCli("getnodebenchmarks", "") + HelpExampleRpc("getnodebenchmarks", ""));

    if (!fZelnode)
        return "Command must be run on a zelnode";

    if (fBenchmarkFailed)
        return "Benchmarking Failed, please restart your node to try again";

    if (!fBenchmarkComplete)
        return "Benchmarking isn't completed, please try again in a minute";

    return benchmarks.NenchResultToString() + "Event Per Second : " + std::to_string(benchmarks.nEventsPerSecond) + "\n";
}



static const CRPCCommand commands[] =
        { //  category              name                      actor (function)         okSafeMode
                //  --------------------- ------------------------  -----------------------  ----------
                { "zelnode",    "createzelnodekey",       &createzelnodekey,       false  },
                { "zelnode",    "getzelnodeoutputs",      &getzelnodeoutputs,      false  },
                { "zelnode",    "znsync",                 &znsync,                 false  },
                { "zelnode",    "startzelnode",           &startzelnode,           false  },
                { "zelnode",    "listzelnodes",           &listzelnodes,           false  },
                { "zelnode",    "zelnodedebug",           &zelnodedebug,           false  },
                { "zelnode",    "spork",                  &spork,                  false  },
                { "zelnode",    "getzelnodecount",        &getzelnodecount,        false  },
                { "zelnode",    "zelnodecurrentwinner",   &zelnodecurrentwinner,   false  }, /* uses wallet if enabled */
                { "zelnode",    "getzelnodestatus",       &getzelnodestatus,       false  },
                { "zelnode",    "getzelnodewinners",      &getzelnodewinners,      false  },
                { "zelnode",    "getzelnodescores",       &getzelnodescores,       false  },
                { "zelnode",    "listzelnodeconf",        &listzelnodeconf,        false  },
                { "zelnode",    "createzelnodebroadcast", &createzelnodebroadcast, false  },
                { "zelnode",    "relayzelnodebroadcast",  &relayzelnodebroadcast,  false  },
                { "zelnode",    "decodezelnodebroadcast", &decodezelnodebroadcast, false  },
                { "zelnode",    "getnodebenchmarks",      &getnodebenchmarks,      false  },

                /** Not shown in help menu */
                { "hidden",    "createsporkkeys",        &createsporkkeys,         false  }


        };


void RegisterZelnodeRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
