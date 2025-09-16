// Copyright (c) 2025 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "emergencyblock.h"
#include "init.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "primitives/block.h"
#include "rpc/server.h"
#include "streams.h"
#include "sync.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "key_io.h"
#include "utiltime.h"
#include "timedata.h"

#include <stdint.h>
#include <boost/assign/list_of.hpp>
#include <univalue.h>

using namespace std;

UniValue createemergencyblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "createemergencyblock\n"
            "\nCreates a new emergency block template. This is similar to getblocktemplate but\n"
            "specifically for emergency blocks with special collateral.\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\": \"xxxx\",               (string) hex-encoded block data\n"
            "  \"hash\": \"xxxx\",              (string) block hash\n"
            "  \"height\": n,                   (numeric) block height\n"
            "  \"collateral\": \"xxxx\",        (string) emergency collateral hash\n"
            "  \"signatures_required\": n,      (numeric) number of signatures required\n"
            "  \"authorized_keys\": [           (array) list of authorized public keys\n"
            "    \"pubkey\",                    (string) authorized public key\n"
            "    ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("createemergencyblock", "")
            + HelpExampleRpc("createemergencyblock", "")
        );

    LOCK(cs_main);

    // Check if emergency block is allowed at current height/time
    int nHeight = chainActive.Height() + 1;
    int64_t nTime = GetTime();

    if (!IsEmergencyBlockAllowed(nHeight, nTime)) {
        throw JSONRPCError(RPC_MISC_ERROR, "Emergency block not allowed at current height/time");
    }

    // Try to get the dev fund address
    CTxDestination dest = DecodeDestination(Params().GetDevFundAddress());
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create block template: Invalid dev payout address");
    }

    CScript devPayoutScript = GetScriptForDestination(dest);
    int64_t now = GetAdjustedTime();

    COutPoint emerygencyCollateral;
    emerygencyCollateral.hash = Params().GetEmergencyCollateralHash();
    emerygencyCollateral.n = 0;

    // Create a new block
    unique_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(Params(), devPayoutScript, true, emerygencyCollateral, now));
    if (!pblocktemplate.get()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create block template");
    }

    CBlock* pblock = &pblocktemplate->block;

    // Set emergency block parameters
    pblock->nVersion = CBlockHeader::PON_VERSION;

    // Clear any existing signature
    pblock->vchBlockSig.clear();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexBlock(*pblock)));
    result.push_back(Pair("hash", pblock->GetHash().GetHex()));
    result.push_back(Pair("height", nHeight));
    result.push_back(Pair("collateral", Params().GetEmergencyCollateralHash().GetHex()));
    result.push_back(Pair("signatures_required", Params().GetEmergencyMinSignatures()));

    UniValue keys(UniValue::VARR);
    for (const auto& key : Params().GetEmergencyPublicKeys()) {
        keys.push_back(key);
    }
    result.push_back(Pair("authorized_keys", keys));

    return result;
}

UniValue signemergencyblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signemergencyblock \"blockhex\" \"privatekey\"\n"
            "\nAdds a signature to an emergency block. Can be called multiple times with different keys.\n"
            "\nArguments:\n"
            "1. \"blockhex\"      (string, required) The hex-encoded block data\n"
            "2. \"privatekey\"    (string, required) The private key to sign with (WIF format)\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\": \"xxxx\",               (string) hex-encoded block with new signature\n"
            "  \"hash\": \"xxxx\",              (string) block hash\n"
            "  \"signatures\": n,               (numeric) total number of signatures\n"
            "  \"complete\": true|false,        (boolean) whether block has enough signatures\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("signemergencyblock", "\"blockhex\" \"privatekey\"")
            + HelpExampleRpc("signemergencyblock", "\"blockhex\", \"privatekey\"")
        );

    // Decode the block
    CBlock block;
    if (!DecodeHexBlk(block, params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    // Verify this is an emergency block
    if (!IsEmergencyBlock(block)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not an emergency block");
    }

    // Decode the private key
    CKey key = DecodeSecret(params[1].get_str());
    if (!key.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid private key");
    }

    // Get the public key
    CPubKey pubKey = key.GetPubKey();
    std::string strPubKey = HexStr(pubKey.begin(), pubKey.end());

    // Check if this public key is authorized
    const std::vector<std::string>& authorizedKeys = Params().GetEmergencyPublicKeys();
    bool isAuthorized = false;
    for (const auto& authKey : authorizedKeys) {
        if (authKey == strPubKey) {
            isAuthorized = true;
            break;
        }
    }

    if (!isAuthorized) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Private key does not correspond to an authorized emergency key");
    }

    // Get existing signatures
    std::vector<std::vector<unsigned char>> signatures = DecodeMultiSig(block.vchBlockSig);

    // Check if this key has already signed
    uint256 blockHash = block.GetHash();
    for (const auto& existingSig : signatures) {
        if (pubKey.Verify(blockHash, existingSig)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "This key has already signed the block");
        }
    }

    // Sign the block
    std::vector<unsigned char> vchSig;
    if (!key.Sign(blockHash, vchSig)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign block");
    }

    // Add the new signature
    signatures.push_back(vchSig);

    // Encode signatures back into block
    block.vchBlockSig = EncodeMultiSig(signatures);

    // Check if block is complete
    bool isComplete = signatures.size() >= (size_t)Params().GetEmergencyMinSignatures();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeHexBlock(block)));
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    result.push_back(Pair("signatures", (int)signatures.size()));
    result.push_back(Pair("complete", isComplete));

    return result;
}

UniValue submitemergencyblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "submitemergencyblock \"blockhex\"\n"
            "\nAttempts to submit an emergency block to the network.\n"
            "\nArguments:\n"
            "1. \"blockhex\"      (string, required) The hex-encoded block data\n"
            "\nResult:\n"
            "\"hash\"             (string) The block hash if successful\n"
            "\nExamples:\n"
            + HelpExampleCli("submitemergencyblock", "\"blockhex\"")
            + HelpExampleRpc("submitemergencyblock", "\"blockhex\"")
        );

    // Decode the block
    CBlock block;
    if (!DecodeHexBlk(block, params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    // Verify this is an emergency block
    if (!IsEmergencyBlock(block)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not an emergency block");
    }

    // Validate signatures
    if (!ValidateEmergencyBlockSignatures(block)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Emergency block has invalid or insufficient signatures");
    }

    // Check if emergency block is allowed
    int nHeight = chainActive.Height() + 1;
    int64_t nTime = block.nTime;
    if (!IsEmergencyBlockAllowed(nHeight, nTime)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Emergency block not allowed at current height/time");
    }

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end()) {
            CBlockIndex* pindex = mi->second;
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
                return hash.GetHex(); // Block already accepted
            }
            if (pindex->nStatus & BLOCK_FAILED_MASK) {
                throw JSONRPCError(RPC_VERIFY_ERROR, "Block has been previously rejected");
            }
            fBlockPresent = true;
        }
    }

    // Process the block
    CValidationState state;
    bool fAccepted = ProcessNewBlock(state, Params(), NULL, &block, true, NULL);

    if (fBlockPresent) {
        if (fAccepted && !state.IsError()) {
            return hash.GetHex();
        }
        throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("%s", state.GetRejectReason()));
    }

    if (!fAccepted) {
        throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("%s", state.GetRejectReason()));
    }

    return hash.GetHex();
}

UniValue verifyemergencyblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "verifyemergencyblock \"blockhex\"\n"
            "\nVerifies the signatures on an emergency block.\n"
            "\nArguments:\n"
            "1. \"blockhex\"      (string, required) The hex-encoded block data\n"
            "\nResult:\n"
            "{\n"
            "  \"valid\": true|false,          (boolean) whether signatures are valid\n"
            "  \"signatures\": n,               (numeric) number of signatures\n"
            "  \"signatures_required\": n,      (numeric) number of signatures required\n"
            "  \"signers\": [                  (array) list of public keys that signed\n"
            "    \"pubkey\",                   (string) public key\n"
            "    ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("verifyemergencyblock", "\"blockhex\"")
            + HelpExampleRpc("verifyemergencyblock", "\"blockhex\"")
        );

    // Decode the block
    CBlock block;
    if (!DecodeHexBlk(block, params[0].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");
    }

    // Verify this is an emergency block
    if (!IsEmergencyBlock(block)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is not an emergency block");
    }

    // Decode signatures
    std::vector<std::vector<unsigned char>> signatures = DecodeMultiSig(block.vchBlockSig);

    // Verify signatures and identify signers
    uint256 blockHash = block.GetHash();
    UniValue signers(UniValue::VARR);
    const std::vector<std::string>& authorizedKeys = Params().GetEmergencyPublicKeys();

    for (const auto& sig : signatures) {
        for (const auto& strPubKey : authorizedKeys) {
            std::vector<unsigned char> vchPubKey = ParseHex(strPubKey);
            CPubKey pubKey(vchPubKey);

            if (pubKey.IsValid() && pubKey.Verify(blockHash, sig)) {
                signers.push_back(strPubKey);
                break;
            }
        }
    }

    bool isValid = ValidateEmergencyBlockSignatures(block);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("valid", isValid));
    result.push_back(Pair("signatures", (int)signatures.size()));
    result.push_back(Pair("signatures_required", Params().GetEmergencyMinSignatures()));
    result.push_back(Pair("signers", signers));

    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                        actor (function)           okSafeMode
  //  --------------------- ------------------------    -----------------------    ----------
    { "emergencyblock",     "createemergencyblock",     &createemergencyblock,     true  },
    { "emergencyblock",     "signemergencyblock",       &signemergencyblock,       true  },
    { "emergencyblock",     "submitemergencyblock",     &submitemergencyblock,     true  },
    { "emergencyblock",     "verifyemergencyblock",     &verifyemergencyblock,     true  },
};

void RegisterEmergencyBlockRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}