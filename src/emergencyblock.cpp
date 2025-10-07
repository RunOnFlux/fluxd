// Copyright (c) 2025 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "emergencyblock.h"
#include "chainparams.h"
#include "main.h"
#include "utilstrencodings.h"
#include "script/script.h"
#include "script/standard.h"
#include "script/sign.h"
#include "key_io.h"
#include "primitives/transaction.h"
#include "serialize.h"
#include "streams.h"
#include "pon/pon-fork.h"

bool IsEmergencyCollateral(const uint256& hash) {
    // Check if collateral hash matches the emergency pattern
    const uint256& emergencyHash = Params().GetEmergencyCollateralHash();
    return hash == emergencyHash;
}

bool IsEmergencyBlock(const CBlockHeader& block) {
    // Check if this is an emergency block by checking the collateral
    if (block.nVersion >= CBlockHeader::PON_VERSION) {
        return IsEmergencyCollateral(block.nodesCollateral.hash) && block.nodesCollateral.n == 0;
    }
    return false;
}

// Helper functions to encode/decode multiple signatures in vchBlockSig
std::vector<std::vector<unsigned char>> DecodeMultiSig(const std::vector<unsigned char>& vchBlockSig) {
    std::vector<std::vector<unsigned char>> vSigs;

    if (vchBlockSig.empty()) {
        return vSigs;
    }

    CDataStream ss(vchBlockSig, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ss >> vSigs;
    } catch (const std::exception& e) {
        LogPrintf("Failed to decode multisig: %s\n", e.what());
    }

    return vSigs;
}

std::vector<unsigned char> EncodeMultiSig(const std::vector<std::vector<unsigned char>>& vSigs) {
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << vSigs;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

bool ValidateEmergencyBlockSignatures(const CBlockHeader& block) {
    if (!IsEmergencyBlock(block)) {
        return false;
    }

    // NEW: Log emergency block usage for transparency
    int currentHeight = chainActive.Height() + 1;
    LogPrintf("=== EMERGENCY BLOCK DETECTED ===\n");
    LogPrintf("Height: %d\n", currentHeight);
    LogPrintf("Hash: %s\n", block.GetHash().ToString());
    LogPrintf("Timestamp: %d (%s)\n", block.nTime, DateTimeStrFormat("%Y-%m-%d %H:%M:%S", block.nTime));
    LogPrintf("Previous: %s\n", block.hashPrevBlock.ToString());
    LogPrintf("================================\n");

    const std::vector<std::string>& emergencyPubKeys = Params().GetEmergencyPublicKeys();
    const int nMinSigs = Params().GetEmergencyMinSignatures();

    // Decode multiple signatures from vchBlockSig
    std::vector<std::vector<unsigned char>> vSignatures = DecodeMultiSig(block.vchBlockSig);

    if (vSignatures.size() < (size_t)nMinSigs) {
        LogPrintf("Emergency block validation failed: insufficient signatures (%d < %d)\n",
                  vSignatures.size(), nMinSigs);
        return false;
    }

    // For regtest, allow any valid signatures for testing
    if (Params().NetworkIDString() == "regtest") {
        LogPrintf("Emergency block validation: Using regtest bypass, accepting %d signatures\n", vSignatures.size());
        return true;
    }

    // Use the block's GetHash() method which handles version-specific serialization
    uint256 hashBlock = block.GetHash();

    int validSigs = 0;
    std::set<std::string> usedPubKeys;

    // Verify each signature against the emergency public keys
    for (const auto& vchSig : vSignatures) {
        bool sigValid = false;

        for (const auto& strPubKey : emergencyPubKeys) {
            // Skip if this public key was already used
            if (usedPubKeys.count(strPubKey)) {
                continue;
            }

            // Parse the public key
            std::vector<unsigned char> vchPubKey = ParseHex(strPubKey);
            CPubKey pubKey(vchPubKey);

            if (!pubKey.IsValid()) {
                LogPrintf("Emergency block validation: invalid public key %s\n", strPubKey);
                continue;
            }

            // Verify the signature
            if (pubKey.Verify(hashBlock, vchSig)) {
                validSigs++;
                usedPubKeys.insert(strPubKey);
                sigValid = true;
                LogPrintf("Emergency block validation: valid signature from key %s\n", strPubKey);
                break;
            }
        }

        if (!sigValid) {
            LogPrintf("Emergency block validation: signature does not match any authorized key\n");
        }

        if (validSigs >= nMinSigs) {
            LogPrintf("Emergency block validation successful: %d/%d valid signatures\n",
                     validSigs, nMinSigs);
            return true;
        }
    }

    LogPrintf("Emergency block validation failed: only %d/%d valid signatures\n",
              validSigs, nMinSigs);
    return false;
}

bool CreateEmergencyBlock(CBlockHeader& block, const std::vector<CKey>& vKeys, std::string& errorMessage) {
    if (vKeys.size() < (size_t)Params().GetEmergencyMinSignatures()) {
        errorMessage = strprintf("Insufficient keys provided (%d < %d)",
                                vKeys.size(), Params().GetEmergencyMinSignatures());
        return false;
    }

    // Set emergency collateral
    block.nodesCollateral.hash = Params().GetEmergencyCollateralHash();
    block.nodesCollateral.n = 0; // Use index 0 for emergency blocks

    // Use the block's GetHash() method
    uint256 hashBlock = block.GetHash();

    // Sign with each provided key
    std::vector<std::vector<unsigned char>> vSignatures;
    for (const auto& key : vKeys) {
        std::vector<unsigned char> vchSig;
        if (!key.Sign(hashBlock, vchSig)) {
            errorMessage = "Failed to sign block with provided key";
            return false;
        }
        vSignatures.push_back(vchSig);
    }

    // Encode multiple signatures into vchBlockSig
    block.vchBlockSig = EncodeMultiSig(vSignatures);

    return true;
}

bool IsEmergencyBlockAllowed(int nHeight, int64_t nTime) {
    if (!IsPONActive(nHeight)) {
        LogPrintf("Emergency block not until PON is active: height too low (%d)\n", nHeight);
        return false;
    }

    LogPrintf("Emergency block allowed at height %d, time %d\n", nHeight, nTime);
    return true;
}