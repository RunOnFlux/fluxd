// Copyright (c) 2025 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EMERGENCYBLOCK_H
#define BITCOIN_EMERGENCYBLOCK_H

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "uint256.h"
#include "pubkey.h"
#include <vector>
#include <string>

class CCoinsViewCache;
class CValidationState;

/**
 * Check if a given collateral hash is the emergency collateral pattern
 */
bool IsEmergencyCollateral(const uint256& hash);

/**
 * Check if a block is an emergency block
 */
bool IsEmergencyBlock(const CBlockHeader& block);

/**
 * Validate emergency block signatures
 * Requires minimum number of signatures from authorized emergency keys
 */
bool ValidateEmergencyBlockSignatures(const CBlockHeader& block);

/**
 * Create an emergency block (for RPC use)
 * Requires private keys to sign
 */
bool CreateEmergencyBlock(CBlockHeader& block, const std::vector<CKey>& vKeys, std::string& errorMessage);

/**
 * Check if emergency block creation is allowed at current height
 * Can add additional restrictions like time delays
 */
bool IsEmergencyBlockAllowed(int nHeight, int64_t nTime);

/**
 * Helper functions to encode/decode multiple signatures
 */
std::vector<std::vector<unsigned char>> DecodeMultiSig(const std::vector<unsigned char>& vchBlockSig);
std::vector<unsigned char> EncodeMultiSig(const std::vector<std::vector<unsigned char>>& vSigs);

#endif // BITCOIN_EMERGENCYBLOCK_H