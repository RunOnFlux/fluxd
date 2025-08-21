// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PON_H
#define BITCOIN_PON_H

#include "consensus/params.h"
#include "primitives/transaction.h"
#include "uint256.h"
#include "arith_uint256.h"

#include <stdint.h>

class CBlockIndex;
class CBlockHeader;
class CBlock;

// Check is hash meetings target
bool CheckProofOfNode(const uint256& hash, unsigned int nBits, const Consensus::Params& params);

// Calculate the pon hash
uint256 GetPONHash(const CBlockHeader& blockHeader);
uint256 GetPONHash(const COutPoint& collateral, const uint256& prevBlockHash, uint32_t slot);

// Calculate the slot number for a given timestamp relative to genesis
uint32_t GetSlotNumber(int64_t timestamp, int64_t genesisTimestamp, const Consensus::Params& params);

// Get the timestamp for a given slot number
int64_t GetSlotTimestamp(uint32_t slot, int64_t genesisTimestamp, const Consensus::Params& params);

// Get next PON work required (difficulty adjustment)
unsigned int GetNextPONWorkRequired(const CBlockIndex* pindexLast);

// Validate PON block header (using only header data - for headers-first sync)
// This validates:
// 1. Block version indicates PON
// 2. Timestamp aligns with slot
// 3. Stake hash meets difficulty target
bool CheckPONBlockHeader(const CBlockHeader* pblock, const CBlockIndex* pindexPrev,
                            const Consensus::Params& params);

// Full PON block header validation (requires chain state - for blocks near tip)
// This additionally validates:
// 1. Signature matches collateral owner
// 2. Fluxnode is active in the network
bool ContextualCheckPONBlockHeader(const CBlockHeader* pblock, const CBlockIndex* pindexPrev,
                     const Consensus::Params& params);


#endif // BITCOIN_PON_H