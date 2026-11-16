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
bool CheckProofOfNode(const uint256& hash, unsigned int nBits, const Consensus::Params& params, int nHeightToCheckWith = 0);

// Calculate the pon hash
uint256 GetPONHash(const CBlockHeader& blockHeader);
uint256 GetPONHash(const COutPoint& collateral, const uint256& prevBlockHash, uint32_t slot);

// Calculate the slot number for a given timestamp relative to genesis
uint32_t GetSlotNumber(int64_t timestamp, int64_t genesisTimestamp, const Consensus::Params& params);

// Whether a block timed at nTime is in a later slot than pindexPrev. A PON-VRF block is: a node
// draws once per slot against the tip, and a block in its parent's slot is a second draw there.
bool IsLaterSlotThan(int64_t nTime, const CBlockIndex* pindexPrev, const Consensus::Params& params);

// How far ahead of this node's clock a block may be stamped once PON-VRF is active. It is
// shorter than the wait between two nodes' turns, so a stamp cannot buy an earlier turn.
static const int64_t PON_VRF_MAX_AHEAD_SECONDS = 2;

// Whether a block stamped nBlockTime is ahead of the clock reading nNow by more than that. The
// clock is the system clock: network-adjusted time is the peers' clocks, sampled once.
bool IsStampedAheadOfClock(int64_t nBlockTime, int64_t nNow);

/** Slots in an epoch of the PON-VRF target. */
static const uint32_t PON_VRF_TARGET_EPOCH_SLOTS = 60;
/** Live eligible nodes a slot the PON-VRF target aims at, times 100. */
static const uint32_t PON_VRF_ELIGIBLE_X100 = 921;

/** Wide enough for the sum of an epoch's winning outputs times PON_VRF_ELIGIBLE_X100. */
typedef base_uint<320> arith_uint320;

/** a, in 320 bits. */
arith_uint320 WidenTo320(const arith_uint256& a);

/**
 * The value nBits holds for a target: arith_uint256's compact form keeps three bytes, and a
 * PON-VRF target is the value its nBits decodes to.
 */
arith_uint256 PonVrfRoundTarget(const arith_uint256& target);

/**
 * The PON-VRF target of an epoch from the target of the epoch before it and the sum of the
 * epoch before that: its winning outputs, with the epoch's own target for each slot that
 * has no version-PON_VRF_VERSION block. Three parts the old target and one part
 * PON_VRF_ELIGIBLE_X100 / 100 times the mean winning output, at most twice the old target.
 */
arith_uint256 PonVrfNextTarget(const arith_uint256& target, const arith_uint320& sum);

/**
 * The PON-VRF target at activation, from the number of confirmed fluxnodes:
 * PON_VRF_ELIGIBLE_X100 / 100 of them eligible a slot, all of them when there are nine or
 * fewer.
 */
arith_uint256 PonVrfFirstTarget(unsigned int nConfirmedNodes);

/** The epoch of the PON-VRF target a block time is in: PON_VRF_TARGET_EPOCH_SLOTS slots, the same on every chain. */
uint32_t GetPonVrfTargetEpoch(int64_t nTime, const Consensus::Params& params);

/**
 * nBits of a block stamped nBlockTime on pindexPrev, above the activation block.
 *
 * A block carries its parent's nBits within an epoch. The activation block's nBits holds for
 * its epoch and the two after it. After that an epoch's target is PonVrfNextTarget of the
 * target of the epoch before it and the sum of the epoch before that. Read from nTime, nBits,
 * nVersion and hashPON of the ancestors, all resident on a pruned entry.
 */
unsigned int GetPonVrfBits(const CBlockIndex* pindexPrev, int64_t nBlockTime, const Consensus::Params& params);

/**
 * nBits of the activation block: PonVrfFirstTarget of the confirmed list as it stands. It is
 * the activation block's only while the fluxnode cache is at that block's parent.
 */
unsigned int GetPonVrfActivationBits();

/** A PON-VRF draw: nBits decodes to a target and the output is at or under it. */
bool CheckPonVrfDraw(const uint256& output, unsigned int nBits);

// PON-VRF: epoch seed (randomness) for VRF eligibility — derived from a buried block
// window the current proposer did not author, so it is not grindable.
uint256 GetEpochSeed(const CBlockIndex* pindexPrev, const Consensus::Params& params);

// PON-VRF: per-slot VRF input = H(epoch_seed || slot || collateral). Mixing the slot gives
// a fresh eligibility draw each slot (leader rotation / liveness). Mixing the collateral
// outpoint makes the draw per-NODE: operator keys are shared across an owner's fleet in
// practice, and with a shared key alone every node computes the identical VRF output —
// collapsing N nodes to one lottery draw and broadcasting N identical-priority blocks on a
// win. Used by both the minter and ContextualCheckPONBlockHeader so prover and verifier
// agree (the header already commits the outpoint as nodesCollateral).
uint256 GetPonVrfMessage(const CBlockIndex* pindexPrev, uint32_t slot, const COutPoint& collateral, const Consensus::Params& params);

// The proof-of-node score a block index entry keeps in hashPON: the VRF output of a PON-VRF
// block, the PON hash of a legacy PON block.
uint256 GetPonScore(const CBlockHeader& block);

// PON fork-choice tie-break between two competing same-work/same-height PON blocks.
// Returns <0 if a is preferred (wins the tie), >0 if b is preferred, 0 if undecided
// (caller falls back to first-seen). PON-VRF blocks compare by VRF output (un-grindable);
// legacy PON blocks by the PON hash cached on the index entry. Both are resident fields,
// valid after header-data pruning. Lower value wins in both cases.
int ComparePonForkChoice(const CBlockIndex* a, const CBlockIndex* b);

/**
 * The order of block index entries as candidate tips: true when pa is the worse of the two.
 * More chain work is better. Between PON entries of equal work at one height the preferred
 * score wins (ComparePonForkChoice). What is left goes to the entry received first, then to
 * the lower address.
 *
 * It reads only fields that do not change while an entry is in a set ordered by it.
 */
bool IsWorseBlockIndex(const CBlockIndex* pa, const CBlockIndex* pb);

// Get next PON work required (difficulty adjustment)
unsigned int GetNextPONWorkRequired(const CBlockIndex* pindexLast);

// Validate PON block header (using only header data - for headers-first sync)
// This validates:
// 1. Block version indicates PON
// 2. Timestamp aligns with slot
// 3. Stake hash meets difficulty target
bool CheckPONBlockHeader(const CBlockHeader& block, const CBlockIndex* pindexPrev,
                            const Consensus::Params& params);

// Full PON block header validation (requires chain state - for blocks near tip)
// This additionally validates:
// 1. Signature matches collateral owner
// 2. Fluxnode is active in the network
// fSignatureFailure: set to true when failure is due to signature validation
//                    (signature is not committed to block hash, so signature failures
//                    should not permanently invalidate by hash)
bool ContextualCheckPONBlockHeader(const CBlockHeader& pblock, const CBlockIndex* pindexPrev,
                     const Consensus::Params& params, bool fCheckSignature, bool& fSignatureFailure);

// Log PON eligibility for all confirmed fluxnodes at a given slot offset
// This is called automatically after each block connection for monitoring
void LogPONEligibility(const CBlockIndex* pindexPrev, int slotOffset = 1);

// Structure to hold eligible node info
struct EligibleNodeInfo {
    COutPoint collateral;
    uint256 ponHash;

    // Sort by PON hash (ascending - lowest hash has best priority)
    bool operator<(const EligibleNodeInfo& other) const {
        return ponHash < other.ponHash;
    }
};

// Get all eligible nodes for a given slot, sorted by PON hash (best hash first)
std::vector<EligibleNodeInfo> GetEligibleNodes(const CBlockIndex* pindexPrev, uint32_t slot, unsigned int nBits);

// Get the rank of a specific node in the eligible nodes list (1-indexed, 1 = best)
// Returns -1 if node is not in the eligible list
int GetNodeRank(const std::vector<EligibleNodeInfo>& eligibleNodes, const COutPoint& myCollateral);

#endif // BITCOIN_PON_H