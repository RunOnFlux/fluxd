// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "pon.h"
#include "pon-fork.h"
#include "../arith_uint256.h"
#include "../crypto/ecvrf.h"
#include "../chain.h"
#include "../chainparams.h"
#include "../emergencyblock.h"
#include "../fluxnode/fluxnode.h"
#include "../hash.h"
#include "../primitives/block.h"
#include "../streams.h"
#include "../uint256.h"
#include "../util.h"

#include <algorithm>
#include <map>

// Forward declarations to avoid circular dependency with main.h
extern CChain chainActive;

// This must match the declaration in main.cpp.
bool IsInitialBlockDownload(const CChainParams& chainParams);

bool CheckProofOfNode(const uint256& hash, unsigned int nBits, const Consensus::Params& params, int nHeightToCheckWith)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 target;
    
    target.SetCompact(nBits, &fNegative, &fOverflow);

    if (Params().NetworkID() == CBaseChainParams::REGTEST) {
        return true;
    }

    arith_uint256 maximumTargetAllowed;
    if (nHeightToCheckWith) {
        if (nHeightToCheckWith >= params.vUpgrades[Consensus::UPGRADE_PON].nActivationHeight + params.nPonDifficultyWindow) {
            maximumTargetAllowed = UintToArith256(params.ponLimit);
        } else {
            maximumTargetAllowed = UintToArith256(params.ponStartLimit);
        }
    } else {
        maximumTargetAllowed = UintToArith256(params.ponLimit) < UintToArith256(params.ponStartLimit) ? UintToArith256(params.ponStartLimit) : UintToArith256(params.ponLimit);
    }

    // Check range - similar to CheckProofOfWork but using ponLimit
    if (fNegative || target == 0 || fOverflow || target > maximumTargetAllowed) {
        return error("CheckProofOfNode(): nBits below minimum work (work is too easy) or invalid");
    }

    // Convert hash to arith_uint256 for comparison
    arith_uint256 hashValue = UintToArith256(hash);

    // Check if the hash meets the target difficulty
    // Lower hash values mean higher difficulty met
    return hashValue <= target;
}


uint256 GetPONHash(const CBlockHeader& blockHeader)
{
    int64_t genesisTimestamp = Params().GenesisBlock().nTime;
    uint32_t slot = GetSlotNumber(blockHeader.nTime, genesisTimestamp, Params().GetConsensus());
    return GetPONHash(blockHeader.nodesCollateral, blockHeader.hashPrevBlock, slot);
}

uint256 GetPONHash(const COutPoint& collateral, const uint256& prevBlockHash, uint32_t slot)
{
    // Create a deterministic hash from the three inputs
    // This ensures that the same fluxnode will always get the same hash for the same slot
    CHashWriter ss(SER_GETHASH, 0);

    // Add collateral outpoint (txid + vout index)
    ss << collateral;

    // Add previous block hash for unpredictability
    ss << prevBlockHash;

    // Add slot number to ensure different hash for each slot
    ss << slot;

    return ss.GetHash();
}

uint32_t GetSlotNumber(int64_t timestamp, int64_t genesisTimestamp, const Consensus::Params& params)
{
    // Calculate slot number based on time elapsed since genesis
    int64_t timeSinceGenesis = timestamp - genesisTimestamp;
    return static_cast<uint32_t>(timeSinceGenesis / params.nPonTargetSpacing);
}

bool IsLaterSlotThan(int64_t nTime, const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    const int64_t genesisTimestamp = Params().GenesisBlock().nTime;
    return GetSlotNumber(nTime, genesisTimestamp, params) >
           GetSlotNumber(pindexPrev->GetBlockTime(), genesisTimestamp, params);
}

bool IsStampedAheadOfClock(int64_t nBlockTime, int64_t nNow)
{
    return nBlockTime > nNow + PON_VRF_MAX_AHEAD_SECONDS;
}

arith_uint320 WidenTo320(const arith_uint256& a)
{
    arith_uint320 wide;
    for (int i = 3; i >= 0; i--) {
        wide <<= 64;
        wide |= arith_uint320((a >> (64 * i)).GetLow64());
    }
    return wide;
}

// The low 256 bits of a value that fits in them.
static arith_uint256 NarrowTo256(const arith_uint320& a)
{
    arith_uint256 narrow;
    for (int i = 3; i >= 0; i--) {
        narrow <<= 64;
        narrow |= arith_uint256((a >> (64 * i)).GetLow64());
    }
    return narrow;
}

arith_uint256 PonVrfRoundTarget(const arith_uint256& target)
{
    arith_uint256 rounded;
    rounded.SetCompact(target.GetCompact());
    return rounded;
}

arith_uint256 PonVrfNextTarget(const arith_uint256& target, const arith_uint320& sum)
{
    const arith_uint320 old = WidenTo320(target);
    const arith_uint320 ceiling = WidenTo320(~arith_uint256());

    arith_uint320 asked = sum;
    asked *= PON_VRF_ELIGIBLE_X100;
    asked /= arith_uint320(100 * PON_VRF_TARGET_EPOCH_SLOTS);

    arith_uint320 next = old;
    next *= 3;
    next += asked;
    next >>= 2;

    arith_uint320 twice = old;
    twice <<= 1;
    if (next > twice) next = twice;
    if (next > ceiling) next = ceiling;

    return PonVrfRoundTarget(NarrowTo256(next));
}

arith_uint256 PonVrfFirstTarget(unsigned int nConfirmedNodes)
{
    const arith_uint256 ceiling = ~arith_uint256();
    if (nConfirmedNodes * 100 <= PON_VRF_ELIGIBLE_X100) {
        return PonVrfRoundTarget(ceiling);
    }
    arith_uint256 target = ceiling / arith_uint256(100 * (uint64_t)nConfirmedNodes);
    target *= PON_VRF_ELIGIBLE_X100;
    return PonVrfRoundTarget(target);
}

uint32_t GetPonVrfTargetEpoch(int64_t nTime, const Consensus::Params& params)
{
    return GetSlotNumber(nTime, Params().GenesisBlock().nTime, params) / PON_VRF_TARGET_EPOCH_SLOTS;
}

namespace {
//! What a chain's blocks say of one epoch of the target.
struct TargetEpoch {
    arith_uint320 sum;      //!< the outputs of its PON-VRF blocks
    uint32_t nFilled = 0;   //!< how many slots those fill
    uint32_t nBits = 0;     //!< what its blocks carry
};

arith_uint256 TargetOf(unsigned int nBits)
{
    arith_uint256 target;
    target.SetCompact(nBits);
    return target;
}
} // namespace

unsigned int GetPonVrfBits(const CBlockIndex* pindexPrev, int64_t nBlockTime, const Consensus::Params& params)
{
    const int nActivation = params.vUpgrades[Consensus::UPGRADE_PON_VRF].nActivationHeight;
    const CBlockIndex* pindexActivation = pindexPrev->GetAncestor(nActivation);
    if (!pindexActivation) {
        return pindexPrev->nBits;
    }

    const uint32_t epochFirst = GetPonVrfTargetEpoch(pindexActivation->GetBlockTime(), params);
    const uint32_t epochPrev = GetPonVrfTargetEpoch(pindexPrev->GetBlockTime(), params);
    const uint32_t epochBlock = GetPonVrfTargetEpoch(nBlockTime, params);

    if (epochBlock <= epochPrev) {
        return pindexPrev->nBits;
    }
    // The epoch the fork lands in holds legacy blocks, so the first sum that moves the
    // target is that of the epoch after it.
    if (epochBlock <= epochFirst + 2) {
        return pindexActivation->nBits;
    }

    // Walk back to two consecutive epochs that each hold a block: their nBits give two
    // targets to roll forward from. An epoch with no block carries no nBits, so the walk
    // passes over it; it ends at the activation block at the latest.
    std::map<uint32_t, TargetEpoch> epochs;
    bool fAnchored = false;
    uint32_t epochAnchor = 0;
    {
        bool fAbove = false;
        uint32_t epochAbove = 0;
        uint32_t epochWalking = epochPrev;
        for (const CBlockIndex* p = pindexPrev; p && p->nHeight >= nActivation; p = p->pprev) {
            const uint32_t epoch = GetPonVrfTargetEpoch(p->GetBlockTime(), params);
            if (epoch != epochWalking) {
                if (fAbove && epochAbove == epochWalking + 1) {
                    fAnchored = true;
                    epochAnchor = epochAbove;
                    break;
                }
                fAbove = true;
                epochAbove = epochWalking;
                epochWalking = epoch;
            }
            TargetEpoch& acc = epochs[epoch];
            acc.nBits = p->nBits;
            // An emergency block is at PON_VERSION: its slot is one no node minted in.
            if (p->nVersion >= CBlockHeader::PON_VRF_VERSION) {
                acc.sum += WidenTo320(UintToArith256(p->hashPON));
                acc.nFilled++;
            }
        }
    }

    const arith_uint256 targetFirst = TargetOf(pindexActivation->nBits);
    std::map<uint32_t, arith_uint256> targets;
    uint32_t epoch;
    if (fAnchored) {
        targets[epochAnchor - 1] = TargetOf(epochs[epochAnchor - 1].nBits);
        targets[epochAnchor] = TargetOf(epochs[epochAnchor].nBits);
        epoch = epochAnchor;
    } else {
        targets[epochFirst + 1] = targetFirst;
        targets[epochFirst + 2] = targetFirst;
        epoch = epochFirst + 2;
    }

    for (; epoch < epochBlock; epoch++) {
        if (epoch + 1 <= epochFirst + 2) {
            targets[epoch + 1] = targetFirst;
        } else {
            const TargetEpoch& before = epochs[epoch - 1];
            arith_uint320 sum = WidenTo320(targets[epoch - 1]);
            sum *= PON_VRF_TARGET_EPOCH_SLOTS - before.nFilled;
            sum += before.sum;
            targets[epoch + 1] = PonVrfNextTarget(targets[epoch], sum);
        }
        targets.erase(epoch - 1);
    }
    return targets[epochBlock].GetCompact();
}

unsigned int GetPonVrfActivationBits()
{
    LOCK(g_fluxnodeCache.cs);
    return PonVrfFirstTarget(g_fluxnodeCache.mapConfirmedFluxnodeData.size()).GetCompact();
}

arith_uint256 PonVrfBlockWork(const arith_uint256& output, unsigned int nBits, bool fEmergency)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 target;
    target.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || target == 0) {
        return 0;
    }

    static const unsigned int GRADE_BITS = 16;
    arith_uint256 grade(2 << GRADE_BITS);
    if (!fEmergency) {
        const arith_uint320 wide = WidenTo320(target);
        arith_uint320 scaled = wide;
        scaled <<= 1;
        scaled -= WidenTo320(output > target ? target : output);
        scaled <<= GRADE_BITS;
        scaled /= wide;
        grade = NarrowTo256(scaled);
    }

    arith_uint256 proof = ~arith_uint256() / ((target >> 32) + 1);
    // A target under 2^49 has a proof the grade would carry out of 256 bits.
    const arith_uint256 most = ~arith_uint256() >> (GRADE_BITS + 1);
    if (proof > most) proof = most;
    return grade * proof;
}

uint32_t PonVrfTurnSeconds(const arith_uint256& output, unsigned int nBits)
{
    arith_uint256 target;
    target.SetCompact(nBits);
    const arith_uint256 step = target / PON_VRF_TURN_SPREAD_SECONDS + 1;
    const arith_uint256 steps = output / step;
    const uint32_t last = PON_VRF_TURN_SPREAD_SECONDS - 1;
    return PON_VRF_FIRST_TURN_SECONDS + (steps > arith_uint256(last) ? last : (uint32_t)steps.GetLow64());
}

int64_t GetPonSlotStart(uint32_t slot, const Consensus::Params& params)
{
    return Params().GenesisBlock().nTime + (int64_t)slot * params.nPonTargetSpacing;
}

bool CheckPonVrfDraw(const uint256& output, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 target;
    target.SetCompact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || target == 0) {
        return error("CheckPonVrfDraw(): nBits %08x does not decode to a target", nBits);
    }
    return UintToArith256(output) <= target;
}

// PON-VRF epoch seed. The randomness for a block's VRF eligibility is derived from a
// window of blocks buried beyond the reorg horizon, so the proposer of the current block
// cannot have authored (and therefore cannot grind) the seed. Constant for an entire epoch.
//
// A VRF block contributes its VRF output, never its block hash. A block hash covers the
// merkle root, so the producer of a window block could try transaction sets and keep the one
// whose seed favours its own nodes; its VRF output is fixed by its key, its slot and the seed
// of its own epoch, which leaves it the choice of publishing the block or not. A block below
// the VRF version, in a window that reaches back before activation, has no output and
// contributes its hash. Both are resident on the index entry (a VRF entry's output is its
// hashPON).
static const int PON_VRF_EPOCH_LEN = 60;   // blocks per epoch (~30 min at 30s spacing)
static const int PON_VRF_SEED_BURY = 60;   // window end is buried this many blocks (> MAX_REORG_LENGTH=40)

uint256 GetEpochSeed(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
    int epoch = nHeight / PON_VRF_EPOCH_LEN;
    int windowEnd = epoch * PON_VRF_EPOCH_LEN - PON_VRF_SEED_BURY;

    // Genesis warmup: before a buried window exists, use a fixed bootstrap seed.
    if (windowEnd < PON_VRF_EPOCH_LEN || pindexPrev == NULL) {
        return Params().GenesisBlock().GetHash();
    }

    CHashWriter ss(SER_GETHASH, 0);
    const CBlockIndex* p = pindexPrev->GetAncestor(windowEnd);
    for (int i = 0; i < PON_VRF_EPOCH_LEN && p != NULL; ++i, p = p->pprev) {
        if (p->nVersion >= CBlockHeader::PON_VRF_VERSION) {
            ss << (unsigned char)1 << p->hashPON;
        } else {
            ss << (unsigned char)0 << p->GetBlockHash();
        }
    }
    return ss.GetHash();
}

// PON-VRF per-slot eligibility input. The epoch seed (un-grindable) provides the base
// randomness; mixing in the slot makes eligibility a FRESH draw each slot, so leadership
// rotates and the chain stays live (without this, a node is eligible for either every slot
// or no slot in an epoch). The slot (from nTime) carries only the minor ~10-slot future-time
// grind already acknowledged in the design — the large prevBlockHash/coinbase grind is gone.
// Mixing in the collateral outpoint makes the draw per-node under shared operator keys
// (standard fleet practice): without it, N same-key nodes share ONE draw (1/N rewards) and
// on a win all N broadcast at the identical VRF-derived delay, with identical outputs that
// also void the lowest-VRF fork-choice tie-break. The outpoint is fixed at node registration
// — before any future epoch seed exists — so it adds no grinding surface.
uint256 GetPonVrfMessage(const CBlockIndex* pindexPrev, uint32_t slot, const COutPoint& collateral, const Consensus::Params& params)
{
    uint256 epochSeed = GetEpochSeed(pindexPrev, params);
    CHashWriter ss(SER_GETHASH, 0);
    ss << epochSeed;
    ss << slot;
    ss << collateral;
    return ss.GetHash();
}

unsigned int GetNextPONWorkRequired(const CBlockIndex* pindexLast)
{
    const Consensus::Params& params = Params().GetConsensus();
    const arith_uint256 ponLimit = UintToArith256(params.ponLimit);
    const arith_uint256 ponStartLimit = UintToArith256(params.ponStartLimit);

    unsigned int nProofOfNodeLimit = ponLimit.GetCompact();
    unsigned int nProofOfNodeStartLimit = ponStartLimit.GetCompact();

    // Genesis block or nullptr
    if (pindexLast == nullptr) {
        return nProofOfNodeStartLimit;
    }

    int ponActivationHeight = GetPONActivationHeight();
    int nextHeight = pindexLast->nHeight + 1;
    int lookbackWindow = params.nPonDifficultyWindow;

    // Before PON activation, use existing difficulty
    if (nextHeight < ponActivationHeight) {
        return pindexLast->nBits;
    }

    // For the first few blocks after PON activation, use start limit
    // Need at least lookbackWindow blocks to calculate difficulty
    if (nextHeight < (ponActivationHeight + lookbackWindow)) {
        return nProofOfNodeStartLimit;
    }

    // Now adjust difficulty every block based on the lookback window
    // Find the first block in the lookback window
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < lookbackWindow - 1; i++) {
        pindexFirst = pindexFirst->pprev;
        if (!pindexFirst || pindexFirst->nHeight < ponActivationHeight) {
            // Not enough PON blocks yet, shouldn't happen due to check above
            return nProofOfNodeStartLimit;
        }
    }

    // Calculate actual timespan over the window
    int64_t actualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    // Target timespan = (window - 1) * target spacing (because we're measuring intervals)
    int64_t targetTimespan = (lookbackWindow - 1) * params.nPonTargetSpacing;

    LogPrint("pon", "PON: Adjustment at height %d: first=%d, last=%d, actualTimespan=%d, targetTimespan=%d\n",
              nextHeight, pindexFirst->nHeight, pindexLast->nHeight, actualTimespan, targetTimespan);

    // Sanity check
    if (targetTimespan <= 0) {
        LogPrintf("PON: Invalid target timespan %d\n", targetTimespan);
        return nProofOfNodeLimit;
    }

    // Limit adjustment to prevent large swings (1.25x max)
    // 4/5 = 0.8 for harder difficulty (blocks too fast)
    // 5/4 = 1.25 for easier difficulty (blocks too slow)
    if (actualTimespan < targetTimespan * 4 / 5) {
        actualTimespan = targetTimespan * 4 / 5;
    }
    if (actualTimespan > targetTimespan * 5 / 4) {
        actualTimespan = targetTimespan * 5 / 4;
    }

    // Calculate new target based on the last block's difficulty
    // Use Digishield-style calculation to avoid overflow
    arith_uint256 newTarget;
    bool fNegative;
    bool fOverflow;
    newTarget.SetCompact(pindexLast->nBits, &fNegative, &fOverflow);

    // Check for invalid compact representation
    if (fNegative || fOverflow || newTarget == 0) {
        LogPrintf("PON: Invalid previous target, using ponLimit\n");
        return nProofOfNodeLimit;
    }

    // Adjust the target based on actual vs target timespan
    // Use Digishield approach: divide first, then multiply to avoid overflow
    // newTarget = oldTarget * actualTimespan / targetTimespan
    newTarget /= targetTimespan;
    newTarget *= actualTimespan;

    // Don't allow target to exceed maximum (easiest difficulty)
    if (newTarget > ponLimit) {
        newTarget = ponLimit;
    }

    // Ensure target is not zero (would cause CheckProofOfNode to reject the block)
    // This should never happen since actualTimespan is clamped to targetTimespan/2 minimum
    if (newTarget == 0) {
        LogPrintf("PON: ERROR - calculated target was 0, using ponLimit as failsafe\n");
        newTarget = ponLimit;  // Use easiest difficulty as failsafe
    }

    LogPrint("pon", "PON difficulty adjustment: height=%d, actualTimespan=%d, targetTimespan=%d, before=%08x, after=%08x\n",
              pindexLast->nHeight + 1, actualTimespan, targetTimespan,
              pindexLast->nBits, newTarget.GetCompact());

    return newTarget.GetCompact();
}

uint256 GetPonScore(const CBlockHeader& block)
{
    return block.nVersion >= CBlockHeader::PON_VRF_VERSION ? block.nodesVrfOutput : GetPONHash(block);
}

int ComparePonForkChoice(const CBlockIndex* a, const CBlockIndex* b)
{
    // Each entry compares by its score in hashPON: a VRF block's committed VRF output
    // (un-grindable), a legacy PON block's PON hash. A VRF and a legacy block (mixed-version
    // fork around activation) each use their own; lower wins in all cases. The score is a
    // resident field: recomputing a PON hash from GetBlockHeader() would hash a zeroed
    // nodesCollateral once the entry's header data has been pruned, and the score would
    // change when header data is restored — mutating a comparator key in place for entries
    // already inside setBlockIndexCandidates.
    const uint256& scoreA = a->hashPON;
    const uint256& scoreB = b->hashPON;

    if (scoreA < scoreB) return -1;  // a preferred
    if (scoreA > scoreB) return 1;   // b preferred

    // At PON-VRF heights equal scores are one draw minted twice: the lower block hash, so
    // that every node settles it alike.
    if (IsPONVRFActive(a->nHeight) && IsPONVRFActive(b->nHeight) && a->phashBlock && b->phashBlock) {
        if (*a->phashBlock < *b->phashBlock) return -1;
        if (*b->phashBlock < *a->phashBlock) return 1;
    }
    return 0;                         // undecided -> caller falls back to first-seen
}

bool IsWorseBlockIndex(const CBlockIndex* pa, const CBlockIndex* pb)
{
    if (pa->nChainWork > pb->nChainWork) return false;
    if (pa->nChainWork < pb->nChainWork) return true;

    // PON entries of equal work at one height, or at any two PON-VRF heights: the preferred
    // score, so that every node holds the same one whatever order they arrived in. ComparePonForkChoice reads
    // resident fields only: a score recomputed from header data would change when an
    // entry's header data is pruned or restored, and an entry's place in a set ordered by
    // this must not move while it is in the set.
    const bool fPonA = pa->nVersion >= CBlockHeader::PON_VERSION;
    const bool fPonB = pb->nVersion >= CBlockHeader::PON_VERSION;
    const bool fBothVrfHeights = IsPONVRFActive(pa->nHeight) && IsPONVRFActive(pb->nHeight);
    if (fPonA && fPonB && (pa->nHeight == pb->nHeight || fBothVrfHeights)) {
        const int cmp = ComparePonForkChoice(pa, pb);
        if (cmp < 0) return false;
        if (cmp > 0) return true;
    }

    // The entry received first.
    if (pa->nSequenceId < pb->nSequenceId) return false;
    if (pa->nSequenceId > pb->nSequenceId) return true;

    // Entries loaded from disk all have sequence id 0: the lower address.
    if (pa < pb) return false;
    if (pa > pb) return true;

    return false;
}


bool CheckPONBlockHeader(const CBlockHeader& block, const CBlockIndex* pindexPrev,
                            const Consensus::Params& params)
{
    // 1. Verify this is a PON block
    if (!block.IsPON()) {
        return error("CheckPONBlockHeader: Block version %d is not PON", block.nVersion);
    }

    int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;

    // One block a slot under PON-VRF, an emergency block included.
    if (IsPONVRFActive(nHeight) && !IsLaterSlotThan(block.nTime, pindexPrev, params)) {
        return error("CheckPONBlockHeader: block at time %d is not in a later slot than its parent at time %d",
                     block.nTime, pindexPrev->GetBlockTime());
    }

    if (IsEmergencyBlock(block)) {
        return true;
    }

    if (IsPONVRFActive(nHeight)) {
        // VRF leader election: eligibility is y <= target, where y = nodesVrfOutput.
        // The proof that y is genuinely VRF(operator_key, epoch_seed) is verified
        // contextually (ContextualCheckPONBlockHeader), where the operator pubkey is
        // available; here we enforce the cheap, context-free preconditions.
        if (block.nVersion < CBlockHeader::PON_VRF_VERSION) {
            return error("CheckPONBlockHeader: block version %d below PON_VRF_VERSION", block.nVersion);
        }
        if (block.nodesVrfProof.size() != 81) {
            return error("CheckPONBlockHeader: bad VRF proof size %d", (int)block.nodesVrfProof.size());
        }
        if (!CheckPonVrfDraw(block.nodesVrfOutput, block.nBits)) {
            return error("CheckPONBlockHeader: VRF output doesn't meet target");
        }
        // A block waits its draw's turn, so that the best draw of a slot is minted first.
        const uint32_t slot = GetSlotNumber(block.nTime, Params().GenesisBlock().nTime, params);
        const int64_t nTurn = GetPonSlotStart(slot, params) +
                              PonVrfTurnSeconds(UintToArith256(block.nodesVrfOutput), block.nBits);
        if (block.nTime < nTurn) {
            return error("CheckPONBlockHeader: block at time %d is before its turn at %d", block.nTime, nTurn);
        }
    } else {
        // Before UPGRADE_PON_VRF no block is at the VRF version: its VRF output is verified
        // by nothing, and fork choice scores a block at that version by its output.
        if (block.nVersion >= CBlockHeader::PON_VRF_VERSION) {
            return error("CheckPONBlockHeader: block version %d before PON_VRF activation", block.nVersion);
        }
        if (!CheckProofOfNode(GetPONHash(block), block.nBits, Params().GetConsensus(), nHeight)) {
            int64_t genesisTimestamp = Params().GenesisBlock().nTime;
            uint32_t slot = GetSlotNumber(block.nTime, genesisTimestamp, Params().GetConsensus());
            return error("CheckPONBlockHeader: stake hash doesn't meet target for slot %d", slot);
        }
    }

    int64_t genesisTimestamp = Params().GenesisBlock().nTime;
    uint32_t slot = GetSlotNumber(block.nTime, genesisTimestamp, Params().GetConsensus());
    LogPrint("pon", "CheckPONBlockHeader: Valid PON header for slot %d\n", slot);
    return true;
}

bool ContextualCheckPONBlockHeader(const CBlockHeader& block, const CBlockIndex* pindexPrev,
                     const Consensus::Params& params, bool fCheckSignature, bool& fSignatureFailure)
{
    fSignatureFailure = false;

    // First do all header validations
    if (!CheckPONBlockHeader(block, pindexPrev, params)) {
        return false;
    }

    // Now do additional validation that requires chain state

    // Check if this is an emergency block first
    if (IsEmergencyBlock(block)) {
        if (!ValidateEmergencyBlockSignatures(block)) {
            // Signature failure - not committed to hash, should not permanently invalidate
            fSignatureFailure = true;
            return error("ContextualCheckPONBlockHeader: Emergency block signature validation failed");
        }

        // Check if emergency blocks are allowed at this height/time
        int nHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
        if (!IsEmergencyBlockAllowed(nHeight, block.nTime)) {
            return error("ContextualCheckPONBlockHeader: Emergency block not allowed at height %d, time %d",
                        nHeight, block.nTime);
        }

        LogPrint("pon", "ContextualCheckPONBlockHeader: Emergency block validated successfully\n");
        return true;
    }

    // Special testnet/regtest collateral for PON for development
    bool isTestnet = (Params().NetworkIDString() == "test");
    bool isRegtest = (Params().NetworkIDString() == "regtest");

    if (isTestnet || isRegtest) {
        // Allow a special collateral that doesn't need to be a confirmed node
        // This is the hash of "TESTPON" - recognizable but unlikely to collide
        static const uint256 TEST_BYPASS_HASH = uint256S("0x544553544e4f4400000000000000000000000000000000000000000000000000");
        if (block.nodesCollateral.hash == TEST_BYPASS_HASH && block.nodesCollateral.n == 0) {
            LogPrint("pon", "ContextualCheckPONBlockHeader: Using testnet/regtest bypass for development\n");
            return true;  // Skip signature verification for test collateral
        }
    }

    // 1. Verify the signature matches the collateral owner
    if (fCheckSignature) {
        int currentHeight = pindexPrev ? pindexPrev->nHeight + 1 : 0;
        int chainTipHeight = chainActive.Height();

        // CRITICAL: Check if we're validating against wrong chain state FIRST
        // During out-of-order or competing chain validation, the global cache reflects
        // a different chain state. Any validation using cache data would be incorrect.
        // Allow validation for:
        // - Blocks at tip height (competing blocks)
        // - Blocks at tip+1 (normal next block, cache is correct after previous block connected)
        // Defer for:
        // - Blocks more than 1 ahead (out-of-order, parent blocks not processed yet)
        // - Blocks behind tip (competing chain)
        if (currentHeight != chainTipHeight && currentHeight != chainTipHeight + 1) {
            // Defer ALL signature validation - will be checked when block is actually connected
            LogPrint("pon", "FluxNode signature check deferred for block at height %d (tip=%d), different chain state\n",
                    currentHeight, chainTipHeight);
            return true;
        }

        // Past this point: block height matches chain tip or tip+1, cache state should be correct
        FluxnodeCacheData data = g_fluxnodeCache.GetFluxnodeData(block.nodesCollateral);

        if (data.IsNull()) {
            // Fluxnode not found in cache
            // Special case: For competing blocks at same height, the fluxnode might have expired in
            // the current tip block, but this competing block might be using it before expiration.
            // Defer validation to ConnectBlock where we'll have the correct state.
            if (currentHeight == chainTipHeight) {
                LogPrint("pon", "FluxNode %s not found at competing height %d (tip=%d), deferring signature validation\n",
                        block.nodesCollateral.ToString(), currentHeight, chainTipHeight);
                return true;
            }

            // For tip+1 blocks, fluxnode should exist. If it doesn't, block is invalid.
            return error("ContextualCheckPONBlockHeader: FluxNode %s not found in cache for block %s (height=%d)",
                        block.nodesCollateral.ToString(), block.GetHash().GetHex(),
                        currentHeight);
        }

        // Create the message that was signed (block hash)
        uint256 hashToSign = block.GetHash();

        // Verify the block signature matches the fluxnode's public key
        if (!data.pubKey.Verify(hashToSign, block.vchBlockSig)) {
            // Signature failure - not committed to hash, should not permanently invalidate
            fSignatureFailure = true;
            return error("ContextualCheckPONBlockHeader: Block signature verification failed for fluxnode %s (block=%s, pubkey=%s)",
                        block.nodesCollateral.ToString(), block.GetHash().GetHex(),
                        HexStr(data.pubKey.begin(), data.pubKey.end()));
        }

        LogPrint("pon", "ContextualCheckPONBlockHeader: Signature verified for fluxnode %s (tier=%d)\n",
             block.nodesCollateral.ToString(), data.nTier);

        // VRF leader election: verify the proof binds nodesVrfOutput to this fluxnode's
        // operator key and the (un-grindable) epoch seed. Shares the deferral logic above:
        // we only reach here when the cache state is correct for this block.
        if (IsPONVRFActive(currentHeight)) {
            int64_t genesisTimestamp = Params().GenesisBlock().nTime;
            uint32_t slot = GetSlotNumber(block.nTime, genesisTimestamp, Params().GetConsensus());
            uint256 seed = GetPonVrfMessage(pindexPrev, slot, block.nodesCollateral, params);
            uint256 betaComputed;
            if (!ECVRF_Verify(data.pubKey, seed, block.nodesVrfProof, betaComputed)) {
                // Proof depends on chain-state (seed) and the cache; treat like a signature
                // failure (not permanently invalidating) to be safe under competing-chain validation.
                fSignatureFailure = true;
                return error("ContextualCheckPONBlockHeader: VRF proof verification failed for fluxnode %s (block=%s)",
                            block.nodesCollateral.ToString(), block.GetHash().GetHex());
            }
            if (betaComputed != block.nodesVrfOutput) {
                fSignatureFailure = true;
                return error("ContextualCheckPONBlockHeader: VRF output mismatch for fluxnode %s (block=%s)",
                            block.nodesCollateral.ToString(), block.GetHash().GetHex());
            }
            LogPrint("pon", "ContextualCheckPONBlockHeader: VRF proof verified for fluxnode %s\n",
                 block.nodesCollateral.ToString());
        }
    }

    LogPrint("pon", "ContextualCheckPONBlockHeader: Full validation passed for block %s\n", block.GetHash().GetHex());
    return true;
}

void LogPONEligibility(const CBlockIndex* pindexPrev, int slotOffset)
{
    // Check if PON is active
    int ponActivationHeight = GetPONActivationHeight();
    if (!pindexPrev || pindexPrev->nHeight < ponActivationHeight) {
        return; // PON not active yet
    }

    // Under VRF leader election the legacy GetPONHash formula below is dead, and other
    // nodes' eligibility cannot be computed at all (each draw needs that node's secret
    // key) — anything this function printed would be meaningless for operators.
    if (IsPONVRFActive(pindexPrev->nHeight + 1)) {
        return;
    }

    // Start timing
    int64_t nTimeStart = GetTimeMicros();

    const Consensus::Params& consensusParams = Params().GetConsensus();
    int64_t genesisTime = Params().GenesisBlock().nTime;

    // Calculate current slot
    int64_t currentTime = GetAdjustedTime();
    uint32_t currentSlot = GetSlotNumber(currentTime, genesisTime, consensusParams);

    // Get the difficulty for the next block
    unsigned int nBits = GetNextPONWorkRequired(pindexPrev);

    // Get the previous block hash (which will be used for PON hash calculation)
    uint256 prevBlockHash = pindexPrev->GetBlockHash();

    LOCK(g_fluxnodeCache.cs);
    int totalNodes = g_fluxnodeCache.mapConfirmedFluxnodeData.size();

    // Keep checking slots until we find one with eligible nodes (max 100 slots ahead)
    int maxSlotsToCheck = 100;
    for (int offset = slotOffset; offset <= maxSlotsToCheck; offset++) {
        uint32_t checkedSlot = currentSlot + offset;
        int eligibleNodes = 0;

        // Iterate through all confirmed fluxnodes
        for (const auto& pair : g_fluxnodeCache.mapConfirmedFluxnodeData) {
            const COutPoint& collateral = pair.first;

            // Calculate PON hash for this node at the checked slot
            uint256 ponHash = GetPONHash(collateral, prevBlockHash, checkedSlot);

            // Check if this hash meets the difficulty requirement
            if (CheckProofOfNode(ponHash, nBits, consensusParams, pindexPrev->nHeight + 1)) {
                eligibleNodes++;

                // Log each eligible node (use full collateral: txhash:index)
                LogPrint("pon", "PON Eligibility: Node %s:%d eligible for slot %d (hash: %s)\n",
                         collateral.hash.ToString().c_str(), collateral.n, checkedSlot, ponHash.ToString().c_str());
            }
        }

        // Calculate timing
        int64_t nTimeEnd = GetTimeMicros();
        double nTimeElapsed = (nTimeEnd - nTimeStart) * 0.001; // Convert to milliseconds

        // Calculate eligibility rate
        double eligibilityRate = (totalNodes > 0) ? (100.0 * eligibleNodes / totalNodes) : 0.0;

        // Log summary with timing (only when -debug=pon is enabled)
        LogPrint("pon", "PON Eligibility Check: Block %d, Slot %d - %d of %d nodes eligible (%.2f%%), difficulty=%08x, time=%.2fms\n",
                 pindexPrev->nHeight + 1, checkedSlot, eligibleNodes, totalNodes, eligibilityRate, nBits, nTimeElapsed);

        // If we found eligible nodes, stop checking
        if (eligibleNodes > 0) {
            break;
        }

        // If no nodes eligible, continue to next slot
        LogPrint("pon", "PON Eligibility: No eligible nodes for slot %d, checking next slot...\n", checkedSlot);
    }
}

std::vector<EligibleNodeInfo> GetEligibleNodes(const CBlockIndex* pindexPrev, uint32_t slot, unsigned int nBits)
{
    std::vector<EligibleNodeInfo> eligibleNodes;

    if (!pindexPrev) {
        return eligibleNodes;
    }

    const Consensus::Params& consensusParams = Params().GetConsensus();
    uint256 prevBlockHash = pindexPrev->GetBlockHash();

    LOCK(g_fluxnodeCache.cs);

    // Check all confirmed fluxnodes
    for (const auto& pair : g_fluxnodeCache.mapConfirmedFluxnodeData) {
        const COutPoint& collateral = pair.first;

        // Calculate PON hash for this node at the slot
        uint256 ponHash = GetPONHash(collateral, prevBlockHash, slot);

        // Check if this hash meets the difficulty requirement
        if (CheckProofOfNode(ponHash, nBits, consensusParams, pindexPrev->nHeight + 1)) {
            EligibleNodeInfo info;
            info.collateral = collateral;
            info.ponHash = ponHash;
            eligibleNodes.push_back(info);
        }
    }

    // Sort by PON hash (lowest hash first = best priority)
    std::sort(eligibleNodes.begin(), eligibleNodes.end());

    return eligibleNodes;
}

int GetNodeRank(const std::vector<EligibleNodeInfo>& eligibleNodes, const COutPoint& myCollateral)
{
    for (size_t i = 0; i < eligibleNodes.size(); i++) {
        if (eligibleNodes[i].collateral == myCollateral) {
            return i + 1; // Rank is 1-indexed (1 = best)
        }
    }
    return -1; // Not found in eligible list
}