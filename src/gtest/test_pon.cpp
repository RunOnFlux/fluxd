// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <deque>

#include "chainparams.h"
#include "consensus/params.h"
#include "consensus/validation.h"
#include "emergencyblock.h"
#include "fluxnode/fluxnode.h"
#include "main.h"
#include "pon/pon.h"
#include "pon/pon-claim.h"
#include "pon/pon-fork.h"
#include "pow.h"
#include "primitives/block.h"
#include "chain.h"
#include "uint256.h"
#include "utiltime.h"
#include "amount.h"
#include "crypto/ecvrf.h"
#include "key.h"
#include "pubkey.h"
#include "streams.h"
#include "version.h"

// Define node tiers for testing (from fluxnode/fluxnode.h)
#ifndef CUMULUS
#define CUMULUS 1
#define NIMBUS 2
#define STRATUS 3
#endif

class PONTest : public ::testing::Test {
protected:
    void SetUp() override {
        SelectParams(CBaseChainParams::MAIN);
    }
};

TEST_F(PONTest, PONActivationHeight) {
    // Test PON activation heights for different networks
    SelectParams(CBaseChainParams::MAIN);
    int mainnetHeight = GetPONActivationHeight();
    EXPECT_GT(mainnetHeight, 0);
    
    SelectParams(CBaseChainParams::TESTNET);
    int testnetHeight = GetPONActivationHeight();
    EXPECT_GT(testnetHeight, 0);
}

TEST_F(PONTest, IsPONActive) {
    SelectParams(CBaseChainParams::MAIN);
    int ponHeight = GetPONActivationHeight();
    
    // Before activation
    EXPECT_FALSE(IsPONActive(ponHeight - 1));
    
    // At activation
    EXPECT_TRUE(IsPONActive(ponHeight));
    
    // After activation
    EXPECT_TRUE(IsPONActive(ponHeight + 100));
}

TEST_F(PONTest, BlockVersionCheck) {
    // Test that block headers correctly identify as PON or POW
    CBlockHeader powBlock;
    powBlock.nVersion = CBlockHeader::CURRENT_VERSION;
    EXPECT_TRUE(powBlock.IsPOW());
    EXPECT_FALSE(powBlock.IsPON());
    
    CBlockHeader ponBlock;
    ponBlock.nVersion = CBlockHeader::PON_VERSION;
    EXPECT_FALSE(ponBlock.IsPOW());
    EXPECT_TRUE(ponBlock.IsPON());
}

TEST_F(PONTest, InitialPONSubsidy) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    
    // Test initial subsidy at activation
    CAmount subsidy = GetBlockSubsidy(ponHeight, consensusParams);
    EXPECT_EQ(subsidy, 14 * COIN);
    
    // Test subsidy remains same in first year
    subsidy = GetBlockSubsidy(ponHeight + 1000, consensusParams);
    EXPECT_EQ(subsidy, 14 * COIN);
    
    // Test before last block of first year
    subsidy = GetBlockSubsidy(ponHeight + 1051199, consensusParams);
    EXPECT_EQ(subsidy, 14 * COIN);
}

TEST_F(PONTest, PONSubsidyReduction) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    
    // Year 0 (initial)
    CAmount subsidy = GetBlockSubsidy(ponHeight, consensusParams);
    EXPECT_EQ(subsidy, 14 * COIN);
    
    // Year 1 (10% reduction)
    subsidy = GetBlockSubsidy(ponHeight + 1051200, consensusParams);
    EXPECT_EQ(subsidy, static_cast<CAmount>(12.6 * COIN));
    
    // Year 2 (another 10% reduction)
    subsidy = GetBlockSubsidy(ponHeight + 2 * 1051200, consensusParams);
    EXPECT_EQ(subsidy, static_cast<CAmount>(11.34 * COIN));
    
    // Year 5
    subsidy = GetBlockSubsidy(ponHeight + 5 * 1051200, consensusParams);
    EXPECT_EQ(subsidy, static_cast<CAmount>(8.26686 * COIN));
}

TEST_F(PONTest, PONSubsidyCap) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    
    // Year 20 - last reduction
    CAmount subsidy20 = GetBlockSubsidy(ponHeight + 20 * 1051200, consensusParams);
    EXPECT_EQ(subsidy20, static_cast<CAmount>(1.70207313 * COIN));
    
    // Year 21 - should be same as year 20 (capped)
    CAmount subsidy21 = GetBlockSubsidy(ponHeight + 21 * 1051200, consensusParams);
    EXPECT_EQ(subsidy21, subsidy20);
    
    // Year 30 - should still be capped
    CAmount subsidy30 = GetBlockSubsidy(ponHeight + 30 * 1051200, consensusParams);
    EXPECT_EQ(subsidy30, subsidy20);
}

TEST_F(PONTest, FluxnodeRewardDistribution) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    CAmount totalReward = GetBlockSubsidy(ponHeight, consensusParams);
    
    // Test initial distribution
    CAmount cumulusReward = GetFluxnodeSubsidy(ponHeight, totalReward, CUMULUS);
    CAmount nimbusReward = GetFluxnodeSubsidy(ponHeight, totalReward, NIMBUS);
    CAmount stratusReward = GetFluxnodeSubsidy(ponHeight, totalReward, STRATUS);
    
    EXPECT_EQ(cumulusReward, 1 * COIN);
    EXPECT_EQ(nimbusReward, static_cast<CAmount>(3.5 * COIN));
    EXPECT_EQ(stratusReward, 9 * COIN);
    
    // Test that rewards sum correctly (minus dev fund)
    CAmount devFund = totalReward / 28; // 3.57% for dev fund
    CAmount nodeRewards = cumulusReward + nimbusReward + stratusReward + devFund;
    EXPECT_EQ(nodeRewards, totalReward);
}

TEST_F(PONTest, DevFundCalculation) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    CAmount totalReward = GetBlockSubsidy(ponHeight, consensusParams);
    
    // Dev fund should be 1/28 of total (approximately 3.57%)
    CAmount devFund = totalReward / 28;
    EXPECT_EQ(devFund, COIN / 2); // 0.5 FLUX for 14 FLUX total
    
    // Test dev fund scales with reduced rewards
    totalReward = GetBlockSubsidy(ponHeight + 1051200, consensusParams); // Year 1
    devFund = totalReward / 28;
    EXPECT_EQ(devFund, static_cast<CAmount>(0.45 * COIN)); // 0.45 FLUX for 12.6 FLUX total
}

TEST_F(PONTest, PrePONSubsidy) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    
    // Test that pre-PON blocks use the old subsidy calculation
    if (ponHeight > 1) {
        CAmount prePONSubsidy = GetBlockSubsidy(ponHeight - 1, consensusParams);
        CAmount ponSubsidy = GetBlockSubsidy(ponHeight, consensusParams);
        
        // Pre-PON should use different calculation than PON
        EXPECT_NE(prePONSubsidy, ponSubsidy);
        EXPECT_EQ(ponSubsidy, 14 * COIN);
    }
}

TEST_F(PONTest, PONBlockHeaderSerialization) {
    CBlockHeader ponBlock;
    ponBlock.nVersion = CBlockHeader::PON_VERSION;
    ponBlock.hashPrevBlock = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    ponBlock.hashMerkleRoot = uint256S("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
    ponBlock.nTime = 1234567890;
    ponBlock.nBits = 0x1d00ffff;
    
    // Set PON-specific fields
    ponBlock.nodesCollateral = COutPoint(uint256S("0xaaaa"), 1);
    ponBlock.vchBlockSig = std::vector<unsigned char>{0x01, 0x02, 0x03, 0x04};
    
    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << ponBlock;
    
    // Deserialize
    CBlockHeader ponBlock2;
    ss >> ponBlock2;
    
    // Check all fields match
    EXPECT_EQ(ponBlock2.nVersion, ponBlock.nVersion);
    EXPECT_EQ(ponBlock2.hashPrevBlock, ponBlock.hashPrevBlock);
    EXPECT_EQ(ponBlock2.hashMerkleRoot, ponBlock.hashMerkleRoot);
    EXPECT_EQ(ponBlock2.nTime, ponBlock.nTime);
    EXPECT_EQ(ponBlock2.nBits, ponBlock.nBits);
    EXPECT_EQ(ponBlock2.nodesCollateral, ponBlock.nodesCollateral);
    EXPECT_EQ(ponBlock2.vchBlockSig, ponBlock.vchBlockSig);
}

TEST_F(PONTest, PONDifficultyCheck) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    // Test CheckProofOfNode with valid and invalid targets
    // Use a small hash that passes easy difficulty
    uint256 easyHash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000001");
    
    // Easy target (high nBits value) - should pass
    unsigned int easyBits = UintToArith256(consensusParams.ponLimit).GetCompact();
    EXPECT_TRUE(CheckProofOfNode(easyHash, easyBits, consensusParams));
    
    // Use a large hash that fails even easy difficulty
    uint256 hardHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    
    // Even with easy target, this large hash should fail
    EXPECT_FALSE(CheckProofOfNode(hardHash, easyBits, consensusParams));
    
    // Test with negative nBits - should fail
    arith_uint256 testTarget;
    bool fNegative = false;
    bool fOverflow = false;
    testTarget.SetCompact(0x0100ffff, &fNegative, &fOverflow); // Very small exponent
    if (fNegative || fOverflow) {
        // This compact representation is invalid
        EXPECT_FALSE(CheckProofOfNode(easyHash, 0x0100ffff, consensusParams));
    }
}

TEST_F(PONTest, PONHashCalculation) {
    // Test PON hash calculation is deterministic
    COutPoint collateral(uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"), 1);
    uint256 prevBlockHash = uint256S("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
    uint32_t slot = 12345;
    
    // Calculate hash twice - should be identical
    uint256 hash1 = GetPONHash(collateral, prevBlockHash, slot);
    uint256 hash2 = GetPONHash(collateral, prevBlockHash, slot);
    EXPECT_EQ(hash1, hash2);
    
    // Different slot should give different hash
    uint256 hash3 = GetPONHash(collateral, prevBlockHash, slot + 1);
    EXPECT_NE(hash1, hash3);
    
    // Different collateral should give different hash
    COutPoint collateral2(uint256S("0xaaaa"), 2);
    uint256 hash4 = GetPONHash(collateral2, prevBlockHash, slot);
    EXPECT_NE(hash1, hash4);
    
    // Different previous block should give different hash
    uint256 prevBlockHash2 = uint256S("0xbbbb");
    uint256 hash5 = GetPONHash(collateral, prevBlockHash2, slot);
    EXPECT_NE(hash1, hash5);
}

TEST_F(PONTest, SlotCalculation) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int64_t genesisTime = Params().GenesisBlock().nTime;
    
    // Test slot calculation
    // Slot 0 should be at genesis
    uint32_t slot0 = GetSlotNumber(genesisTime, genesisTime, consensusParams);
    EXPECT_EQ(slot0, 0);
    
    // Each slot is nPonTargetSpacing seconds (30 seconds typically)
    int ponTargetSpacing = consensusParams.nPonTargetSpacing;
    uint32_t slot1 = GetSlotNumber(genesisTime + ponTargetSpacing, genesisTime, consensusParams);
    EXPECT_EQ(slot1, 1);
    
    uint32_t slot10 = GetSlotNumber(genesisTime + 10 * ponTargetSpacing, genesisTime, consensusParams);
    EXPECT_EQ(slot10, 10);
}

TEST_F(PONTest, PONDifficultyAdjustmentInitial) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    // Create a mock chain for testing difficulty adjustment
    CBlockIndex* pindexPrev = new CBlockIndex();
    pindexPrev->nHeight = GetPONActivationHeight();
    pindexPrev->nTime = Params().GenesisBlock().nTime + pindexPrev->nHeight * consensusParams.nPonTargetSpacing;
    pindexPrev->nBits = UintToArith256(consensusParams.ponLimit).GetCompact();
    pindexPrev->pprev = nullptr;
    
    // For the first interval after PON activation, should use ponStartLimit
    unsigned int nextBits = GetNextPONWorkRequired(pindexPrev);
    unsigned int ponStartLimitBits = UintToArith256(consensusParams.ponStartLimit).GetCompact();
    
    // Should use the start limit for first interval
    EXPECT_EQ(nextBits, ponStartLimitBits);
    
    delete pindexPrev;
}

TEST_F(PONTest, PONDifficultyAdjustmentWindow) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    int64_t baseTime = Params().GenesisBlock().nTime;
    
    // Build a chain starting from PON activation with perfect timing
    size_t lastBlk = ponHeight + 120; // 120 blocks after PON activation
    std::vector<CBlockIndex> blocks(lastBlk + 1);
    
    // Create pre-PON blocks
    for (int i = 0; i < ponHeight; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = baseTime + i * consensusParams.nPowTargetSpacing;
        blocks[i].nBits = 0x1e7fffff;
        blocks[i].nVersion = CBlockHeader::CURRENT_VERSION;
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }
    
    // Create PON blocks with perfect timing (30-second intervals)
    for (int i = ponHeight; i <= lastBlk; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = blocks[ponHeight - 1].nTime + (i - ponHeight + 1) * consensusParams.nPonTargetSpacing;
        blocks[i].nBits = i == ponHeight ? 
            UintToArith256(consensusParams.ponLimit).GetCompact() : 
            GetNextPONWorkRequired(&blocks[i - 1]);
        blocks[i].nVersion = CBlockHeader::PON_VERSION;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    
    // With perfect timing, difficulty should stabilize
    unsigned int stableDifficulty = blocks[lastBlk].nBits;
    unsigned int previousDifficulty = blocks[lastBlk - 10].nBits;
    
    // Should be very close after stabilization
    arith_uint256 stableTarget, previousTarget;
    stableTarget.SetCompact(stableDifficulty);
    previousTarget.SetCompact(previousDifficulty);
    
    // The difference should be minimal with perfect timing
    arith_uint256 diff = (stableTarget > previousTarget) ? 
        stableTarget - previousTarget : previousTarget - stableTarget;
    arith_uint256 maxDiff = previousTarget / 100; // Allow 1% variation
    EXPECT_LE(diff, maxDiff);
}

TEST_F(PONTest, PONDifficultyAdjustmentFastBlocks) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    int64_t baseTime = Params().GenesisBlock().nTime;
    
    // Build a chain that goes past the first difficulty adjustment
    // Need to go past ponHeight + nPonDifficultyWindow for adjustment to occur
    size_t lastBlk = ponHeight + consensusParams.nPonDifficultyWindow + 10;
    std::vector<CBlockIndex> blocks(lastBlk + 1);
    
    // Create pre-PON blocks
    for (int i = 0; i < ponHeight; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = baseTime + i * consensusParams.nPowTargetSpacing;
        blocks[i].nBits = 0x1e7fffff;
        blocks[i].nVersion = CBlockHeader::CURRENT_VERSION;
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }
    
    // Create PON blocks with fast timing (15-second intervals instead of 30)
    for (int i = ponHeight; i <= lastBlk; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = blocks[ponHeight - 1].nTime + (i - ponHeight + 1) * (consensusParams.nPonTargetSpacing / 2);
        blocks[i].nBits = GetNextPONWorkRequired(&blocks[i - 1]);
        blocks[i].nVersion = CBlockHeader::PON_VERSION;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
        
        // Debug output for key blocks
        if (i == ponHeight || i == ponHeight + 29 || i == ponHeight + 30) {
            std::cout << "Block " << i << " (PON block " << (i - ponHeight + 1) << "):" << std::endl;
            std::cout << "  nBits: 0x" << std::hex << blocks[i].nBits << std::dec << std::endl;
            std::cout << "  Time: " << blocks[i].nTime << " (delta: " << (blocks[i].nTime - blocks[ponHeight - 1].nTime) << ")" << std::endl;
        }
    }
    
    // Check difficulty at the adjustment boundary
    // At ponHeight + nPonDifficultyWindow, difficulty should have adjusted
    arith_uint256 startTarget, adjustedTarget;
    unsigned int startBits = blocks[ponHeight + consensusParams.nPonDifficultyWindow - 1].nBits;
    unsigned int adjustedBits = blocks[ponHeight + consensusParams.nPonDifficultyWindow].nBits;
    startTarget.SetCompact(startBits);
    adjustedTarget.SetCompact(adjustedBits);
    
    // Debug output
    std::cout << "Fast blocks test:" << std::endl;
    std::cout << "  Start bits: 0x" << std::hex << startBits << std::endl;
    std::cout << "  Adjusted bits: 0x" << std::hex << adjustedBits << std::endl;
    std::cout << "  ponStartLimit: 0x" << std::hex << UintToArith256(consensusParams.ponStartLimit).GetCompact() << std::endl;
    std::cout << "  ponLimit: 0x" << std::hex << UintToArith256(consensusParams.ponLimit).GetCompact() << std::endl;
    
    // With fast blocks, target should decrease (harder difficulty)
    EXPECT_LT(adjustedTarget, startTarget);
}

TEST_F(PONTest, PONDifficultyAdjustmentSlowBlocks) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    int ponHeight = GetPONActivationHeight();
    int64_t baseTime = Params().GenesisBlock().nTime;
    
    // Build a chain that goes past the first difficulty adjustment
    size_t lastBlk = ponHeight + consensusParams.nPonDifficultyWindow + 10;
    std::vector<CBlockIndex> blocks(lastBlk + 1);
    
    // Create pre-PON blocks
    for (int i = 0; i < ponHeight; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = baseTime + i * consensusParams.nPowTargetSpacing;
        blocks[i].nBits = 0x1e7fffff;
        blocks[i].nVersion = CBlockHeader::CURRENT_VERSION;
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }
    
    // Create PON blocks with slow timing (60-second intervals instead of 30)
    for (int i = ponHeight; i <= lastBlk; i++) {
        blocks[i].pprev = &blocks[i - 1];
        blocks[i].nHeight = i;
        blocks[i].nTime = blocks[ponHeight - 1].nTime + (i - ponHeight + 1) * (consensusParams.nPonTargetSpacing * 2);
        blocks[i].nBits = GetNextPONWorkRequired(&blocks[i - 1]);
        blocks[i].nVersion = CBlockHeader::PON_VERSION;
        blocks[i].nChainWork = blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]);
    }
    
    // Check difficulty at the adjustment boundary
    arith_uint256 startTarget, adjustedTarget;
    startTarget.SetCompact(blocks[ponHeight + consensusParams.nPonDifficultyWindow - 1].nBits);
    adjustedTarget.SetCompact(blocks[ponHeight + consensusParams.nPonDifficultyWindow].nBits);
    
    // With slow blocks, target should increase (easier difficulty)
    EXPECT_GT(adjustedTarget, startTarget);
    
    // But should not exceed PON limit
    EXPECT_LE(adjustedTarget, UintToArith256(consensusParams.ponLimit));
}

TEST_F(PONTest, PONDifficultyAdjustmentLimits) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& consensusParams = Params().GetConsensus();
    
    // Test that difficulty can't exceed PON limit
    CBlockIndex* pindexPrev = new CBlockIndex();
    pindexPrev->nHeight = GetPONActivationHeight() + 10;
    pindexPrev->nTime = Params().GenesisBlock().nTime + pindexPrev->nHeight * consensusParams.nPonTargetSpacing;
    pindexPrev->nBits = 0x207fffff; // Very easy difficulty
    pindexPrev->pprev = nullptr;
    pindexPrev->nVersion = CBlockHeader::PON_VERSION;
    
    unsigned int nextBits = GetNextPONWorkRequired(pindexPrev);
    
    // Should not exceed PON limit
    arith_uint256 nextTarget;
    nextTarget.SetCompact(nextBits);
    EXPECT_LE(nextTarget, UintToArith256(consensusParams.ponLimit));
    
    delete pindexPrev;
}

TEST_F(PONTest, POWBlockHeaderSerialization) {
    CBlockHeader powBlock;
    powBlock.nVersion = CBlockHeader::CURRENT_VERSION;
    powBlock.hashPrevBlock = uint256S("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    powBlock.hashMerkleRoot = uint256S("0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321");
    powBlock.nTime = 1234567890;
    powBlock.nBits = 0x1d00ffff;
    powBlock.nNonce = uint256S("0xdeadbeef");
    powBlock.nSolution = std::vector<unsigned char>{0x01, 0x02, 0x03, 0x04, 0x05};
    
    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << powBlock;
    
    // Deserialize
    CBlockHeader powBlock2;
    ss >> powBlock2;
    
    // Check all fields match
    EXPECT_EQ(powBlock2.nVersion, powBlock.nVersion);
    EXPECT_EQ(powBlock2.hashPrevBlock, powBlock.hashPrevBlock);
    EXPECT_EQ(powBlock2.hashMerkleRoot, powBlock.hashMerkleRoot);
    EXPECT_EQ(powBlock2.nTime, powBlock.nTime);
    EXPECT_EQ(powBlock2.nBits, powBlock.nBits);
    EXPECT_EQ(powBlock2.nNonce, powBlock.nNonce);
    EXPECT_EQ(powBlock2.nSolution, powBlock.nSolution);
}

// --- Deterministic PON fork choice (ComparePonForkChoice) ------------------------------
// This is the convergence guarantee: competing same-height PON blocks must resolve to the
// same winner on every node (lowest cached PON hash), regardless of arrival order.
//
// Entries score by the resident cached PON hash; an entry whose header data has
// been pruned (pHeaderData == nullptr) must compare exactly like an unpruned
// one, because the comparator may only touch resident fields.

static CBlockIndex MakeLegacyPonIndex(int height, const uint256& ponHash) {
    CBlockIndex idx;                       // SetNull(): pHeaderData == nullptr (pruned shape)
    idx.nVersion = CBlockHeader::PON_VERSION;
    idx.nHeight = height;
    idx.hashPON = ponHash;
    return idx;
}

TEST_F(PONTest, ForkChoiceLowestHashWins) {
    CBlockIndex a = MakeLegacyPonIndex(100, uint256S("0x1111111111111111111111111111111111111111111111111111111111111111"));
    CBlockIndex b = MakeLegacyPonIndex(100, uint256S("0x2222222222222222222222222222222222222222222222222222222222222222"));

    // Whichever hash is lower by uint256 ordering must be preferred (negative result).
    // (The exact ordering direction is irrelevant to convergence; determinism is.)
    bool aLower = (a.hashPON < b.hashPON);
    EXPECT_EQ(ComparePonForkChoice(&a, &b) < 0, aLower);
    EXPECT_EQ(ComparePonForkChoice(&a, &b) > 0, !aLower);
}

TEST_F(PONTest, ForkChoiceAntisymmetricAndDeterministic) {
    CBlockIndex a = MakeLegacyPonIndex(100, uint256S("0x00000000000000000000000000000000000000000000000000000000000000aa"));
    CBlockIndex b = MakeLegacyPonIndex(100, uint256S("0x00000000000000000000000000000000000000000000000000000000000000bb"));

    int ab = ComparePonForkChoice(&a, &b);
    // Antisymmetry: swapping arguments flips the sign — so all nodes agree on the winner.
    EXPECT_EQ(ab, -ComparePonForkChoice(&b, &a));
    // Determinism: same inputs always give the same result.
    EXPECT_EQ(ab, ComparePonForkChoice(&a, &b));
    EXPECT_NE(ab, 0); // distinct hashes are decided, never a tie
}

TEST_F(PONTest, ForkChoiceEqualHashUndecided) {
    uint256 same = uint256S("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CBlockIndex a = MakeLegacyPonIndex(100, same);
    CBlockIndex b = MakeLegacyPonIndex(100, same);
    // Identical PON hash -> no decision; caller falls back to first-seen.
    EXPECT_EQ(ComparePonForkChoice(&a, &b), 0);
}

TEST_F(PONTest, ForkChoicePrunedEntriesMatchUnpruned) {
    const uint256 hashA = uint256S("0x00000000000000000000000000000000000000000000000000000000000000aa");
    const uint256 hashB = uint256S("0x00000000000000000000000000000000000000000000000000000000000000bb");

    // Pruned pair (no header data at all)
    CBlockIndex prunedA = MakeLegacyPonIndex(100, hashA);
    CBlockIndex prunedB = MakeLegacyPonIndex(100, hashB);
    ASSERT_EQ(prunedA.pHeaderData, nullptr);
    int pruned = ComparePonForkChoice(&prunedA, &prunedB);

    // Same pair with header data present (and deliberately mismatched, to
    // prove the comparator ignores it)
    CBlockIndex fullA = MakeLegacyPonIndex(100, hashA);
    CBlockIndex fullB = MakeLegacyPonIndex(100, hashB);
    fullA.AllocateHeaderData();
    fullB.AllocateHeaderData();
    int full = ComparePonForkChoice(&fullA, &fullB);

    EXPECT_EQ(pruned, full);
    EXPECT_LT(pruned, 0);

    fullA.FreeHeaderData();
    fullB.FreeHeaderData();
}

// The order of candidate tips: more chain work is better whatever else differs; PON entries
// of equal work at one height go to the preferred score; what is left goes to the entry
// received first. No entry is worse than itself.
TEST_F(PONTest, CandidateTipOrder) {
    const uint256 low = uint256S("0x01");
    const uint256 high = uint256S("0x02");
    ASSERT_TRUE(low < high);

    CBlockIndex a = MakeLegacyPonIndex(100, low);
    CBlockIndex b = MakeLegacyPonIndex(100, high);
    a.nChainWork = b.nChainWork = arith_uint256(1000);
    a.nSequenceId = 7;
    b.nSequenceId = 3;

    // Equal work, one height: the preferred score, though it was received later.
    ASSERT_LT(ComparePonForkChoice(&a, &b), 0);
    EXPECT_TRUE(IsWorseBlockIndex(&b, &a));
    EXPECT_FALSE(IsWorseBlockIndex(&a, &b));

    // More work wins against a better score and an earlier arrival.
    b.nChainWork = arith_uint256(1001);
    EXPECT_TRUE(IsWorseBlockIndex(&a, &b));
    EXPECT_FALSE(IsWorseBlockIndex(&b, &a));

    // Equal work at different heights: the score is not asked; the one received first.
    b.nChainWork = arith_uint256(1000);
    b.nHeight = a.nHeight + 1;
    EXPECT_TRUE(IsWorseBlockIndex(&a, &b));
    EXPECT_FALSE(IsWorseBlockIndex(&b, &a));

    // Equal work, one height, equal scores: the one received first.
    b.nHeight = a.nHeight;
    b.hashPON = a.hashPON;
    EXPECT_TRUE(IsWorseBlockIndex(&a, &b));
    EXPECT_FALSE(IsWorseBlockIndex(&b, &a));

    EXPECT_FALSE(IsWorseBlockIndex(&a, &a));
}

// --- PON-VRF deterministic fork choice (ComparePonForkChoice) -------------------------
// This is the convergence guarantee: competing same-height VRF blocks must resolve to the
// same winner on every node (lowest VRF output), regardless of arrival order.

static CBlockIndex MakeVrfIndex(int height, const uint256& vrfOut) {
    CBlockIndex idx;                       // SetNull() via default ctor
    idx.nVersion = CBlockHeader::PON_VRF_VERSION;
    idx.nHeight = height;
    idx.hashPON = vrfOut;
    return idx;
}

TEST_F(PONTest, VrfForkChoiceLowestOutputWins) {
    CBlockIndex a = MakeVrfIndex(100, uint256S("0x1111111111111111111111111111111111111111111111111111111111111111"));
    CBlockIndex b = MakeVrfIndex(100, uint256S("0x2222222222222222222222222222222222222222222222222222222222222222"));

    // Whichever output is lower by uint256 ordering must be preferred (negative result).
    // (The exact ordering direction is irrelevant to convergence; determinism is.)
    bool aLower = (a.VrfOutput() < b.VrfOutput());
    EXPECT_EQ(ComparePonForkChoice(&a, &b) < 0, aLower);
    EXPECT_EQ(ComparePonForkChoice(&a, &b) > 0, !aLower);
}

TEST_F(PONTest, VrfForkChoiceAntisymmetricAndDeterministic) {
    CBlockIndex a = MakeVrfIndex(100, uint256S("0x00000000000000000000000000000000000000000000000000000000000000aa"));
    CBlockIndex b = MakeVrfIndex(100, uint256S("0x00000000000000000000000000000000000000000000000000000000000000bb"));

    int ab = ComparePonForkChoice(&a, &b);
    // Antisymmetry: swapping arguments flips the sign — so all nodes agree on the winner.
    EXPECT_EQ(ab, -ComparePonForkChoice(&b, &a));
    // Determinism: same inputs always give the same result.
    EXPECT_EQ(ab, ComparePonForkChoice(&a, &b));
    EXPECT_NE(ab, 0); // distinct outputs are decided, never a tie
}

TEST_F(PONTest, VrfForkChoiceEqualOutputUndecided) {
    uint256 same = uint256S("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CBlockIndex a = MakeVrfIndex(100, same);
    CBlockIndex b = MakeVrfIndex(100, same);
    // Identical VRF output -> no decision; caller falls back to first-seen.
    EXPECT_EQ(ComparePonForkChoice(&a, &b), 0);
}

// --- PON-VRF block-header serialization + hash-commitment -----------------------------

static CBlockHeader MakeVrfHeader() {
    CBlockHeader h;
    h.nVersion = CBlockHeader::PON_VRF_VERSION;
    h.hashPrevBlock = uint256S("0x01");
    h.hashMerkleRoot = uint256S("0x02");
    h.hashFinalSaplingRoot = uint256S("0x03");
    h.nTime = 1700000000;
    h.nBits = 0x1d00ffff;
    h.nodesCollateral = COutPoint(uint256S("0x04"), 1);
    h.nodesVrfOutput = uint256S("0x0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a");
    h.nodesVrfProof = std::vector<unsigned char>(81, 0x77);
    h.vchBlockSig = std::vector<unsigned char>(64, 0x99);
    return h;
}

TEST_F(PONTest, VrfBlockHeaderSerializationRoundTrip) {
    CBlockHeader h = MakeVrfHeader();
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << h;
    CBlockHeader h2;
    ss >> h2;
    EXPECT_EQ(h2.nVersion, h.nVersion);
    EXPECT_EQ(h2.nodesCollateral, h.nodesCollateral);
    EXPECT_EQ(h2.nodesVrfOutput, h.nodesVrfOutput);
    EXPECT_EQ(h2.nodesVrfProof, h.nodesVrfProof);
    EXPECT_EQ(h2.vchBlockSig, h.vchBlockSig);
    EXPECT_EQ(h2.GetHash(), h.GetHash());
}

TEST_F(PONTest, VrfOutputCommittedProofExcludedFromHash) {
    CBlockHeader base = MakeVrfHeader();
    uint256 h0 = base.GetHash();

    // The proof is excluded from the block hash (like the signature): changing it must NOT
    // change the hash — required so CBlockIndex (which omits the proof) recomputes correctly.
    CBlockHeader p = base;
    p.nodesVrfProof = std::vector<unsigned char>(81, 0x11);
    EXPECT_EQ(p.GetHash(), h0);

    // The VRF output IS committed: changing it MUST change the hash (so it is signed/immutable
    // and usable as the deterministic fork-choice key).
    CBlockHeader o = base;
    o.nodesVrfOutput = uint256S("0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    EXPECT_NE(o.GetHash(), h0);
}

// --- Real ECVRF prove/verify path (the same crypto ContextualCheckPONBlockHeader runs) -

TEST_F(PONTest, EcvrfProveVerifyRoundTrip) {
    CKey key;
    key.MakeNewKey(true);
    CPubKey pub = key.GetPubKey();
    uint256 seed = uint256S("0x1111111111111111111111111111111111111111111111111111111111111111");

    std::vector<unsigned char> proof;
    uint256 beta;
    ASSERT_TRUE(ECVRF_Prove(key, pub, seed, proof, beta));
    EXPECT_EQ(proof.size(), 81u);

    // Verify against the same key+seed reproduces the output.
    uint256 beta2;
    EXPECT_TRUE(ECVRF_Verify(pub, seed, proof, beta2));
    EXPECT_EQ(beta2, beta);

    // Tampered proof is rejected.
    std::vector<unsigned char> badProof = proof;
    badProof[40] ^= 0x01;
    uint256 bx;
    EXPECT_FALSE(ECVRF_Verify(pub, seed, badProof, bx));

    // Wrong seed is rejected (binds the output to the epoch seed).
    uint256 by;
    EXPECT_FALSE(ECVRF_Verify(pub, uint256S("0x99"), proof, by));

    // Wrong key is rejected (binds the output to the operator key).
    CKey other;
    other.MakeNewKey(true);
    uint256 bz;
    EXPECT_FALSE(ECVRF_Verify(other.GetPubKey(), seed, proof, bz));

    // Deterministic: proving again yields the identical proof+output (RFC 6979 nonce).
    std::vector<unsigned char> proof2;
    uint256 beta3;
    ASSERT_TRUE(ECVRF_Prove(key, pub, seed, proof2, beta3));
    EXPECT_EQ(proof2, proof);
    EXPECT_EQ(beta3, beta);
}

TEST_F(PONTest, VrfMessagePerNodeUnderSharedOperatorKey) {
    // Operator keys are shared across an owner's fleet in practice. The VRF message must
    // therefore mix in the per-node collateral outpoint: with the key alone, N same-key
    // nodes share one lottery draw and broadcast N identical-priority blocks on a win.
    const Consensus::Params& params = Params().GetConsensus();

    COutPoint collateralA(uint256S("0xaa"), 0);
    COutPoint collateralB(uint256S("0xbb"), 0);
    COutPoint collateralA1(uint256S("0xaa"), 1);

    uint256 msgA = GetPonVrfMessage(NULL, 100, collateralA, params);
    uint256 msgB = GetPonVrfMessage(NULL, 100, collateralB, params);
    uint256 msgA1 = GetPonVrfMessage(NULL, 100, collateralA1, params);

    // Distinct nodes (different txid OR different vout) get distinct messages.
    EXPECT_NE(msgA, msgB);
    EXPECT_NE(msgA, msgA1);

    // Same node, same slot is deterministic; a new slot is a fresh draw.
    EXPECT_EQ(msgA, GetPonVrfMessage(NULL, 100, collateralA, params));
    EXPECT_NE(msgA, GetPonVrfMessage(NULL, 101, collateralA, params));

    // Under ONE shared operator key, distinct messages yield independent VRF outputs,
    // each verifiable against the same pubkey — restoring one draw per node.
    CKey opKey;
    opKey.MakeNewKey(true);
    CPubKey opPub = opKey.GetPubKey();

    std::vector<unsigned char> proofA, proofB;
    uint256 yA, yB;
    ASSERT_TRUE(ECVRF_Prove(opKey, opPub, msgA, proofA, yA));
    ASSERT_TRUE(ECVRF_Prove(opKey, opPub, msgB, proofB, yB));
    EXPECT_NE(yA, yB);

    uint256 yCheck;
    EXPECT_TRUE(ECVRF_Verify(opPub, msgA, proofA, yCheck));
    EXPECT_EQ(yCheck, yA);

    // A proof made for node A does not verify as node B (cross-node replay rejected).
    uint256 yx;
    EXPECT_FALSE(ECVRF_Verify(opPub, msgB, proofA, yx));
}

// Before UPGRADE_PON_VRF a header at the VRF version is refused, whatever its eligibility:
// fork choice scores such a block by a VRF output that nothing has verified.
TEST_F(PONTest, VrfVersionRefusedBeforeActivation) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();

    CBlockIndex prev;
    prev.nHeight = GetPONActivationHeight() + params.nPonDifficultyWindow + 10;   // ponLimit applies
    const int nHeight = prev.nHeight + 1;
    ASSERT_FALSE(IsPONVRFActive(nHeight));

    // A legacy header that meets the target at the easiest difficulty.
    CBlockHeader legacy;
    legacy.nVersion = CBlockHeader::PON_VERSION;
    legacy.hashPrevBlock = uint256S("0x01");
    legacy.nBits = UintToArith256(params.ponLimit).GetCompact();
    legacy.nodesCollateral = COutPoint(uint256S("0x04"), 1);
    bool fEligible = false;
    for (uint32_t t = 0; t < 100000 && !fEligible; t++) {
        legacy.nTime = 1700000000 + t * params.nPonTargetSpacing;
        fEligible = CheckProofOfNode(GetPONHash(legacy), legacy.nBits, params, nHeight);
    }
    ASSERT_TRUE(fEligible);
    EXPECT_TRUE(CheckPONBlockHeader(legacy, &prev, params));

    // The same header at the VRF version, with the smallest output there is.
    CBlockHeader vrf = legacy;
    vrf.nVersion = CBlockHeader::PON_VRF_VERSION;
    vrf.nodesVrfOutput = uint256();
    vrf.nodesVrfProof = std::vector<unsigned char>(81, 0x77);
    ASSERT_TRUE(CheckProofOfNode(GetPONHash(vrf), vrf.nBits, params, nHeight) ||
                CheckProofOfNode(vrf.nodesVrfOutput, vrf.nBits, params, nHeight));
    EXPECT_FALSE(CheckPONBlockHeader(vrf, &prev, params));
}

// With UPGRADE_PON_VRF active a block is in a later slot than its parent: a block in its
// parent's slot is refused, at any offset within the slot, and one in the next slot is
// accepted. An emergency block is held to it too.
TEST_F(PONTest, VrfBlockIsInALaterSlotThanItsParent) {
    SelectParams(CBaseChainParams::LABNET);
    const Consensus::Params& params = Params().GetConsensus();
    const int64_t genesisTime = Params().GenesisBlock().nTime;
    const int64_t spacing = params.nPonTargetSpacing;

    CBlockIndex prev;
    prev.nHeight = 1000;
    const int nHeight = prev.nHeight + 1;
    ASSERT_TRUE(IsPONVRFActive(nHeight));
    const int64_t slotStart = genesisTime + 5000 * spacing;
    prev.nTime = slotStart + 3;

    CBlockHeader h;
    h.nVersion = CBlockHeader::PON_VRF_VERSION;
    h.hashPrevBlock = uint256S("0x01");
    h.nBits = UintToArith256(params.ponLimit).GetCompact();
    h.nodesCollateral = COutPoint(uint256S("0x04"), 1);
    h.nodesVrfOutput = uint256();
    h.nodesVrfProof = std::vector<unsigned char>(81, 0x77);
    ASSERT_TRUE(CheckProofOfNode(h.nodesVrfOutput, h.nBits, params, nHeight));

    EXPECT_FALSE(IsLaterSlotThan(slotStart + 4, &prev, params));
    EXPECT_FALSE(IsLaterSlotThan(slotStart + spacing - 1, &prev, params));
    EXPECT_TRUE(IsLaterSlotThan(slotStart + spacing, &prev, params));

    h.nTime = slotStart + 4;
    EXPECT_FALSE(CheckPONBlockHeader(h, &prev, params));
    h.nTime = slotStart + spacing - 1;
    EXPECT_FALSE(CheckPONBlockHeader(h, &prev, params));
    h.nTime = slotStart + spacing + PON_VRF_FIRST_TURN_SECONDS;
    EXPECT_TRUE(CheckPONBlockHeader(h, &prev, params));
    h.nTime = slotStart + 3 * spacing + 7;
    EXPECT_TRUE(CheckPONBlockHeader(h, &prev, params));

    // The parent at the last second of its slot: the next second is the next slot.
    prev.nTime = slotStart + spacing - 1;
    EXPECT_TRUE(IsLaterSlotThan(slotStart + spacing, &prev, params));
    h.nTime = slotStart + spacing + PON_VRF_FIRST_TURN_SECONDS;
    EXPECT_TRUE(CheckPONBlockHeader(h, &prev, params));

    // An emergency block is held to the same rule.
    CBlockHeader emergency;
    emergency.nVersion = CBlockHeader::PON_VERSION;
    emergency.hashPrevBlock = uint256S("0x01");
    emergency.nBits = h.nBits;
    emergency.nodesCollateral = COutPoint(Params().GetEmergencyCollateralHash(), 0);
    ASSERT_TRUE(IsEmergencyBlock(emergency));
    prev.nTime = slotStart + 3;
    emergency.nTime = slotStart + 4;
    EXPECT_FALSE(CheckPONBlockHeader(emergency, &prev, params));
    emergency.nTime = slotStart + spacing;
    EXPECT_TRUE(CheckPONBlockHeader(emergency, &prev, params));

    SelectParams(CBaseChainParams::MAIN);
}

// The PON-VRF target's arithmetic, against values worked outside this code: the target at
// activation from the confirmed-node count, and an epoch's target from the target before it
// and an epoch's sum.
TEST_F(PONTest, VrfTargetArithmetic) {
    auto bits = [](const arith_uint256& t) { return t.GetCompact(); };

    EXPECT_EQ(bits(PonVrfFirstTarget(1)), 0x2100ffffu);
    EXPECT_EQ(bits(PonVrfFirstTarget(9)), 0x2100ffffu);
    EXPECT_EQ(bits(PonVrfFirstTarget(10)), 0x2100ebc6u);
    EXPECT_EQ(bits(PonVrfFirstTarget(18)), 0x210082fcu);
    EXPECT_EQ(bits(PonVrfFirstTarget(6956)), 0x1f56c5a6u);
    EXPECT_EQ(bits(PonVrfFirstTarget(100000)), 0x1f06092eu);

    const arith_uint256 target = PonVrfFirstTarget(6956);
    EXPECT_EQ(target, PonVrfRoundTarget(target));
    const arith_uint320 wide = WidenTo320(target);

    // No winning output at all: three quarters of the target.
    EXPECT_EQ(bits(PonVrfNextTarget(target, arith_uint320())), 0x1f41143cu);
    // Every slot empty: the sum asks for 9.21 times the target, and twice is the most.
    arith_uint320 empty = wide;
    empty *= PON_VRF_TARGET_EPOCH_SLOTS;
    EXPECT_EQ(bits(PonVrfNextTarget(target, empty)), 0x2000ad8bu);
    // Half the slots empty and the rest with an output of zero: 1.9 times.
    arith_uint320 half = wide;
    half *= PON_VRF_TARGET_EPOCH_SLOTS / 2;
    EXPECT_EQ(bits(PonVrfNextTarget(target, half)), 0x2000a4f9u);
    // The sum that asks for the target itself, floored: one step under it.
    const arith_uint320 neutral = WidenTo320(
        arith_uint256("02354a5273132ddcfa29b19d9a4460bac9cc4cb773e8a6c676691182eb273132"));
    EXPECT_EQ(bits(PonVrfNextTarget(target, neutral)), 0x1f56c5a5u);
    const arith_uint320 odd = WidenTo320(
        arith_uint256("02ffc22b1dbdd887a4d45c4844ef0b657476f7621e9351712113bc2d95d1dbdc"));
    EXPECT_EQ(bits(PonVrfNextTarget(target, odd)), 0x1f5e8ab2u);

    // At the ceiling the target does not rise, and falls by a quarter on a sum of zero.
    const arith_uint256 ceiling = PonVrfFirstTarget(1);
    arith_uint320 ceilingEmpty = WidenTo320(ceiling);
    ceilingEmpty *= PON_VRF_TARGET_EPOCH_SLOTS;
    EXPECT_EQ(bits(PonVrfNextTarget(ceiling, ceilingEmpty)), 0x2100ffffu);
    EXPECT_EQ(bits(PonVrfNextTarget(ceiling, arith_uint320())), 0x2100bfffu);
}

namespace {
// Index entries on labnet for the target's tests: a legacy parent, the activation block, and
// blocks added on any of them, each carrying the nBits the rule gives it.
struct VrfTargetChain {
    std::deque<CBlockIndex> entries;
    const Consensus::Params& params;
    int64_t genesis;
    uint32_t first;     //!< the first slot of the epoch the activation block is in

    VrfTargetChain(uint32_t nBitsFirst) : params(Params().GetConsensus()), genesis(Params().GenesisBlock().nTime), first(1000 * PON_VRF_TARGET_EPOCH_SLOTS)
    {
        const int nActivation = params.vUpgrades[Consensus::UPGRADE_PON_VRF].nActivationHeight;
        CBlockIndex legacy;
        legacy.nHeight = nActivation - 1;
        legacy.nTime = TimeOf(first - 5);
        legacy.nVersion = CBlockHeader::PON_VERSION;
        legacy.nBits = nBitsFirst;
        entries.push_back(legacy);

        CBlockIndex activation;
        activation.pprev = &entries.back();
        activation.nHeight = nActivation;
        activation.nTime = TimeOf(first + 10);
        activation.nVersion = CBlockHeader::PON_VRF_VERSION;
        activation.nBits = nBitsFirst;
        entries.push_back(activation);
    }

    int64_t TimeOf(uint32_t slot) const { return genesis + (int64_t)slot * params.nPonTargetSpacing + 5; }
    //! The first slot of the n-th epoch after the activation block's.
    uint32_t Epoch(uint32_t n) const { return first + n * PON_VRF_TARGET_EPOCH_SLOTS; }
    CBlockIndex* Activation() { return &entries[1]; }
    uint32_t BitsAt(const CBlockIndex* parent, uint32_t slot) const { return GetPonVrfBits(parent, TimeOf(slot), params); }

    CBlockIndex* Add(CBlockIndex* parent, uint32_t slot, const arith_uint256& output,
                     int32_t version = CBlockHeader::PON_VRF_VERSION)
    {
        CBlockIndex entry;
        entry.pprev = parent;
        entry.nHeight = parent->nHeight + 1;
        entry.nTime = TimeOf(slot);
        entry.nVersion = version;
        entry.nBits = BitsAt(parent, slot);
        entry.hashPON = ArithToUint256(output);
        entries.push_back(entry);
        return &entries.back();
    }
};

arith_uint256 TargetFromBits(uint32_t nBits) { arith_uint256 t; t.SetCompact(nBits); return t; }
// The i-th output of the tests' pattern under a target.
arith_uint256 PatternOutput(int i, const arith_uint256& target) { return target * (uint32_t)(i % 5 + 1) / arith_uint256(50); }
} // namespace

// A block carries its parent's target within an epoch; the activation block's target holds
// for its epoch and the two after; then an epoch's target comes from the target before it
// and the sum of the epoch before that, an empty slot counting as that epoch's target. The
// expected values are worked outside this code.
TEST_F(PONTest, VrfTargetFollowsTheEpochBeforeTheLast) {
    SelectParams(CBaseChainParams::LABNET);
    const uint32_t nBitsFirst = PonVrfFirstTarget(6956).GetCompact();
    const arith_uint256 targetFirst = TargetFromBits(nBitsFirst);
    VrfTargetChain chain(nBitsFirst);

    CBlockIndex* tip = chain.Activation();
    EXPECT_EQ(chain.BitsAt(tip, chain.Epoch(0) + 11), nBitsFirst);
    EXPECT_EQ(chain.BitsAt(tip, chain.Epoch(1)), nBitsFirst);
    EXPECT_EQ(chain.BitsAt(tip, chain.Epoch(2) + 59), nBitsFirst);

    // The epoch after the activation block's: 50 slots filled, 10 empty.
    for (int i = 0; i < 50; i++) tip = chain.Add(tip, chain.Epoch(1) + i, PatternOutput(i, targetFirst));
    EXPECT_EQ(tip->nBits, nBitsFirst);
    // The one after: 3 slots filled.
    for (int i = 0; i < 3; i++) tip = chain.Add(tip, chain.Epoch(2) + i, PatternOutput(i, targetFirst));
    EXPECT_EQ(tip->nBits, nBitsFirst);

    // The third epoch after is moved by the first, not by the second.
    EXPECT_EQ(chain.BitsAt(tip, chain.Epoch(3)), 0x1f6c5e11u);
    EXPECT_EQ(chain.BitsAt(tip, chain.Epoch(3) + 59), 0x1f6c5e11u);
    // With no block in the third, the fourth is still reached, moved by the second.
    EXPECT_EQ(chain.BitsAt(tip, chain.Epoch(4)), 0x2000d8bcu);

    const arith_uint256 target3 = TargetFromBits(0x1f6c5e11u);
    CBlockIndex* fork = tip;
    for (int i = 0; i < 10; i++) fork = chain.Add(fork, chain.Epoch(3) + i, PatternOutput(i, target3));
    EXPECT_EQ(fork->nBits, 0x1f6c5e11u);
    CBlockIndex* a = fork;
    for (int i = 10; i < 20; i++) a = chain.Add(a, chain.Epoch(3) + i, PatternOutput(i, target3));

    // An epoch with no block in it: the walk passes over it and its sum is all empty slots.
    EXPECT_EQ(chain.BitsAt(a, chain.Epoch(5)), 0x20014de2u);
    CBlockIndex* later = chain.Add(a, chain.Epoch(5), arith_uint256(0));
    EXPECT_EQ(later->nBits, 0x20014de2u);
    EXPECT_EQ(chain.BitsAt(later, chain.Epoch(6)), 0x20029bc4u);

    // A branch forked inside an epoch carries the same target through the next epoch, and
    // its own after that.
    CBlockIndex* b = fork;
    for (int i = 10; i < 20; i++) b = chain.Add(b, chain.Epoch(3) + i, arith_uint256(0));
    EXPECT_EQ(chain.BitsAt(a, chain.Epoch(4) + 7), 0x2000d8bcu);
    EXPECT_EQ(chain.BitsAt(b, chain.Epoch(4) + 7), 0x2000d8bcu);
    EXPECT_EQ(chain.BitsAt(b, chain.Epoch(5)), 0x20014b63u);

    SelectParams(CBaseChainParams::MAIN);
}

// An emergency block's slot counts in its epoch's sum as a slot no node minted in.
TEST_F(PONTest, VrfTargetCountsAnEmergencyBlocksSlotAsEmpty) {
    SelectParams(CBaseChainParams::LABNET);
    const uint32_t nBitsFirst = PonVrfFirstTarget(6956).GetCompact();
    const arith_uint256 targetFirst = TargetFromBits(nBitsFirst);
    VrfTargetChain chain(nBitsFirst);

    CBlockIndex* tip = chain.Activation();
    for (int i = 0; i < 50; i++) {
        tip = chain.Add(tip, chain.Epoch(1) + i, PatternOutput(i, targetFirst),
                        i == 7 ? CBlockHeader::PON_VERSION : CBlockHeader::PON_VRF_VERSION);
    }
    tip = chain.Add(tip, chain.Epoch(2), arith_uint256(0));
    EXPECT_EQ(chain.BitsAt(tip, chain.Epoch(3)), 0x1f6f7f5fu);

    SelectParams(CBaseChainParams::MAIN);
}

// A block at a PON-VRF height whose nBits is not the rule's is refused, and a target above
// ponLimit is a target: the draw is checked against nBits with no ceiling.
TEST_F(PONTest, VrfBlockCarriesTheRulesTarget) {
    SelectParams(CBaseChainParams::LABNET);
    const Consensus::Params& params = Params().GetConsensus();
    const uint32_t nBitsCeiling = PonVrfFirstTarget(1).GetCompact();
    ASSERT_GT(TargetFromBits(nBitsCeiling), UintToArith256(params.ponLimit));
    EXPECT_TRUE(CheckPonVrfDraw(uint256(), nBitsCeiling));
    EXPECT_FALSE(CheckPonVrfDraw(uint256(), 0));
    EXPECT_FALSE(CheckPonVrfDraw(ArithToUint256(TargetFromBits(0x1f6c5e11u) + 1), 0x1f6c5e11u));
    EXPECT_TRUE(CheckPonVrfDraw(ArithToUint256(TargetFromBits(0x1f6c5e11u)), 0x1f6c5e11u));

    VrfTargetChain chain(nBitsCeiling);
    CBlockIndex* tip = chain.Activation();
    for (int i = 0; i < 4; i++) tip = chain.Add(tip, chain.Epoch(1) + i, arith_uint256(0));
    const uint32_t slot = chain.Epoch(1) + 9;

    CBlockHeader h;
    h.nVersion = CBlockHeader::PON_VRF_VERSION;
    h.nTime = chain.TimeOf(slot);
    h.nodesCollateral = COutPoint(uint256S("0x04"), 1);
    h.nodesVrfOutput = uint256();
    h.nodesVrfProof = std::vector<unsigned char>(81, 0x77);
    SetMockTime(h.nTime);

    h.nBits = nBitsCeiling;
    EXPECT_TRUE(CheckPONBlockHeader(h, tip, params));
    CValidationState right;
    ContextualCheckBlockHeader(h, right, Params(), tip);
    EXPECT_NE(right.GetRejectReason(), "bad-pon-diffbits");
    EXPECT_NE(right.GetRejectReason(), "bad-pon-header");

    h.nBits = PonVrfFirstTarget(6956).GetCompact();
    CValidationState wrong;
    EXPECT_FALSE(ContextualCheckBlockHeader(h, wrong, Params(), tip));
    EXPECT_EQ(wrong.GetRejectReason(), "bad-pon-diffbits");

    SetMockTime(0);
    SelectParams(CBaseChainParams::MAIN);
}

// The work of a block at a PON-VRF height, against values worked outside this code: twice the
// proof of its target for an output of zero, once for an output at the target, and for an
// emergency block the most. An index entry weighs so from its resident fields; below the
// PON-VRF height a PON block weighs 2^40.
TEST_F(PONTest, VrfBlockWorkGradesTheDrawOverTheTarget) {
    const uint32_t nBits = PonVrfFirstTarget(6956).GetCompact();
    const arith_uint256 target = TargetFromBits(nBits);

    EXPECT_EQ(PonVrfBlockWork(arith_uint256(0), nBits, false), arith_uint256("05e688407d160000"));
    EXPECT_EQ(PonVrfBlockWork(target / 2, nBits, false), arith_uint256("046ce6305dd08000"));
    EXPECT_EQ(PonVrfBlockWork(target - 1, nBits, false), arith_uint256("02f344203e8b0000"));
    EXPECT_EQ(PonVrfBlockWork(target, nBits, false), arith_uint256("02f344203e8b0000"));
    EXPECT_EQ(PonVrfBlockWork(target, nBits, true), arith_uint256("05e688407d160000"));

    const uint32_t nBitsCeiling = PonVrfFirstTarget(1).GetCompact();
    EXPECT_EQ(PonVrfBlockWork(TargetFromBits(nBitsCeiling) / 3, nBitsCeiling, false), arith_uint256("01aaabaaabaaaa"));
    EXPECT_EQ(PonVrfBlockWork(arith_uint256(0), 0, false), arith_uint256(0));

    // A looser target never makes a draw weigh more.
    const arith_uint256 output = target / 2;
    const uint32_t nBitsLooser = arith_uint256(target * 3 / 2).GetCompact();
    EXPECT_LT(PonVrfBlockWork(output, nBitsLooser, false), PonVrfBlockWork(output, nBits, false));

    SelectParams(CBaseChainParams::LABNET);
    CBlockIndex entry;
    entry.nHeight = 1000;
    ASSERT_TRUE(IsPONVRFActive(entry.nHeight));
    entry.nVersion = CBlockHeader::PON_VRF_VERSION;
    entry.nBits = nBits;
    entry.hashPON = ArithToUint256(target / 2);
    EXPECT_EQ(GetBlockProof(entry), arith_uint256("046ce6305dd08000"));
    entry.nVersion = CBlockHeader::PON_VERSION;     // an emergency block
    EXPECT_EQ(GetBlockProof(entry), arith_uint256("05e688407d160000"));

    SelectParams(CBaseChainParams::MAIN);
    CBlockIndex legacy;
    legacy.nHeight = GetPONActivationHeight() + 10;
    ASSERT_FALSE(IsPONVRFActive(legacy.nHeight));
    legacy.nVersion = CBlockHeader::PON_VERSION;
    legacy.nBits = nBits;
    EXPECT_EQ(GetBlockProof(legacy), arith_uint256(arith_uint256(1) << 40));
}

// Between two entries at PON-VRF heights with the same draw the lower block hash is
// preferred, whichever is asked first; below the PON-VRF height it stays undecided.
TEST_F(PONTest, VrfEqualDrawsGoToTheLowerBlockHash) {
    SelectParams(CBaseChainParams::LABNET);
    const uint256 draw = uint256S("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const uint256 lower = uint256S("0x01");
    const uint256 higher = uint256S("0x02");
    ASSERT_TRUE(lower < higher);

    CBlockIndex a, b;
    a.nHeight = b.nHeight = 1000;
    ASSERT_TRUE(IsPONVRFActive(a.nHeight));
    a.nVersion = b.nVersion = CBlockHeader::PON_VRF_VERSION;
    a.hashPON = b.hashPON = draw;
    a.phashBlock = &lower;
    b.phashBlock = &higher;
    EXPECT_LT(ComparePonForkChoice(&a, &b), 0);
    EXPECT_GT(ComparePonForkChoice(&b, &a), 0);

    // A better draw is preferred whatever the hashes.
    b.hashPON = uint256S("0x0023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    ASSERT_TRUE(b.hashPON < a.hashPON);
    EXPECT_GT(ComparePonForkChoice(&a, &b), 0);

    SelectParams(CBaseChainParams::MAIN);
    CBlockIndex c, d;
    c.nHeight = d.nHeight = GetPONActivationHeight() + 10;
    ASSERT_FALSE(IsPONVRFActive(c.nHeight));
    c.nVersion = d.nVersion = CBlockHeader::PON_VERSION;
    c.hashPON = d.hashPON = draw;
    c.phashBlock = &lower;
    d.phashBlock = &higher;
    EXPECT_EQ(ComparePonForkChoice(&c, &d), 0);
}

// At PON-VRF heights candidate tips of equal work are ordered by draw and then by block
// hash at any two heights, ahead of the order they were received in; more work still wins.
TEST_F(PONTest, VrfCandidateTipOrder) {
    SelectParams(CBaseChainParams::LABNET);
    const uint256 lowHash = uint256S("0x01");
    const uint256 highHash = uint256S("0x02");
    const uint256 better = uint256S("0x0023456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    const uint256 worse = uint256S("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    ASSERT_TRUE(better < worse);

    CBlockIndex a, b;
    a.nHeight = 1000;
    b.nHeight = 1001;
    ASSERT_TRUE(IsPONVRFActive(a.nHeight));
    a.nVersion = b.nVersion = CBlockHeader::PON_VRF_VERSION;
    a.nChainWork = b.nChainWork = arith_uint256(1000);
    a.phashBlock = &highHash;
    b.phashBlock = &lowHash;
    a.hashPON = better;
    b.hashPON = worse;
    a.nSequenceId = 7;      // received later
    b.nSequenceId = 3;

    // The better draw, at another height and received later.
    EXPECT_TRUE(IsWorseBlockIndex(&b, &a));
    EXPECT_FALSE(IsWorseBlockIndex(&a, &b));

    // Equal draws: the lower block hash.
    a.hashPON = worse;
    EXPECT_TRUE(IsWorseBlockIndex(&a, &b));
    EXPECT_FALSE(IsWorseBlockIndex(&b, &a));

    // More work wins against a better draw and a lower hash.
    a.hashPON = better;
    a.phashBlock = &lowHash;
    b.phashBlock = &highHash;
    b.nChainWork = arith_uint256(1001);
    EXPECT_TRUE(IsWorseBlockIndex(&a, &b));
    EXPECT_FALSE(IsWorseBlockIndex(&b, &a));

    SelectParams(CBaseChainParams::MAIN);
}

// A PON-VRF block is not stamped before its draw's turn: four seconds into its slot for the
// best draws and a second later for each twentieth of the target. A block a second early is
// refused and one on its turn is not. An emergency block has no draw and no turn.
TEST_F(PONTest, VrfBlockWaitsItsTurn) {
    SelectParams(CBaseChainParams::LABNET);
    const Consensus::Params& params = Params().GetConsensus();
    const uint32_t nBits = PonVrfFirstTarget(6956).GetCompact();
    const arith_uint256 target = TargetFromBits(nBits);
    const arith_uint256 step = target / 20 + 1;

    EXPECT_EQ(PonVrfTurnSeconds(arith_uint256(0), nBits), 4u);
    EXPECT_EQ(PonVrfTurnSeconds(step - 1, nBits), 4u);
    EXPECT_EQ(PonVrfTurnSeconds(step, nBits), 5u);
    EXPECT_EQ(PonVrfTurnSeconds(step * 10, nBits), 14u);
    EXPECT_EQ(PonVrfTurnSeconds(target, nBits), 23u);

    CBlockIndex prev;
    prev.nHeight = 1000;
    ASSERT_TRUE(IsPONVRFActive(prev.nHeight + 1));
    const uint32_t slot = 5000;
    const int64_t slotStart = GetPonSlotStart(slot, params);
    EXPECT_EQ(GetSlotNumber(slotStart, Params().GenesisBlock().nTime, params), slot);
    EXPECT_EQ(GetSlotNumber(slotStart - 1, Params().GenesisBlock().nTime, params), slot - 1);
    prev.nTime = slotStart - 10;

    CBlockHeader h;
    h.nVersion = CBlockHeader::PON_VRF_VERSION;
    h.nBits = nBits;
    h.nodesCollateral = COutPoint(uint256S("0x04"), 1);
    h.nodesVrfProof = std::vector<unsigned char>(81, 0x77);

    h.nodesVrfOutput = uint256();
    h.nTime = slotStart + 3;
    EXPECT_FALSE(CheckPONBlockHeader(h, &prev, params));
    h.nTime = slotStart + 4;
    EXPECT_TRUE(CheckPONBlockHeader(h, &prev, params));

    h.nodesVrfOutput = ArithToUint256(step * 10);
    h.nTime = slotStart + 13;
    EXPECT_FALSE(CheckPONBlockHeader(h, &prev, params));
    h.nTime = slotStart + 14;
    EXPECT_TRUE(CheckPONBlockHeader(h, &prev, params));

    CBlockHeader emergency;
    emergency.nVersion = CBlockHeader::PON_VERSION;
    emergency.nBits = nBits;
    emergency.nodesCollateral = COutPoint(Params().GetEmergencyCollateralHash(), 0);
    emergency.nTime = slotStart;
    EXPECT_TRUE(CheckPONBlockHeader(emergency, &prev, params));

    SelectParams(CBaseChainParams::MAIN);
}

// A node keeps the best six claims of a slot: a claim is kept when it is new and among them,
// the worst gives way to a better one, and a collateral claims a slot once.
TEST_F(PONTest, VrfClaimsKeepTheBestSix) {
    CPonClaimPool pool;
    const uint32_t slot = 5000;
    auto collateral = [](int i) { return COutPoint(uint256S("0x04"), i); };

    for (int i = 0; i < 6; i++) {
        EXPECT_TRUE(pool.Add(slot, collateral(i), arith_uint256(100 + 10 * i)));
    }
    EXPECT_TRUE(pool.Have(slot, collateral(5)));
    EXPECT_FALSE(pool.Add(slot, collateral(3), arith_uint256(1)));      // claimed already
    EXPECT_FALSE(pool.Add(slot, collateral(6), arith_uint256(151)));    // worse than all six
    EXPECT_FALSE(pool.Have(slot, collateral(6)));

    EXPECT_TRUE(pool.Add(slot, collateral(7), arith_uint256(105)));     // better than the worst
    EXPECT_TRUE(pool.Have(slot, collateral(7)));
    EXPECT_FALSE(pool.Have(slot, collateral(5)));                       // the worst gave way

    const std::vector<arith_uint256> better = pool.BetterThan(slot, arith_uint256(120));
    ASSERT_EQ(better.size(), 3u);
    EXPECT_EQ(better[0], arith_uint256(100));
    EXPECT_EQ(better[1], arith_uint256(105));
    EXPECT_EQ(better[2], arith_uint256(110));
    EXPECT_TRUE(pool.BetterThan(slot, arith_uint256(100)).empty());
    EXPECT_TRUE(pool.BetterThan(slot + 1, arith_uint256(120)).empty());

    // Another slot is its own six, and a slot that has passed is forgotten.
    EXPECT_TRUE(pool.Add(slot + 1, collateral(3), arith_uint256(999)));
    pool.Forget(slot + 1);
    EXPECT_FALSE(pool.Have(slot, collateral(0)));
    EXPECT_TRUE(pool.Have(slot + 1, collateral(3)));
}

// A node mints at its own turn when it has heard no better claim, and gives each better
// claim four seconds after that claim's turn, or after the one before it.
TEST_F(PONTest, VrfMinterWaitsForBetterClaims) {
    EXPECT_EQ(PonVrfMintSecond(10, {}), 10u);
    EXPECT_EQ(PonVrfMintSecond(10, {4}), 10u);          // the better claim's four seconds are up
    EXPECT_EQ(PonVrfMintSecond(5, {4}), 8u);
    EXPECT_EQ(PonVrfMintSecond(4, {4, 4}), 12u);        // two better claims: two turns
    EXPECT_EQ(PonVrfMintSecond(5, {4, 9}), 13u);
    EXPECT_EQ(PonVrfMintSecond(23, {4, 4, 4}), 23u);
}

// A node waiting to mint mints from its time on, hands the slot back when the tip it drew on
// has moved, and mints nothing once the minter is stopping.
TEST_F(PONTest, VrfMinterStepsThroughItsWait) {
    EXPECT_TRUE(PonVrfMinterStep(99, 100, false, false) == PonMinterStep::WAIT);
    EXPECT_TRUE(PonVrfMinterStep(100, 100, false, false) == PonMinterStep::MINT);
    EXPECT_TRUE(PonVrfMinterStep(99, 100, true, false) == PonMinterStep::TIP_MOVED);
    EXPECT_TRUE(PonVrfMinterStep(100, 100, true, false) == PonMinterStep::MINT);   // the caller checks the tip
    EXPECT_TRUE(PonVrfMinterStep(99, 100, false, true) == PonMinterStep::STOP);    // stopped before its time
    EXPECT_TRUE(PonVrfMinterStep(100, 100, false, true) == PonMinterStep::STOP);
    EXPECT_TRUE(PonVrfMinterStep(99, 100, true, true) == PonMinterStep::STOP);
}

// A node that has started mints once its tip has moved to a block of this slot or the one
// before, and without one after the start wait.
TEST_F(PONTest, MinterStartsOnALiveTip) {
    const uint32_t started = 1000;
    EXPECT_FALSE(PonMinterMayStart(false, 999, 1000, started));             // the stored tip, however recent
    EXPECT_FALSE(PonMinterMayStart(true, 900, 1001, started));              // still syncing: the tip is old
    EXPECT_FALSE(PonMinterMayStart(true, 999, 1001, started));              // two slots behind
    EXPECT_TRUE(PonMinterMayStart(true, 1000, 1001, started));              // the block of the slot before
    EXPECT_TRUE(PonMinterMayStart(true, 1001, 1001, started));              // the block of this slot
    EXPECT_FALSE(PonMinterMayStart(false, 999, started + PON_MINTER_START_WAIT_SLOTS - 1, started));
    EXPECT_TRUE(PonMinterMayStart(false, 999, started + PON_MINTER_START_WAIT_SLOTS, started));
    EXPECT_TRUE(PonMinterMayStart(true, 900, started + PON_MINTER_START_WAIT_SLOTS, started));
}

// An emergency block has no draw and passes under any target it carries; a node's block is
// held to its draw, by the rule of its version.
TEST_F(PONTest, BlockDrawIsCheckedByItsKind) {
    const Consensus::Params& params = Params().GetConsensus();
    const int nHeight = params.vUpgrades[Consensus::UPGRADE_PON].nActivationHeight + params.nPonDifficultyWindow;

    CBlockHeader block;
    block.nVersion = CBlockHeader::PON_VERSION;
    block.nBits = 0x2100ffff;                                           // above ponLimit
    block.nodesCollateral = COutPoint(Params().GetEmergencyCollateralHash(), 0);
    EXPECT_TRUE(CheckPonBlockDraw(block, params));
    EXPECT_TRUE(CheckPonBlockDraw(block, params, nHeight));

    block.nodesCollateral.n = 1;                                        // a node's block
    EXPECT_FALSE(CheckPonBlockDraw(block, params));
    EXPECT_FALSE(CheckPonBlockDraw(block, params, nHeight));

    block.nVersion = CBlockHeader::PON_VRF_VERSION;
    arith_uint256 target;
    target.SetCompact(block.nBits);
    block.nodesVrfOutput = ArithToUint256(target);
    EXPECT_TRUE(CheckPonBlockDraw(block, params));                      // a VRF target has no ceiling
    block.nBits = 0x2000ffff;
    EXPECT_FALSE(CheckPonBlockDraw(block, params));                     // the same output over a tighter target
}

namespace {
// A labnet chain from genesis to a tip above the activation block, one block a slot, every
// entry with a hash: enough behind the tip for an epoch seed.
struct VrfClaimChain {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> entries;
    uint32_t slotOfGenesis;

    VrfClaimChain(int nTip, uint32_t nBits) : hashes(nTip + 1), entries(nTip + 1), slotOfGenesis(1000 * PON_VRF_TARGET_EPOCH_SLOTS)
    {
        const Consensus::Params& params = Params().GetConsensus();
        const int nActivation = params.vUpgrades[Consensus::UPGRADE_PON_VRF].nActivationHeight;
        for (int h = 0; h <= nTip; h++) {
            hashes[h] = ArithToUint256(arith_uint256(7000 + h));
            entries[h].nHeight = h;
            entries[h].phashBlock = &hashes[h];
            entries[h].pprev = h ? &entries[h - 1] : nullptr;
            entries[h].nTime = GetPonSlotStart(slotOfGenesis + h, params) + 5;
            entries[h].nBits = nBits;
            entries[h].nVersion = h >= nActivation ? CBlockHeader::PON_VRF_VERSION : CBlockHeader::PON_VERSION;
            entries[h].hashPON = ArithToUint256(arith_uint256(9000 + h));
        }
    }
    const CBlockIndex* Tip() const { return &entries.back(); }
    uint32_t NextSlot() const { return slotOfGenesis + entries.size(); }
};
} // namespace

// A claim is kept when its proof gives its output under the key of a confirmed node, for
// the slot the clock is in or the next within two seconds, and the output is at or under
// the target; each other claim is turned away for its own reason.
TEST_F(PONTest, VrfClaimIsCheckedBeforeItIsKept) {
    SelectParams(CBaseChainParams::LABNET);
    const Consensus::Params& params = Params().GetConsensus();
    const uint32_t nBitsCeiling = PonVrfFirstTarget(1).GetCompact();
    const int nTip = params.vUpgrades[Consensus::UPGRADE_PON_VRF].nActivationHeight + 5;
    VrfClaimChain chain(nTip, nBitsCeiling);
    ASSERT_TRUE(IsPONVRFActive(chain.Tip()->nHeight + 1));
    const uint32_t slot = chain.NextSlot();
    const int64_t slotStart = GetPonSlotStart(slot, params);

    CKey key;
    key.MakeNewKey(true);
    const CPubKey pub = key.GetPubKey();
    const COutPoint collateral(uint256S("0xc1a1"), 0);
    FluxnodeCacheData node;
    node.pubKey = pub;
    {
        LOCK(g_fluxnodeCache.cs);
        g_fluxnodeCache.mapConfirmedFluxnodeData[collateral] = node;
    }

    CPonClaim claim;
    claim.slot = slot;
    claim.collateral = collateral;
    ASSERT_TRUE(ECVRF_Prove(key, pub, GetPonVrfMessage(chain.Tip(), slot, collateral, params), claim.proof, claim.output));

    {
        CPonClaimPool pool;
        EXPECT_EQ(AcceptPonClaim(claim, chain.Tip(), slotStart + 1, params, pool), PonClaimResult::KEPT);
        EXPECT_TRUE(pool.Have(slot, collateral));
        EXPECT_EQ(AcceptPonClaim(claim, chain.Tip(), slotStart + 1, params, pool), PonClaimResult::HELD);
        EXPECT_STREQ(PonClaimResultName(PonClaimResult::KEPT), "kept");
        EXPECT_STREQ(PonClaimResultName(PonClaimResult::HELD), "held already");
    }
    {
        // The slot before, two seconds from this one's start, and not three.
        CPonClaimPool pool;
        EXPECT_EQ(AcceptPonClaim(claim, chain.Tip(), slotStart - 3, params, pool), PonClaimResult::WRONG_SLOT);
        EXPECT_EQ(AcceptPonClaim(claim, chain.Tip(), slotStart - 2, params, pool), PonClaimResult::KEPT);
    }
    {
        CPonClaimPool pool;
        EXPECT_EQ(AcceptPonClaim(claim, chain.Tip(), slotStart + params.nPonTargetSpacing, params, pool), PonClaimResult::WRONG_SLOT);

        CPonClaim shortProof = claim;
        shortProof.proof.pop_back();
        EXPECT_EQ(AcceptPonClaim(shortProof, chain.Tip(), slotStart + 1, params, pool), PonClaimResult::BAD_PROOF_SIZE);

        CPonClaim stranger = claim;
        stranger.collateral = COutPoint(uint256S("0xc1a2"), 0);
        EXPECT_EQ(AcceptPonClaim(stranger, chain.Tip(), slotStart + 1, params, pool), PonClaimResult::UNCONFIRMED);

        CPonClaim otherOutput = claim;
        otherOutput.output = ArithToUint256(UintToArith256(claim.output) + 1);
        EXPECT_EQ(AcceptPonClaim(otherOutput, chain.Tip(), slotStart + 1, params, pool), PonClaimResult::BAD_PROOF);

        CPonClaim otherSlot = claim;
        otherSlot.slot = slot + 1;
        EXPECT_EQ(AcceptPonClaim(otherSlot, chain.Tip(), slotStart + params.nPonTargetSpacing, params, pool), PonClaimResult::BAD_PROOF);

        // Before the PON-VRF height.
        EXPECT_EQ(AcceptPonClaim(claim, &chain.entries[100], slotStart + 1, params, pool), PonClaimResult::NOT_ACTIVE);
        EXPECT_FALSE(pool.Have(slot, collateral));
    }
    {
        // A target the output is over: the same chain, the same seed, tighter nBits.
        VrfClaimChain tight(nTip, arith_uint256(arith_uint256(1) << 200).GetCompact());
        CPonClaimPool pool;
        EXPECT_EQ(AcceptPonClaim(claim, tight.Tip(), slotStart + 1, params, pool), PonClaimResult::NOT_ELIGIBLE);
    }
    {
        CPonClaimPool pool;
        for (int i = 0; i < 6; i++) pool.Add(slot, COutPoint(uint256S("0x04"), i), arith_uint256(i));
        EXPECT_EQ(AcceptPonClaim(claim, chain.Tip(), slotStart + 1, params, pool), PonClaimResult::NOT_AMONG_BEST);
    }

    {
        LOCK(g_fluxnodeCache.cs);
        g_fluxnodeCache.mapConfirmedFluxnodeData.erase(collateral);
    }
    SelectParams(CBaseChainParams::MAIN);
}

// With UPGRADE_PON_VRF active a block stamped more than PON_VRF_MAX_AHEAD_SECONDS ahead of the
// system clock is refused as too new, whatever its version; one stamped within it is not
// refused for its time. Before activation the bound does not apply.
TEST_F(PONTest, VrfBlockIsNotAheadOfTheClock) {
    EXPECT_FALSE(IsStampedAheadOfClock(1000 + PON_VRF_MAX_AHEAD_SECONDS, 1000));
    EXPECT_TRUE(IsStampedAheadOfClock(1001 + PON_VRF_MAX_AHEAD_SECONDS, 1000));

    SelectParams(CBaseChainParams::LABNET);
    const int64_t now = Params().GenesisBlock().nTime + 5000 * Params().GetConsensus().nPonTargetSpacing + 7;
    SetMockTime(now);

    CBlockIndex prev;
    prev.nHeight = 1000;
    prev.nTime = now - 60;
    ASSERT_TRUE(IsPONVRFActive(prev.nHeight + 1));

    for (int32_t version : {CBlockHeader::PON_VERSION, CBlockHeader::PON_VRF_VERSION}) {
        CBlockHeader h;
        h.nVersion = version;
        h.nodesVrfProof = std::vector<unsigned char>(81, 0x77);

        h.nTime = now + PON_VRF_MAX_AHEAD_SECONDS + 1;
        CValidationState ahead;
        EXPECT_FALSE(ContextualCheckBlockHeader(h, ahead, Params(), &prev));
        EXPECT_EQ(ahead.GetRejectReason(), "time-too-new") << "version " << version;

        h.nTime = now + PON_VRF_MAX_AHEAD_SECONDS;
        CValidationState within;
        ContextualCheckBlockHeader(h, within, Params(), &prev);
        EXPECT_NE(within.GetRejectReason(), "time-too-new") << "version " << version;
    }

    // Before activation: mainnet, where a legacy block 200 s ahead is not refused here.
    SelectParams(CBaseChainParams::MAIN);
    CBlockIndex legacyPrev;
    legacyPrev.nHeight = GetPONActivationHeight() + 100;
    legacyPrev.nTime = now - 60;
    ASSERT_FALSE(IsPONVRFActive(legacyPrev.nHeight + 1));
    CBlockHeader legacy;
    legacy.nVersion = CBlockHeader::PON_VERSION;
    legacy.nTime = now + 200;
    CValidationState state;
    ContextualCheckBlockHeader(legacy, state, Params(), &legacyPrev);
    EXPECT_NE(state.GetRejectReason(), "time-too-new");

    SetMockTime(0);
}

// Before UPGRADE_PON_VRF a block may share its parent's slot.
TEST_F(PONTest, LegacyBlockMayShareItsParentsSlot) {
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();
    const int64_t genesisTime = Params().GenesisBlock().nTime;

    CBlockIndex prev;
    prev.nHeight = GetPONActivationHeight() + params.nPonDifficultyWindow + 10;
    const int nHeight = prev.nHeight + 1;
    ASSERT_FALSE(IsPONVRFActive(nHeight));

    CBlockHeader legacy;
    legacy.nVersion = CBlockHeader::PON_VERSION;
    legacy.hashPrevBlock = uint256S("0x01");
    legacy.nBits = UintToArith256(params.ponLimit).GetCompact();
    legacy.nodesCollateral = COutPoint(uint256S("0x04"), 1);
    bool fEligible = false;
    for (uint32_t t = 0; t < 100000 && !fEligible; t++) {
        legacy.nTime = genesisTime + (9000000 + t) * params.nPonTargetSpacing + 20;
        fEligible = CheckProofOfNode(GetPONHash(legacy), legacy.nBits, params, nHeight);
    }
    ASSERT_TRUE(fEligible);
    prev.nTime = legacy.nTime - 15;   // the same slot, 15 s earlier
    ASSERT_FALSE(IsLaterSlotThan(legacy.nTime, &prev, params));
    EXPECT_TRUE(CheckPONBlockHeader(legacy, &prev, params));
}

// getheaders serves a header rebuilt from the block index, and CheckPONBlockHeader refuses a
// VRF header whose proof is not 81 bytes: the proof is carried by the index entry and by its
// record on disk.
TEST_F(PONTest, VrfProofSurvivesBlockIndexRoundTrip) {
    CBlockHeader original = MakeVrfHeader();
    ASSERT_EQ(original.nodesVrfProof.size(), 81u);

    CBlockIndex index(original);
    uint256 blockHash = original.GetHash();
    index.phashBlock = &blockHash;
    CBlockHeader relayed = index.GetBlockHeader();
    EXPECT_EQ(relayed.nodesVrfOutput, original.nodesVrfOutput);
    EXPECT_EQ(relayed.nodesVrfProof, original.nodesVrfProof);

    CBlockIndex copy(index);
    EXPECT_EQ(copy.GetBlockHeader().nodesVrfProof, original.nodesVrfProof);

    CDiskBlockIndex disk(&index);
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << disk;
    CDiskBlockIndex loaded;
    ss >> loaded;
    ASSERT_NE(loaded.pHeaderData, nullptr);
    EXPECT_EQ(loaded.VrfOutput(), original.nodesVrfOutput);
    EXPECT_EQ(loaded.pHeaderData->nodesVrfProof, original.nodesVrfProof);
}

TEST_F(PONTest, MixedVersionForkChoiceDeterministic) {
    // A legacy block and a VRF block competing at the same height (the
    // activation-boundary fork shape): each scores by its own resident value.
    CBlockIndex legacy = MakeLegacyPonIndex(100, uint256S("0x00000000000000000000000000000000000000000000000000000000000000aa"));
    CBlockIndex vrf = MakeVrfIndex(100, uint256S("0x00000000000000000000000000000000000000000000000000000000000000bb"));

    int lv = ComparePonForkChoice(&legacy, &vrf);
    EXPECT_LT(lv, 0);                                    // lower score (legacy aa) preferred
    EXPECT_EQ(lv, -ComparePonForkChoice(&vrf, &legacy)); // antisymmetric
    EXPECT_EQ(lv, ComparePonForkChoice(&legacy, &vrf));  // deterministic
}

// A v101 (PON-VRF) block commits nodesVrfOutput to its block hash, so the
// hand-written CBlockIndex copy operations MUST carry it. The serialization
// write path builds CDiskBlockIndex(*pindex) through the copy constructor, so
// an omitted field is persisted as zero and the entry fails its hash check on
// the next startup. Guards against the copy ctor / operator= dropping it.
TEST_F(PONTest, VrfOutputSurvivesCBlockIndexCopy) {
    const uint256 vrf = uint256S("0x00000000000000000000000000000000000000000000000000000000000000aa");
    CBlockIndex original = MakeVrfIndex(100, vrf);
    ASSERT_EQ(original.VrfOutput(), vrf);

    CBlockIndex copyCtor(original);
    EXPECT_EQ(copyCtor.VrfOutput(), vrf) << "CBlockIndex copy constructor dropped nodesVrfOutput";

    CBlockIndex assigned;
    assigned = original;
    EXPECT_EQ(assigned.VrfOutput(), vrf) << "CBlockIndex operator= dropped nodesVrfOutput";
}

// The epoch seed is taken from the VRF outputs of its window, not the block hashes: a block
// hash covers the transactions its producer chose, a VRF output does not.
namespace {
struct SeedChain {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> entries;

    // Heights 0..nBlocks-1; VRF blocks from nVrfFrom.
    SeedChain(int nBlocks, int nVrfFrom) : hashes(nBlocks), entries(nBlocks) {
        for (int h = 0; h < nBlocks; h++) {
            hashes[h] = ArithToUint256(arith_uint256(1000 + h));
            entries[h].nHeight = h;
            entries[h].phashBlock = &hashes[h];
            entries[h].pprev = h ? &entries[h - 1] : nullptr;
            entries[h].nVersion = h >= nVrfFrom ? CBlockHeader::PON_VRF_VERSION : CBlockHeader::PON_VERSION;
            entries[h].hashPON = h >= nVrfFrom ? ArithToUint256(arith_uint256(5000 + h)) : uint256();
        }
    }
    uint256 Seed() const { return GetEpochSeed(&entries.back(), Params().GetConsensus()); }
};
}

TEST_F(PONTest, EpochSeedIsTakenFromVrfOutputs) {
    // The block after height 239 is 240, epoch 4: its window is heights 180 down to 121.
    SeedChain base(240, 0);
    const uint256 seed = base.Seed();
    EXPECT_NE(seed, Params().GenesisBlock().GetHash());

    // Another block hash at the top of the window, the same VRF output: the same seed.
    SeedChain otherHash(240, 0);
    otherHash.hashes[180] = ArithToUint256(arith_uint256(999999));
    EXPECT_EQ(otherHash.Seed(), seed);

    // Another VRF output anywhere in the window: another seed.
    SeedChain otherOutput(240, 0);
    otherOutput.entries[121].hashPON = ArithToUint256(arith_uint256(999999));
    EXPECT_NE(otherOutput.Seed(), seed);

    // Outside the window, neither matters.
    SeedChain outside(240, 0);
    outside.entries[120].hashPON = ArithToUint256(arith_uint256(999999));
    outside.entries[181].hashPON = ArithToUint256(arith_uint256(999999));
    EXPECT_EQ(outside.Seed(), seed);
}

TEST_F(PONTest, EpochSeedUsesTheHashOfABlockWithoutAnOutput) {
    // VRF from height 150: the window 121..180 holds legacy blocks 121..149.
    SeedChain base(240, 150);
    const uint256 seed = base.Seed();

    SeedChain legacyHash(240, 150);
    legacyHash.hashes[130] = ArithToUint256(arith_uint256(999999));
    EXPECT_NE(legacyHash.Seed(), seed);

    SeedChain vrfHash(240, 150);
    vrfHash.hashes[170] = ArithToUint256(arith_uint256(999999));
    EXPECT_EQ(vrfHash.Seed(), seed);
}

// An index entry keeps one proof-of-node score, in hashPON: the VRF output of a PON-VRF
// block, the PON hash of a legacy one.
TEST_F(PONTest, VrfOutputIsTheIndexEntryScore) {
    CBlockHeader vrf = MakeVrfHeader();
    vrf.hashPrevBlock = uint256();          // the entries below have no pprev
    CBlockIndex vrfIndex(vrf);
    EXPECT_EQ(vrfIndex.hashPON, vrf.nodesVrfOutput);
    EXPECT_EQ(vrfIndex.VrfOutput(), vrf.nodesVrfOutput);
    EXPECT_EQ(vrfIndex.GetBlockHeader().nodesVrfOutput, vrf.nodesVrfOutput);
    EXPECT_EQ(vrfIndex.GetBlockHeader().GetHash(), vrf.GetHash());
    EXPECT_EQ(GetPonScore(vrf), vrf.nodesVrfOutput);

    CBlockHeader legacy = MakeVrfHeader();
    legacy.hashPrevBlock = uint256();
    legacy.nVersion = CBlockHeader::PON_VERSION;
    legacy.nodesVrfOutput.SetNull();
    legacy.nodesVrfProof.clear();
    CBlockIndex legacyIndex(legacy);
    legacyIndex.hashPON = GetPonScore(legacy);
    EXPECT_EQ(legacyIndex.hashPON, GetPONHash(legacy));
    EXPECT_TRUE(legacyIndex.VrfOutput().IsNull());
    EXPECT_TRUE(legacyIndex.GetBlockHeader().nodesVrfOutput.IsNull());
    EXPECT_EQ(legacyIndex.GetBlockHeader().GetHash(), legacy.GetHash());
}

