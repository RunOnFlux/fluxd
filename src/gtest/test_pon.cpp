// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "consensus/params.h"
#include "main.h"
#include "pon/pon-fork.h"
#include "primitives/block.h"
#include "amount.h"

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
    
    // Test reverse calculation (slot to timestamp)
    int64_t timestamp0 = GetSlotTimestamp(0, genesisTime, consensusParams);
    EXPECT_EQ(timestamp0, genesisTime);
    
    int64_t timestamp10 = GetSlotTimestamp(10, genesisTime, consensusParams);
    EXPECT_EQ(timestamp10, genesisTime + 10 * ponTargetSpacing);
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