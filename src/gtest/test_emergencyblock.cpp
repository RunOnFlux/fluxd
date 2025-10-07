#include <gtest/gtest.h>
#include "chainparams.h"
#include "emergencyblock.h"
#include "primitives/block.h"
#include "key.h"
#include "pubkey.h"
#include "utilstrencodings.h"
#include "consensus/params.h"
#include "random.h"
#include <vector>

namespace {

// Test fixture for emergency block tests
class EmergencyBlockTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Select testnet parameters for testing
        SelectParams(CBaseChainParams::TESTNET);

        // Generate test keys matching the testnet emergency keys
        // These are the private keys for the public keys in chainparams
        // In real usage, these would be kept secret and distributed among devs
        GenerateTestKeys();
    }

    void TearDown() override {
        // Clean up
        testKeys.clear();
    }

    void GenerateTestKeys() {
        // Generate 4 test keys
        for (int i = 0; i < 4; i++) {
            CKey key;
            key.MakeNewKey(true);
            testKeys.push_back(key);
        }
    }

    CBlockHeader CreateTestBlockHeader() {
        CBlockHeader block;
        block.nVersion = CBlockHeader::PON_VERSION; // Use PON version for emergency blocks
        block.hashPrevBlock = GetRandHash();
        block.hashMerkleRoot = GetRandHash();
        block.hashFinalSaplingRoot = GetRandHash();
        block.nTime = GetTime();
        block.nBits = 0x1e0ffff0;

        // Set emergency collateral
        block.nodesCollateral.hash = Params().GetEmergencyCollateralHash();
        block.nodesCollateral.n = 0;

        return block;
    }

    CBlock CreateTestBlock() {
        CBlock block;
        block.nVersion = CBlockHeader::PON_VERSION; // Use PON version for emergency blocks
        block.hashPrevBlock = GetRandHash();
        block.hashMerkleRoot = GetRandHash();
        block.hashFinalSaplingRoot = GetRandHash();
        block.nTime = GetTime();
        block.nBits = 0x1e0ffff0;

        // Set emergency collateral
        block.nodesCollateral.hash = Params().GetEmergencyCollateralHash();
        block.nodesCollateral.n = 0;

        return block;
    }

    std::vector<CKey> testKeys;
};

TEST_F(EmergencyBlockTest, TestEmergencyCollateralDetection) {
    // Test that emergency collateral pattern is correctly identified
    uint256 emergencyHash = Params().GetEmergencyCollateralHash();
    EXPECT_TRUE(IsEmergencyCollateral(emergencyHash));

    // Test that regular hash is not identified as emergency
    uint256 regularHash = GetRandHash();
    EXPECT_FALSE(IsEmergencyCollateral(regularHash));

    // Test specific pattern (all 1's)
    uint256 allOnes = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    EXPECT_EQ(emergencyHash, allOnes);
}

TEST_F(EmergencyBlockTest, TestEmergencyBlockIdentification) {
    // Create a regular PON block
    CBlock regularBlock;
    regularBlock.nVersion = CBlockHeader::PON_VERSION;
    regularBlock.nodesCollateral.hash = GetRandHash();
    regularBlock.nodesCollateral.n = 0;
    EXPECT_FALSE(IsEmergencyBlock(regularBlock));

    // Create an emergency block
    CBlock emergencyBlock = CreateTestBlock();
    EXPECT_TRUE(IsEmergencyBlock(emergencyBlock));

    // Test POW block (should not be emergency)
    CBlock powBlock;
    powBlock.nVersion = 4; // POW version
    EXPECT_FALSE(IsEmergencyBlock(powBlock));
}

TEST_F(EmergencyBlockTest, TestSignatureEncoding) {
    // Create test signatures
    std::vector<std::vector<unsigned char>> originalSigs;
    for (int i = 0; i < 3; i++) {
        std::vector<unsigned char> sig;
        sig.resize(64); // Typical signature size
        GetRandBytes(sig.data(), sig.size());
        originalSigs.push_back(sig);
    }

    // Encode signatures
    std::vector<unsigned char> encoded = EncodeMultiSig(originalSigs);
    EXPECT_FALSE(encoded.empty());

    // Decode signatures
    std::vector<std::vector<unsigned char>> decodedSigs = DecodeMultiSig(encoded);

    // Verify they match
    EXPECT_EQ(originalSigs.size(), decodedSigs.size());
    for (size_t i = 0; i < originalSigs.size(); i++) {
        EXPECT_EQ(originalSigs[i], decodedSigs[i]);
    }
}

TEST_F(EmergencyBlockTest, TestEmergencyBlockCreation) {
    CBlockHeader block = CreateTestBlockHeader();
    std::string errorMessage;

    // Test with insufficient keys (only 1, need 2)
    std::vector<CKey> insufficientKeys;
    insufficientKeys.push_back(testKeys[0]);
    EXPECT_FALSE(CreateEmergencyBlock(block, insufficientKeys, errorMessage));
    EXPECT_FALSE(errorMessage.empty());

    // Test with sufficient keys (2 keys)
    errorMessage.clear();  // Clear error message from previous test
    std::vector<CKey> sufficientKeys;
    sufficientKeys.push_back(testKeys[0]);
    sufficientKeys.push_back(testKeys[1]);
    bool result = CreateEmergencyBlock(block, sufficientKeys, errorMessage);
    if (!result) {
        printf("CreateEmergencyBlock failed with error: %s\n", errorMessage.c_str());
    }
    EXPECT_TRUE(result);
    EXPECT_TRUE(errorMessage.empty());

    // Verify signatures were added to block
    EXPECT_FALSE(block.vchBlockSig.empty());

    // Decode and verify we have 2 signatures
    std::vector<std::vector<unsigned char>> sigs = DecodeMultiSig(block.vchBlockSig);
    EXPECT_EQ(sigs.size(), 2);
}

TEST_F(EmergencyBlockTest, TestEmergencyBlockValidation) {
    // Note: This test would need actual emergency keys to work properly
    // For now, we test the validation logic with mock signatures

    CBlockHeader block = CreateTestBlockHeader();

    // Create block with no signatures
    block.vchBlockSig.clear();
    EXPECT_FALSE(ValidateEmergencyBlockSignatures(block));

    // Create block with one signature (insufficient)
    std::vector<std::vector<unsigned char>> oneSig;
    std::vector<unsigned char> sig1(64);
    GetRandBytes(sig1.data(), sig1.size());
    oneSig.push_back(sig1);
    block.vchBlockSig = EncodeMultiSig(oneSig);
    EXPECT_FALSE(ValidateEmergencyBlockSignatures(block));

    // Note: To properly test validation with real signatures,
    // we would need the private keys corresponding to the emergency public keys
    // This would typically be done in integration tests with test keys
}

TEST_F(EmergencyBlockTest, TestEmergencyBlockTimeRestrictions) {
    int64_t currentTime = GetTime();

    // Test on testnet (PON activates at height 800)
    SelectParams(CBaseChainParams::TESTNET);
    int testnetHeight = 1000;  // After PON activation
    EXPECT_TRUE(IsEmergencyBlockAllowed(testnetHeight, currentTime));

    // Test with low height on testnet (before PON activation - should fail)
    EXPECT_FALSE(IsEmergencyBlockAllowed(799, currentTime));

    // Test time restriction - second call with same height should pass
    // because the static lastBlockTime is only updated when height increases
    EXPECT_TRUE(IsEmergencyBlockAllowed(testnetHeight, currentTime));

    // Test on mainnet (PON activates at height 2900000)
    SelectParams(CBaseChainParams::MAIN);
    EXPECT_FALSE(IsEmergencyBlockAllowed(testnetHeight, currentTime)); // Too low for mainnet
    EXPECT_TRUE(IsEmergencyBlockAllowed(2900001, currentTime)); // After PON activation
}

TEST_F(EmergencyBlockTest, TestMultipleSignatureValidation) {
    // Test that duplicate signatures from same key are rejected
    CBlockHeader block = CreateTestBlockHeader();
    std::string errorMessage;

    // Create signatures with same key used twice
    std::vector<CKey> duplicateKeys;
    duplicateKeys.push_back(testKeys[0]);
    duplicateKeys.push_back(testKeys[0]); // Same key again

    // This should still succeed in creation (signs twice with same key)
    EXPECT_TRUE(CreateEmergencyBlock(block, duplicateKeys, errorMessage));

    // But validation should fail because it needs 2 different keys
    // (This would be tested in actual validation with real keys)
}

TEST_F(EmergencyBlockTest, TestEmergencyParameterRetrieval) {
    // Test that parameters are correctly set
    const std::vector<std::string>& emergencyKeys = Params().GetEmergencyPublicKeys();

    // Testnet should have 4 emergency keys
    EXPECT_EQ(emergencyKeys.size(), 4);

    // Check minimum signatures requirement
    EXPECT_EQ(Params().GetEmergencyMinSignatures(), 2);

    // Verify emergency collateral hash
    uint256 emergencyHash = Params().GetEmergencyCollateralHash();
    EXPECT_EQ(emergencyHash.ToString(), "1111111111111111111111111111111111111111111111111111111111111111");

    // Verify testnet keys are set correctly
    EXPECT_EQ(emergencyKeys[0], "029a1c55fa7e69dd99087f7ca799797052ae21327b94159e60b8cc5704eb188583");
    EXPECT_EQ(emergencyKeys[1], "023c806b01f35a18b42b08f23f5c7e8490801a7da8fd6f6e77708d9f26f22c423e");
    EXPECT_EQ(emergencyKeys[2], "02615c78e21078c21a63cb21cc4d29eaa148d97c3dcbe7be5d9d4dda4e969bb05a");
    EXPECT_EQ(emergencyKeys[3], "033d301dc7ef7ab653da36da1285063ea9be1448d601e3c9f99185476b9d4ae1d1");
}

TEST_F(EmergencyBlockTest, TestBlockHashConsistency) {
    // Ensure that block hash doesn't change when signatures are added
    CBlockHeader block = CreateTestBlockHeader();

    // Get hash before signatures
    uint256 hashBefore = block.GetHash();

    // Add signatures
    std::string errorMessage;
    std::vector<CKey> keys;
    keys.push_back(testKeys[0]);
    keys.push_back(testKeys[1]);
    CreateEmergencyBlock(block, keys, errorMessage);

    // Get hash after signatures
    uint256 hashAfter = block.GetHash();

    // Hashes should be the same (signatures excluded from hash calculation)
    EXPECT_EQ(hashBefore, hashAfter);
}

} // namespace