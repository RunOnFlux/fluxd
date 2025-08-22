#include <gtest/gtest.h>
#include "primitives/transaction.h"
#include "key.h"
#include "pubkey.h"
#include "script/script.h"
#include "fluxnode/obfuscation.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "chainparams.h"
#include "utiltime.h"

// Test fixture for delegate tests
class DelegateTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Initialize any necessary test environment
        SelectParams(CBaseChainParams::REGTEST);
    }
    
    void TearDown() override {
        // Clean up
    }
    
    // Helper function to create a valid compressed key
    CKey GenerateKey() {
        CKey key;
        key.MakeNewKey(true); // true for compressed
        return key;
    }
};

TEST_F(DelegateTest, CFluxnodeDelegates_BasicSerialization) {
    // Create delegate object with UPDATE type
    CFluxnodeDelegates delegates;
    delegates.nDelegateVersion = 1;
    delegates.nType = CFluxnodeDelegates::UPDATE;
    
    // Add some delegate keys
    CKey key1 = GenerateKey();
    CKey key2 = GenerateKey();
    delegates.delegateStartingKeys.push_back(key1.GetPubKey());
    delegates.delegateStartingKeys.push_back(key2.GetPubKey());
    
    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << delegates;
    
    // Deserialize
    CFluxnodeDelegates delegates2;
    ss >> delegates2;
    
    // Verify
    EXPECT_EQ(delegates.nDelegateVersion, delegates2.nDelegateVersion);
    EXPECT_EQ(delegates.nType, delegates2.nType);
    EXPECT_EQ(delegates.delegateStartingKeys.size(), delegates2.delegateStartingKeys.size());
    EXPECT_EQ(delegates.delegateStartingKeys[0], delegates2.delegateStartingKeys[0]);
    EXPECT_EQ(delegates.delegateStartingKeys[1], delegates2.delegateStartingKeys[1]);
}

TEST_F(DelegateTest, CFluxnodeDelegates_SigningTypeSerialization) {
    // Create delegate object with SIGNING type (no keys serialized)
    CFluxnodeDelegates delegates;
    delegates.nDelegateVersion = 1;
    delegates.nType = CFluxnodeDelegates::SIGNING;
    
    // Even if we add keys, they shouldn't be serialized for SIGNING type
    CKey key1 = GenerateKey();
    delegates.delegateStartingKeys.push_back(key1.GetPubKey());
    
    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << delegates;
    
    // Deserialize
    CFluxnodeDelegates delegates2;
    ss >> delegates2;
    
    // Verify
    EXPECT_EQ(delegates2.nDelegateVersion, 1);
    EXPECT_EQ(delegates2.nType, CFluxnodeDelegates::SIGNING);
    EXPECT_EQ(delegates2.delegateStartingKeys.size(), 0); // Keys not serialized for SIGNING
}

TEST_F(DelegateTest, CFluxnodeDelegates_Validation) {
    CFluxnodeDelegates delegates;
    delegates.nDelegateVersion = 1;
    delegates.nType = CFluxnodeDelegates::UPDATE;
    
    // Test empty delegates (valid - means remove all)
    EXPECT_TRUE(delegates.IsValid());
    
    // Test with valid compressed keys
    CKey key1 = GenerateKey();
    CKey key2 = GenerateKey();
    delegates.delegateStartingKeys.push_back(key1.GetPubKey());
    delegates.delegateStartingKeys.push_back(key2.GetPubKey());
    EXPECT_TRUE(delegates.IsValid());
    
    // Test with maximum allowed keys (4)
    CKey key3 = GenerateKey();
    CKey key4 = GenerateKey();
    delegates.delegateStartingKeys.push_back(key3.GetPubKey());
    delegates.delegateStartingKeys.push_back(key4.GetPubKey());
    EXPECT_TRUE(delegates.IsValid());
    
    // Test exceeding maximum keys
    CKey key5 = GenerateKey();
    delegates.delegateStartingKeys.push_back(key5.GetPubKey());
    EXPECT_FALSE(delegates.IsValid());
    
    // Test invalid type
    delegates.delegateStartingKeys.clear();
    delegates.nType = 99; // Invalid type
    EXPECT_FALSE(delegates.IsValid());
}

TEST_F(DelegateTest, Transaction_DelegateBitFlags) {
    // Test bit flag detection
    int32_t normalVersion = FLUXNODE_INTERNAL_NORMAL_TX_VERSION;
    int32_t p2shVersion = FLUXNODE_INTERNAL_P2SH_TX_VERSION;
    int32_t normalWithDelegates = FLUXNODE_TX_TYPE_NORMAL_BIT | FLUXNODE_TX_FEATURE_DELEGATES_BIT;
    int32_t p2shWithDelegates = FLUXNODE_TX_TYPE_P2SH_BIT | FLUXNODE_TX_FEATURE_DELEGATES_BIT;
    
    // Test normal type detection
    EXPECT_TRUE(IsFluxTxNormalType(normalVersion, false)); // Legacy
    EXPECT_TRUE(IsFluxTxNormalType(normalVersion, true));  // With bit check
    EXPECT_TRUE(IsFluxTxNormalType(normalWithDelegates, true));
    EXPECT_FALSE(IsFluxTxP2SHType(normalVersion, true));
    
    // Test P2SH type detection
    EXPECT_TRUE(IsFluxTxP2SHType(p2shVersion, false)); // Legacy
    EXPECT_TRUE(IsFluxTxP2SHType(p2shVersion, true));  // With bit check
    EXPECT_TRUE(IsFluxTxP2SHType(p2shWithDelegates, true));
    EXPECT_FALSE(IsFluxTxNormalType(p2shVersion, true));
    
    // Test delegate feature detection
    EXPECT_FALSE(HasFluxTxDelegatesFeature(normalVersion));
    EXPECT_FALSE(HasFluxTxDelegatesFeature(p2shVersion));
    EXPECT_TRUE(HasFluxTxDelegatesFeature(normalWithDelegates));
    EXPECT_TRUE(HasFluxTxDelegatesFeature(p2shWithDelegates));
    
    // Test conflicting bits detection
    int32_t conflicting = FLUXNODE_TX_TYPE_NORMAL_BIT | FLUXNODE_TX_TYPE_P2SH_BIT;
    EXPECT_TRUE(HasConflictingBits(conflicting));
    EXPECT_FALSE(IsFluxTxNormalType(conflicting, true));
    EXPECT_FALSE(IsFluxTxP2SHType(conflicting, true));
}

TEST_F(DelegateTest, Transaction_WithDelegates) {
    // Create a transaction with delegates
    CMutableTransaction mtx;
    mtx.nVersion = FLUXNODE_TX_UPGRADEABLE_VERSION;
    mtx.nType = FLUXNODE_START_TX_TYPE;
    mtx.nFluxTxVersion = FLUXNODE_TX_TYPE_NORMAL_BIT | FLUXNODE_TX_FEATURE_DELEGATES_BIT;
    
    // Set up collateral
    mtx.collateralIn = COutPoint(uint256S("0x1234"), 0);
    
    // Create delegate data for updating
    mtx.fUsingDelegates = true;
    mtx.delegateData.nDelegateVersion = 1;
    mtx.delegateData.nType = CFluxnodeDelegates::UPDATE;
    
    CKey delegateKey = GenerateKey();
    mtx.delegateData.delegateStartingKeys.push_back(delegateKey.GetPubKey());
    
    // Convert to CTransaction
    CTransaction tx(mtx);
    
    // Test helper functions
    EXPECT_TRUE(tx.IsFluxnodeTx());
    EXPECT_TRUE(tx.IsFluxnodeUpgradeTx());
    EXPECT_TRUE(tx.HasDelegates());
    EXPECT_TRUE(tx.IsUpdatingDelegate());
    EXPECT_FALSE(tx.IsSigningAsDelegate());
    
    // Test serialization round-trip
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;
    
    CTransaction tx2;
    ss >> tx2;
    
    EXPECT_EQ(tx.GetHash(), tx2.GetHash());
    EXPECT_EQ(tx2.delegateData.delegateStartingKeys.size(), 1);
    EXPECT_EQ(tx2.delegateData.delegateStartingKeys[0], delegateKey.GetPubKey());
}

TEST_F(DelegateTest, Transaction_SigningAsDelegate) {
    // Create a transaction signed by a delegate
    CMutableTransaction mtx;
    mtx.nVersion = FLUXNODE_TX_UPGRADEABLE_VERSION;
    mtx.nType = FLUXNODE_START_TX_TYPE;
    mtx.nFluxTxVersion = FLUXNODE_TX_TYPE_NORMAL_BIT | FLUXNODE_TX_FEATURE_DELEGATES_BIT;
    
    // Set up for signing (not updating)
    mtx.fUsingDelegates = true;
    mtx.delegateData.nDelegateVersion = 1;
    mtx.delegateData.nType = CFluxnodeDelegates::SIGNING;
    
    CTransaction tx(mtx);
    
    // Test helper functions
    EXPECT_TRUE(tx.HasDelegates());
    EXPECT_TRUE(tx.IsSigningAsDelegate());
    EXPECT_FALSE(tx.IsUpdatingDelegate());
}

TEST_F(DelegateTest, DelegateSignatureVerification) {
    // Create owner and delegate keys
    CKey ownerKey = GenerateKey();
    CKey delegateKey1 = GenerateKey();
    CKey delegateKey2 = GenerateKey();
    
    // Create a transaction
    CMutableTransaction mtx;
    mtx.nVersion = FLUXNODE_TX_UPGRADEABLE_VERSION;
    mtx.nType = FLUXNODE_START_TX_TYPE;
    mtx.nFluxTxVersion = FLUXNODE_TX_TYPE_NORMAL_BIT | FLUXNODE_TX_FEATURE_DELEGATES_BIT;
    mtx.collateralIn = COutPoint(uint256S("0x1234"), 0);
    mtx.collateralPubkey = ownerKey.GetPubKey();
    mtx.pubKey = ownerKey.GetPubKey(); // VPS key
    mtx.sigTime = GetTime();
    
    // Sign as delegate
    mtx.fUsingDelegates = true;
    mtx.delegateData.nDelegateVersion = 1;
    mtx.delegateData.nType = CFluxnodeDelegates::SIGNING;
    
    CTransaction tx(mtx);
    std::string strMessage = tx.GetHash().GetHex();
    
    // Create signatures
    std::vector<unsigned char> ownerSig;
    std::vector<unsigned char> delegateSig;
    
    CObfuScationSigner signer;
    std::string errorMessage;
    
    // Sign with owner key
    EXPECT_TRUE(signer.SignMessage(strMessage, errorMessage, ownerSig, ownerKey));
    
    // Sign with delegate key
    EXPECT_TRUE(signer.SignMessage(strMessage, errorMessage, delegateSig, delegateKey1));
    
    // Verify signatures
    EXPECT_TRUE(signer.VerifyMessage(ownerKey.GetPubKey(), ownerSig, strMessage, errorMessage));
    EXPECT_TRUE(signer.VerifyMessage(delegateKey1.GetPubKey(), delegateSig, strMessage, errorMessage));
    
    // Cross-verify should fail
    EXPECT_FALSE(signer.VerifyMessage(ownerKey.GetPubKey(), delegateSig, strMessage, errorMessage));
    EXPECT_FALSE(signer.VerifyMessage(delegateKey1.GetPubKey(), ownerSig, strMessage, errorMessage));
}

TEST_F(DelegateTest, BackwardCompatibility) {
    // Test that legacy version values still work
    CMutableTransaction mtx;
    mtx.nVersion = FLUXNODE_TX_UPGRADEABLE_VERSION;
    mtx.nType = FLUXNODE_START_TX_TYPE;
    mtx.nFluxTxVersion = FLUXNODE_INTERNAL_NORMAL_TX_VERSION; // Legacy value = 1
    
    CTransaction tx(mtx);
    
    // Should be recognized as normal type
    EXPECT_TRUE(IsFluxTxNormalType(tx.nFluxTxVersion, false)); // Legacy check
    EXPECT_TRUE(IsFluxTxNormalType(tx.nFluxTxVersion, true));  // Bit check should also work
    EXPECT_FALSE(HasFluxTxDelegatesFeature(tx.nFluxTxVersion));
    
    // Test P2SH legacy
    mtx.nFluxTxVersion = FLUXNODE_INTERNAL_P2SH_TX_VERSION; // Legacy value = 2
    CTransaction tx2(mtx);
    
    EXPECT_TRUE(IsFluxTxP2SHType(tx2.nFluxTxVersion, false)); // Legacy check
    EXPECT_TRUE(IsFluxTxP2SHType(tx2.nFluxTxVersion, true));  // Bit check should also work
    EXPECT_FALSE(HasFluxTxDelegatesFeature(tx2.nFluxTxVersion));
}