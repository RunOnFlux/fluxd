// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "primitives/transaction.h"
#include "flux/Note.hpp"
#include "flux/Address.hpp"
#include "utilstrencodings.h"
#include "key.h"
#include "key_io.h"
#include "fluxnode/obfuscation.h"

#include <array>

extern ZCJoinSplit* params;
extern int GenZero(int n);
extern int GenMax(int n);

TEST(Transaction, JSDescriptionRandomized) {
    // construct a merkle tree
    SproutMerkleTree merkleTree;

    libflux::SproutSpendingKey k = libflux::SproutSpendingKey::random();
    libflux::SproutPaymentAddress addr = k.address();

    libflux::SproutNote note(addr.a_pk, 100, uint256(), uint256());

    // commitment from coin
    uint256 commitment = note.cm();

    // insert commitment into the merkle tree
    merkleTree.append(commitment);

    // compute the merkle root we will be working with
    uint256 rt = merkleTree.root();

    auto witness = merkleTree.witness();

    // create JSDescription
    uint256 joinSplitPubKey;
    std::array<libflux::JSInput, ZC_NUM_JS_INPUTS> inputs = {
        libflux::JSInput(witness, note, k),
        libflux::JSInput() // dummy input of zero value
    };
    std::array<libflux::JSOutput, ZC_NUM_JS_OUTPUTS> outputs = {
        libflux::JSOutput(addr, 50),
        libflux::JSOutput(addr, 50)
    };
    std::array<size_t, ZC_NUM_JS_INPUTS> inputMap;
    std::array<size_t, ZC_NUM_JS_OUTPUTS> outputMap;

    {
        auto jsdesc = JSDescription::Randomized(
            *params, joinSplitPubKey, rt,
            inputs, outputs,
            inputMap, outputMap,
            0, 0, false);

        std::set<size_t> inputSet(inputMap.begin(), inputMap.end());
        std::set<size_t> expectedInputSet {0, 1};
        EXPECT_EQ(expectedInputSet, inputSet);

        std::set<size_t> outputSet(outputMap.begin(), outputMap.end());
        std::set<size_t> expectedOutputSet {0, 1};
        EXPECT_EQ(expectedOutputSet, outputSet);
    }

    {
        auto jsdesc = JSDescription::Randomized(
            *params, joinSplitPubKey, rt,
            inputs, outputs,
            inputMap, outputMap,
            0, 0, false, nullptr, GenZero);

        std::array<size_t, ZC_NUM_JS_INPUTS> expectedInputMap {1, 0};
        std::array<size_t, ZC_NUM_JS_OUTPUTS> expectedOutputMap {1, 0};
        EXPECT_EQ(expectedInputMap, inputMap);
        EXPECT_EQ(expectedOutputMap, outputMap);
    }

    {
        auto jsdesc = JSDescription::Randomized(
            *params, joinSplitPubKey, rt,
            inputs, outputs,
            inputMap, outputMap,
            0, 0, false, nullptr, GenMax);

        std::array<size_t, ZC_NUM_JS_INPUTS> expectedInputMap {0, 1};
        std::array<size_t, ZC_NUM_JS_OUTPUTS> expectedOutputMap {0, 1};
        EXPECT_EQ(expectedInputMap, inputMap);
        EXPECT_EQ(expectedOutputMap, outputMap);
    }
}

TEST(Transaction, FluxNodeP2SHStartTransaction) {
    /**
     * 2 of 2 Multisig Script Using the following keys
     *
     * Pair 1
     * Public Key: 0348cb791eb9b13b7c2e9873a8caadfc0994b0e68969dd9b387d641cf945406121
     * Private Key: L4t5cfxnYmqMHDjTRp2zw4x7HhxfdeA9KgTZ5W1LSMKJymLNvd4E
     *
     * Pair 2
     * Public Key: 03d5cdcca8b864f3bee70e0f570cbea198f3afe577fa8e53dcb50ca47ab3ac70ec
     * Private Key: L1XjcSo9LtgfY1rdnGeQSvG61iKgmCrTnPvvMQuVsQyJWpzeLjHW
     *
     * Output
     * Address: t3ba4XTTQR8UbkY53KFQ9zZnx6sMXsnU9ZV
     * Redeem Script: 52210348cb791eb9b13b7c2e9873a8caadfc0994b0e68969dd9b387d641cf9454061212103d5cdcca8b864f3bee70e0f570cbea198f3afe577fa8e53dcb50ca47ab3ac70ec52ae
     *
     * Additional Keys for Tx Creation
     * VPS Keys
     * Public Key: 02b7da05c6b7b2e2fd18b9ad60ac9f8c8751ff0a0687c3f866ae3c7841ac9fb561
     * Private Key: KxeGXhULiSrjibyHzLuQ1LVaCKJjyKW54WZwZwZEMyseKx5PLEm6
     */

    // We want to use mainnet keys so we need to set network to main
    SelectParams(CBaseChainParams::MAIN);

    // Redeem Script Creation
    std::string redeemScriptStr = "52210348cb791eb9b13b7c2e9873a8caadfc0994b0e68969dd9b387d641cf9454061212103d5cdcca8b864f3bee70e0f570cbea198f3afe577fa8e53dcb50ca47ab3ac70ec52ae"; // From Script Data
    std::vector<unsigned char> redeemScriptData = ParseHex( redeemScriptStr);
    CScript redeemScript(redeemScriptData.begin(), redeemScriptData.end());

    // Collateral PubKey Creation
    std::string collateralPubKeyStr = "03d5cdcca8b864f3bee70e0f570cbea198f3afe577fa8e53dcb50ca47ab3ac70ec"; // From Script Data -> Pair 2
    std::vector<unsigned char> collateralPubKeyData = ParseHex( collateralPubKeyStr);
    CPubKey collateralPubKey(collateralPubKeyData);

    // VPS PrivateKey Creation
    std::string vpsPrivKeyStr = "KxeGXhULiSrjibyHzLuQ1LVaCKJjyKW54WZwZwZEMyseKx5PLEm6"; // From Script Data
    CPubKey vpsPubKey;
    CKey vpsKey;
    std::string errorMessage;

    // Test the VPS PrivateKey
    EXPECT_TRUE(obfuScationSigner.SetKey(vpsPrivKeyStr, errorMessage, vpsKey, vpsPubKey));

    // Collateral In Creation
    COutPoint collateralIn(uint256(), 0);

    // Collateral Key Creation that matches the collateral PubKey
    CKey collateralKey;
    CPubKey collateralPubKeyTemp;
    std::string collateralPrivStr = "L1XjcSo9LtgfY1rdnGeQSvG61iKgmCrTnPvvMQuVsQyJWpzeLjHW"; // From Script Data -> Pair 2

    EXPECT_TRUE(obfuScationSigner.SetKey(collateralPrivStr, errorMessage, collateralKey, collateralPubKeyTemp));
    EXPECT_TRUE(collateralKey.IsValid());

    // Create the transaction
    CMutableTransaction mutableTransaction;

    // Set the data for the P2SH Node Transaction
    mutableTransaction.nVersion = FLUXNODE_TX_UPGRADEABLE_VERSION;
    mutableTransaction.nFluxTxVersion = FLUXNODE_INTERNAL_P2SH_TX_VERSION;
    mutableTransaction.nType = FLUXNODE_START_TX_TYPE;

    mutableTransaction.collateralIn = collateralIn;
    mutableTransaction.P2SHRedeemScript = redeemScript;
    mutableTransaction.pubKey = vpsPubKey;

    CObfuScationSigner Signer;
    std::string strMessage;
    bool fFoundKey = false;

    txnouttype type;
    std::vector<CTxDestination> addresses;
    std::vector<CPubKey> pubkeys;
    int nRequired;

    CScriptID inner;
    CTxDestination destination;

    //---------------------------- ACTUAL TESTS ----------------------------------------------------------

    // TODO - Testing removal of collateralpobkey if p2sh tx
//    // Core Check 1 (Collateral PubKey is in the RedeemScript)
//    {
//        EXPECT_TRUE(ListPubKeysFromMultiSigScript(mutableTransaction.P2SHRedeemScript, type, addresses, pubkeys, nRequired));
//        fFoundKey = false;
//        for (int i = 0; i < pubkeys.size(); i++) {
//            if (mutableTransaction.collateralPubkey == pubkeys[i]) {
//                fFoundKey = true;
//                break;
//            }
//        }
//        EXPECT_TRUE(fFoundKey);
//    }

    // Core Check 2 (The redeem script hash is the same as the address)
    {
        inner = CScriptID(mutableTransaction.P2SHRedeemScript);
        destination = DecodeDestination("t3ba4XTTQR8UbkY53KFQ9zZnx6sMXsnU9ZV"); // From Script Data

        EXPECT_TRUE(EncodeDestination(destination) == EncodeDestination(inner));
    }

    // Core Check 3 (Signature Sign and Verify)
    {
        // Sign & Verify the transaction
        mutableTransaction.sigTime = GetTime();

        strMessage = mutableTransaction.GetHash().GetHex();

        EXPECT_TRUE(Signer.SignMessage(strMessage, errorMessage, mutableTransaction.sig, collateralKey));
        // Get the Keys from the RedeemScript.
        std::vector<CPubKey> pubkeys;
        EXPECT_TRUE(ListPubKeysFromMultiSigScript(mutableTransaction.P2SHRedeemScript, pubkeys));

        bool fValidatedSignature = false;
        for (const auto& pubkey: pubkeys) {
            if (Signer.VerifyMessage(pubkey, mutableTransaction.sig, strMessage, errorMessage)) {
                fValidatedSignature = true;
            }
        }

        EXPECT_TRUE(fValidatedSignature);
    }


    // Core Check 3 with the wrong public collateral key. Signature Verify should fail
    {
        // Collateral PubKey Creation
        collateralPubKeyStr = "0348cb791eb9b13b7c2e9873a8caadfc0994b0e68969dd9b387d641cf945406121"; // From Script Data -> Pair 1
        collateralPubKeyData = ParseHex( collateralPubKeyStr);
        collateralPubKey = CPubKey(collateralPubKeyData);

        strMessage = mutableTransaction.GetHash().GetHex();

        EXPECT_TRUE(Signer.SignMessage(strMessage, errorMessage, mutableTransaction.sig, collateralKey));
        EXPECT_FALSE(Signer.VerifyMessage(collateralPubKey, mutableTransaction.sig, strMessage, errorMessage));
    }

    // TODO - remove check once we know the collateral pbukey removal doesn't break things
//    // Core Check 2 with the wrong public collateral key
//    {
//        collateralPubKeyStr = "02b7da05c6b7b2e2fd18b9ad60ac9f8c8751ff0a0687c3f866ae3c7841ac9fb561"; // From Script Data -> VPS Key (Wrong Key Should Fail)
//        collateralPubKeyData = ParseHex( collateralPubKeyStr);
//        collateralPubKey = CPubKey(collateralPubKeyData);
//        mutableTransaction.collateralPubkey = collateralPubKey;
//
//        EXPECT_TRUE(ListPubKeysFromMultiSigScript(mutableTransaction.P2SHRedeemScript, type, addresses, pubkeys, nRequired));
//        fFoundKey = false;
//        for (int i = 0; i < pubkeys.size(); i++) {
//            if (mutableTransaction.collateralPubkey == pubkeys[i]) {
//                fFoundKey = true;
//                break;
//            }
//        }
//        EXPECT_FALSE(fFoundKey);
//    }

    // Core Check 1 with wrong address but correct redeemscript
    {
        inner = CScriptID(mutableTransaction.P2SHRedeemScript);
        destination = DecodeDestination("t3Y3M9utFUXLxLPTvbyaVPXmhceBHKGK115"); // Wrong Address

        EXPECT_FALSE(EncodeDestination(destination) == EncodeDestination(inner));
    }

    // Core Check 1 with wrong redeem script but right address
    {
        redeemScriptStr = "53210348cb791eb9b13b7c2e9873a8caadfc0994b0e68969dd9b387d641cf9454061212103d5cdcca8b864f3bee70e0f570cbea198f3afe577fa8e53dcb50ca47ab3ac70ec2102f76fa263eeb4bc344d388412a6ac7614f7c119ff35af19d694efe5078bfb85c22102b4e51fd6edc1f9929fa7a881a48bac6943522fac9d39dfaba5c21a75e5bbbff854ae"; // From Script Data
        redeemScriptData = ParseHex( redeemScriptStr);
        redeemScript = CScript(redeemScriptData.begin(), redeemScriptData.end());
        mutableTransaction.P2SHRedeemScript = redeemScript;

        inner = CScriptID(mutableTransaction.P2SHRedeemScript);
        destination = DecodeDestination("t3ba4XTTQR8UbkY53KFQ9zZnx6sMXsnU9ZV"); // Wrong Address

        EXPECT_FALSE(EncodeDestination(destination) == EncodeDestination(inner));
    }

    // Test Transaction Serialization by Calling GetHash and CMutableTransaction Serialization by Calling GetHash
    CTransaction tx(mutableTransaction);
    EXPECT_TRUE(tx.GetHash().GetHex() == mutableTransaction.GetHash().GetHex());
}
