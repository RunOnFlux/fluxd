#include <gtest/gtest.h>

#include "primitives/transaction.h"
#include "zelcash/Note.hpp"
#include "zelcash/Address.hpp"

#include <array>

extern ZCJoinSplit* params;
extern int GenZero(int n);
extern int GenMax(int n);

TEST(Transaction, JSDescriptionRandomized) {
    // construct a merkle tree
    SproutMerkleTree merkleTree;

    libzelcash::SproutSpendingKey k = libzelcash::SproutSpendingKey::random();
    libzelcash::SproutPaymentAddress addr = k.address();

    libzelcash::SproutNote note(addr.a_pk, 100, uint256(), uint256());

    // commitment from coin
    uint256 commitment = note.cm();

    // insert commitment into the merkle tree
    merkleTree.append(commitment);

    // compute the merkle root we will be working with
    uint256 rt = merkleTree.root();

    auto witness = merkleTree.witness();

    // create JSDescription
    uint256 joinSplitPubKey;
    std::array<libzelcash::JSInput, ZC_NUM_JS_INPUTS> inputs = {
        libzelcash::JSInput(witness, note, k),
        libzelcash::JSInput() // dummy input of zero value
    };
    std::array<libzelcash::JSOutput, ZC_NUM_JS_OUTPUTS> outputs = {
        libzelcash::JSOutput(addr, 50),
        libzelcash::JSOutput(addr, 50)
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
