// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "main.h"

#include <univalue.h>

UniValue getindexinfo(const UniValue& params, bool fHelp);

class GetIndexInfo : public ::testing::Test {
protected:
    bool saved[6];

    void SetUp() override {
        saved[0] = fTxIndex; saved[1] = fAddressIndex; saved[2] = fSpentIndex;
        saved[3] = fTimestampIndex; saved[4] = fReindex; saved[5] = fImporting;
        fTxIndex = fAddressIndex = fSpentIndex = fTimestampIndex = false;
        fReindex = fImporting = false;
    }

    void TearDown() override {
        fTxIndex = saved[0]; fAddressIndex = saved[1]; fSpentIndex = saved[2];
        fTimestampIndex = saved[3]; fReindex = saved[4]; fImporting = saved[5];
    }

    static UniValue Call(const std::string& filter = "") {
        UniValue params(UniValue::VARR);
        if (!filter.empty()) params.push_back(filter);
        return getindexinfo(params, false);
    }
};

TEST_F(GetIndexInfo, NoIndexIsEmpty) {
    UniValue result = Call();
    ASSERT_TRUE(result.isObject());
    EXPECT_EQ(result.size(), 0u);
}

TEST_F(GetIndexInfo, ReportsEachIndexThatIsOn) {
    fTxIndex = true;
    fAddressIndex = fSpentIndex = fTimestampIndex = true;
    UniValue result = Call();
    EXPECT_EQ(result.getKeys(), (std::vector<std::string>{"txindex", "addressindex", "spentindex", "timestampindex"}));
    for (const std::string& name : result.getKeys()) {
        EXPECT_TRUE(result[name]["synced"].get_bool()) << name;
        EXPECT_EQ(result[name]["best_block_height"].get_int(), chainActive.Height()) << name;
    }
}

TEST_F(GetIndexInfo, TxIndexAloneHasNoAddressIndex) {
    fTxIndex = true;
    UniValue result = Call();
    EXPECT_EQ(result.getKeys(), std::vector<std::string>{"txindex"});
    EXPECT_TRUE(result["addressindex"].isNull());
}

TEST_F(GetIndexInfo, FiltersByName) {
    fTxIndex = fAddressIndex = true;
    EXPECT_EQ(Call("addressindex").getKeys(), std::vector<std::string>{"addressindex"});
    EXPECT_EQ(Call("spentindex").size(), 0u);
    EXPECT_EQ(Call("nosuchindex").size(), 0u);
}

TEST_F(GetIndexInfo, NotSyncedWhileReindexingOrImporting) {
    fAddressIndex = true;
    fReindex = true;
    EXPECT_FALSE(Call()["addressindex"]["synced"].get_bool());
    fReindex = false;
    fImporting = true;
    EXPECT_FALSE(Call()["addressindex"]["synced"].get_bool());
}

TEST_F(GetIndexInfo, RefusesTwoParametersAndAnswersHelp) {
    UniValue two(UniValue::VARR);
    two.push_back("txindex");
    two.push_back("addressindex");
    EXPECT_THROW(getindexinfo(two, false), std::runtime_error);
    EXPECT_THROW(getindexinfo(UniValue(UniValue::VARR), true), std::runtime_error);
}
