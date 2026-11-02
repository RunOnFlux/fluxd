// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "arith_uint256.h"
#include "main.h"
#include "rpc/server.h"

#include <univalue.h>

#include <map>
#include <set>
#include <string>

UniValue getchaintips(const UniValue& params, bool fHelp);

// A block tree built through AddToBlockIndex, the path every header accepted at runtime
// takes, with chainActive at block 10 of the main chain:
//
//   0 - 1 - 2 - 3 - 4 - 5 - 6 - 7 - 8 - 9 - 10 - 11h   (11h: a header beyond the active tip)
//               \           \           \
//                4c          6a - 7a     9b, 9b2      (stale branches)
class ChainTips : public ::testing::Test {
protected:
    std::map<std::string, CBlockIndex*> blocks;
    const CBlockIndex* savedTip = nullptr;
    CBlockIndex* savedBestHeader = nullptr;
    uint32_t nonce = 0;

    CBlockIndex* Add(const std::string& name, const std::string& parent)
    {
        CBlockHeader header;
        header.hashPrevBlock = parent.empty() ? uint256() : blocks.at(parent)->GetBlockHash();
        header.nNonce = ArithToUint256(arith_uint256(++nonce));
        CBlockIndex* pindex = AddToBlockIndex(header);
        blocks[name] = pindex;
        return pindex;
    }

    void SetUp() override
    {
        LOCK(cs_main);
        savedTip = chainActive.Tip();
        savedBestHeader = pindexBestHeader;
        Add("0", "");
        for (int h = 1; h <= 10; h++)
            Add(std::to_string(h), std::to_string(h - 1));
        chainActive.SetTip(blocks.at("10"));
        Add("4c", "3");
        Add("6a", "5");
        Add("7a", "6a");
        Add("9b", "8");
        Add("9b2", "8");
        Add("11h", "10");
    }

    void TearDown() override
    {
        LOCK(cs_main);
        chainActive.SetTip(const_cast<CBlockIndex*>(savedTip));
        pindexBestHeader = savedBestHeader;
        for (const auto& [name, pindex] : blocks) {
            mapBlockIndex.erase(pindex->GetBlockHash());
            delete pindex;
        }
        RebuildChainTips();
    }

    // The tips getchaintips reported before the set: every entry at or above minHeight that
    // no entry at or above minHeight has as pprev, read by walking the whole index.
    static std::set<const CBlockIndex*> FullWalkTips(int minHeight)
    {
        std::set<const CBlockIndex*> referenced, tips;
        std::vector<const CBlockIndex*> recent;
        for (const auto& [hash, block] : mapBlockIndex) {
            if (block->nHeight >= minHeight) {
                recent.push_back(block);
                if (block->pprev && block->pprev->nHeight >= minHeight)
                    referenced.insert(block->pprev);
            }
        }
        for (const CBlockIndex* block : recent)
            if (!referenced.count(block))
                tips.insert(block);
        tips.insert(chainActive.Tip());
        return tips;
    }

    static std::set<std::string> Hashes(const std::set<const CBlockIndex*>& tips)
    {
        std::set<std::string> out;
        for (const CBlockIndex* tip : tips)
            out.insert(tip->GetBlockHash().GetHex());
        return out;
    }

    static std::set<std::string> RpcHashes(int minHeight)
    {
        UniValue params(UniValue::VARR);
        params.push_back(minHeight);
        UniValue result = getchaintips(params, false);
        std::set<std::string> out;
        for (size_t i = 0; i < result.size(); i++)
            out.insert(result[i]["hash"].get_str());
        return out;
    }

    std::set<const CBlockIndex*> Named(std::initializer_list<const char*> names)
    {
        std::set<const CBlockIndex*> out;
        for (const char* name : names)
            out.insert(blocks.at(name));
        return out;
    }
};

TEST_F(ChainTips, GetchaintipsReportsWhatTheFullWalkFound)
{
    LOCK(cs_main);
    for (int minHeight : {0, 3, 4, 5, 6, 7, 8, 9, 10, 11}) {
        EXPECT_EQ(RpcHashes(minHeight), Hashes(FullWalkTips(minHeight))) << "minheight " << minHeight;
    }
}

TEST_F(ChainTips, TheLeavesAndTheActiveTip)
{
    LOCK(cs_main);
    std::vector<const CBlockIndex*> tips = ChainTipsFrom(0);
    EXPECT_EQ(std::set<const CBlockIndex*>(tips.begin(), tips.end()), Named({"4c", "7a", "9b", "9b2", "11h"}));
    // the active tip has a header beyond it, so it is no leaf; getchaintips adds it
    EXPECT_EQ(RpcHashes(0), Hashes(Named({"4c", "7a", "9b", "9b2", "11h", "10"})));
}

TEST_F(ChainTips, ATipBelowMinHeightIsNotRead)
{
    LOCK(cs_main);
    std::vector<const CBlockIndex*> tips = ChainTipsFrom(8);
    EXPECT_EQ(std::set<const CBlockIndex*>(tips.begin(), tips.end()), Named({"9b", "9b2", "11h"}));
}

TEST_F(ChainTips, AParentLeavesTheTipsWhenAChildIsAdded)
{
    LOCK(cs_main);
    Add("8b", "7a");
    std::vector<const CBlockIndex*> tips = ChainTipsFrom(0);
    std::set<const CBlockIndex*> set(tips.begin(), tips.end());
    EXPECT_FALSE(set.count(blocks.at("7a")));
    EXPECT_TRUE(set.count(blocks.at("8b")));
}

TEST_F(ChainTips, TheRebuildFindsWhatTheAddsKept)
{
    LOCK(cs_main);
    std::vector<const CBlockIndex*> kept = ChainTipsFrom(0);
    RebuildChainTips();
    EXPECT_EQ(ChainTipsFrom(0), kept);
}

TEST_F(ChainTips, TheRebuildKeepsTheActiveTipWhenNothingBuildsOnIt)
{
    LOCK(cs_main);
    chainActive.SetTip(blocks.at("11h"));
    RebuildChainTips();
    std::vector<const CBlockIndex*> tips = ChainTipsFrom(11);
    EXPECT_EQ(std::set<const CBlockIndex*>(tips.begin(), tips.end()), Named({"11h"}));
}
