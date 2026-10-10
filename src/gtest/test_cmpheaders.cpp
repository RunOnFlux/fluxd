// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "chain.h"
#include "main.h"

namespace {

// A chain of n blocks, each with its own hash.
struct TestChain {
    std::vector<uint256> hashes;
    std::vector<CBlockIndex> blocks;
    CChain chain;

    explicit TestChain(int n) : hashes(n), blocks(n)
    {
        for (int i = 0; i < n; i++) {
            hashes[i] = ArithToUint256(arith_uint256(i + 1));
            blocks[i].phashBlock = &hashes[i];
            blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
            blocks[i].nHeight = i;
            blocks[i].nVersion = 4;
        }
        chain.SetTip(&blocks.back());
    }
};

} // namespace

TEST(CompactHeaders, BatchStopsBelowTheLastCheckpoint)
{
    TestChain t(3000);
    const int checkpoint = 2029;

    // A batch starting 1028 below the checkpoint has room for 2000 headers,
    // but carries only those below it.
    std::vector<const CBlockIndex*> v =
        CompactHeaderBlocks(t.chain, &t.blocks[1001], uint256(), checkpoint, 2000);

    ASSERT_EQ(v.size(), 1028u);
    EXPECT_EQ(v.front()->nHeight, 1001);
    EXPECT_EQ(v.back()->nHeight, checkpoint - 1);
}

TEST(CompactHeaders, BatchKeepsItsLimitAndStopHash)
{
    TestChain t(3000);

    EXPECT_EQ(CompactHeaderBlocks(t.chain, &t.blocks[0], uint256(), 2029, 2000).size(), 2000u);
    EXPECT_EQ(CompactHeaderBlocks(t.chain, &t.blocks[0], t.hashes[9], 2029, 2000).size(), 10u);
}

TEST(CompactHeaders, NoBatchFromTheCheckpointOn)
{
    TestChain t(3000);

    EXPECT_TRUE(CompactHeaderBlocks(t.chain, &t.blocks[2029], uint256(), 2029, 2000).empty());
}
