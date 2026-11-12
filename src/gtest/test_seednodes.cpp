// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// Seed nodes: each -seednode destination is asked for addresses at most once,
// one at a time, and only while the node is short of peers.

#include <gtest/gtest.h>

#include "net.h"

#include <optional>
#include <string>
#include <vector>

namespace {

const int64_t T0 = 1700000000;
const int NO_PEERS = 0;
const int ENOUGH_PEERS = SEED_NODE_OUTBOUND_THRESHOLD;

std::string Next(SeedNodeFeeder& feeder, int nKeptOutbound, int64_t nNow)
{
    return feeder.Next(nKeptOutbound, nNow).value_or("");
}

} // namespace

TEST(SeedNodes, EmptyAddressBookAsksTheFirstAtOnce)
{
    SeedNodeFeeder feeder({"a", "b", "c"}, /*fAddressBookEmpty=*/true, T0);
    // Whatever peers the node has: with no addresses it can find no more.
    EXPECT_EQ(Next(feeder, ENOUGH_PEERS, T0), "c");
    // The next waits for the interval.
    EXPECT_EQ(Next(feeder, NO_PEERS, T0), "");
    EXPECT_EQ(Next(feeder, NO_PEERS, T0 + SEED_NODE_INTERVAL - 1), "");
    EXPECT_EQ(Next(feeder, NO_PEERS, T0 + SEED_NODE_INTERVAL), "b");
}

TEST(SeedNodes, KnownAddressesAreTriedFirst)
{
    SeedNodeFeeder feeder({"a", "b"}, /*fAddressBookEmpty=*/false, T0);
    EXPECT_EQ(Next(feeder, NO_PEERS, T0), "");
    EXPECT_EQ(Next(feeder, NO_PEERS, T0 + SEED_NODE_INTERVAL - 1), "");
    // Still short of peers after the interval.
    EXPECT_EQ(Next(feeder, NO_PEERS, T0 + SEED_NODE_INTERVAL), "b");
}

TEST(SeedNodes, ANodeWithPeersAsksNone)
{
    SeedNodeFeeder feeder({"a", "b"}, /*fAddressBookEmpty=*/false, T0);
    EXPECT_EQ(Next(feeder, ENOUGH_PEERS, T0 + 100 * SEED_NODE_INTERVAL), "");
    EXPECT_EQ(Next(feeder, ENOUGH_PEERS + 14, T0 + 200 * SEED_NODE_INTERVAL), "");
    // One peer short of the threshold: a seed node is asked.
    EXPECT_EQ(Next(feeder, ENOUGH_PEERS - 1, T0 + 300 * SEED_NODE_INTERVAL), "b");
    // Peers found: the rest are left alone, and asked when the node is short again.
    EXPECT_EQ(Next(feeder, ENOUGH_PEERS, T0 + 400 * SEED_NODE_INTERVAL), "");
    EXPECT_EQ(Next(feeder, NO_PEERS, T0 + 500 * SEED_NODE_INTERVAL), "a");
}

TEST(SeedNodes, EachIsAskedOnce)
{
    SeedNodeFeeder feeder({"a", "b"}, /*fAddressBookEmpty=*/true, T0);
    std::vector<std::string> asked;
    for (int i = 0; i < 100; i++) {
        const std::string strSeed = Next(feeder, NO_PEERS, T0 + i * SEED_NODE_INTERVAL);
        if (!strSeed.empty())
            asked.push_back(strSeed);
    }
    EXPECT_EQ(asked, (std::vector<std::string>{"b", "a"}));

    SeedNodeFeeder none({}, /*fAddressBookEmpty=*/true, T0);
    EXPECT_EQ(Next(none, NO_PEERS, T0), "");
}

TEST(SeedNodes, OneShotTimeout)
{
    EXPECT_FALSE(OneShotTimedOut(T0, T0));
    EXPECT_FALSE(OneShotTimedOut(T0 + ONE_SHOT_TIMEOUT, T0));
    EXPECT_TRUE(OneShotTimedOut(T0 + ONE_SHOT_TIMEOUT + 1, T0));
}
