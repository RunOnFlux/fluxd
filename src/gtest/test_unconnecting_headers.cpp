// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "main.h"

TEST(UnconnectingHeaders, NotScoredBelowTheLimit)
{
    for (int n = 1; n < MAX_UNCONNECTING_HEADERS; n++)
        EXPECT_EQ(UnconnectingHeadersScore(n), 0) << n;
}

TEST(UnconnectingHeaders, ScoredAtEachMultipleOfTheLimit)
{
    EXPECT_EQ(UnconnectingHeadersScore(MAX_UNCONNECTING_HEADERS), 20);
    for (int n = MAX_UNCONNECTING_HEADERS + 1; n < 2 * MAX_UNCONNECTING_HEADERS; n++)
        EXPECT_EQ(UnconnectingHeadersScore(n), 0) << n;
    EXPECT_EQ(UnconnectingHeadersScore(2 * MAX_UNCONNECTING_HEADERS), 20);
}

TEST(UnconnectingHeaders, BanNeedsFiftyInARow)
{
    // The ban threshold is 100: a peer sending nothing but unconnecting announcements is
    // banned at the fiftieth.
    int score = 0;
    int n = 0;
    while (score < 100)
        score += UnconnectingHeadersScore(++n);
    EXPECT_EQ(n, 5 * MAX_UNCONNECTING_HEADERS);
}

TEST(UnconnectingHeaders, NothingCountedIsNotScored)
{
    EXPECT_EQ(UnconnectingHeadersScore(0), 0);
}
