// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "addrman.h"
#include "netbase.h"
#include "protocol.h"
#include "utiltime.h"

#include <thread>

// Select() holds CAddrMan::cs for its whole search, so its cost on a sparse
// table is time every other addrman caller spends waiting.

namespace {

//! An addrman holding one new-table entry tried a moment ago: the sparsest
//! table there is, with a GetChance() of 0.01.
void AddOneRecentlyTried(CAddrMan& addrman)
{
    CService addr("250.1.2.3", 16125, false);
    ASSERT_TRUE(addrman.Add(CAddress(addr), CNetAddr("252.2.2.2", false)));
    addrman.Attempt(addr, GetAdjustedTime());
    ASSERT_EQ(addrman.size(), 1u);
}

} // namespace

TEST(AddrManSelect, FindsTheOnlyEntryOfASparseTableQuickly)
{
    CAddrMan addrman;
    AddOneRecentlyTried(addrman);

    // As many selections as one ThreadOpenConnections pass makes.
    int64_t nStart = GetTimeMillis();
    for (int i = 0; i < 100; i++)
        EXPECT_EQ(addrman.Select().ToStringIPPort(), "250.1.2.3:16125");
    EXPECT_LT(GetTimeMillis() - nStart, 1000);
}

TEST(AddrManSelect, GetAddrIsNotHeldUpBySelectOnASparseTable)
{
    CAddrMan addrman;
    AddOneRecentlyTried(addrman);

    std::thread selector([&addrman] {
        for (int i = 0; i < 100; i++)
            addrman.Select();
    });
    MilliSleep(20);
    int64_t nStart = GetTimeMillis();
    addrman.GetAddr();
    int64_t nWaited = GetTimeMillis() - nStart;
    selector.join();
    EXPECT_LT(nWaited, 500);
}
