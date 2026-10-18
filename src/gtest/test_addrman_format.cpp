// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "addrman.h"
#include "clientversion.h"
#include "netbase.h"
#include "protocol.h"
#include "streams.h"
#include "tinyformat.h"

#include <ios>

// peers.dat compatibility: the second byte of a format-2 file names the lowest
// format able to read it, so a format-1-only fluxd refuses it before loading
// any entry, and a load that fails part-way leaves addrman empty.

namespace {

class TestAddrMan : public CAddrMan
{
public:
    void MakeDeterministic() { nKey.SetNull(); }
    CAddrInfo* Find(const CNetAddr& addr) { return CAddrMan::Find(addr); }
};

CService Address(int i)
{
    return CService(strprintf("250.1.%d.%d", i / 256, i % 256), 8333, false);
}

//! The peers.dat serialization of an addrman offered n addresses; ``held`` is
//! how many it kept (addresses sharing a group and source collide in buckets).
CDataStream Serialized(int n, size_t* held = nullptr)
{
    TestAddrMan addrman;
    addrman.MakeDeterministic();
    CNetAddr source("252.2.2.2", false);
    for (int i = 1; i <= n; i++)
        addrman.Add(CAddress(Address(i)), source);
    if (held) *held = addrman.size();
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << addrman;
    return ss;
}

} // namespace

TEST(AddrManFormat, SecondByteIsBasePlusLowestCompatibleFormat)
{
    CDataStream ss = Serialized(10);
    EXPECT_EQ((unsigned char)ss[0], CAddrMan::ADDRMAN_FORMAT_VERSION);
    // A format-1-only reader takes this byte as the key's length and refuses
    // anything but 32.
    EXPECT_EQ((unsigned char)ss[1], 32 + 2);
}

TEST(AddrManFormat, ReadsFormat2WrittenWithABare32)
{
    size_t held = 0;
    CDataStream ss = Serialized(10, &held);
    ss[1] = 32;
    TestAddrMan addrman;
    ss >> addrman;
    EXPECT_GT(held, 0u);
    EXPECT_EQ(addrman.size(), held);
}

TEST(AddrManFormat, RefusesAFileNeedingANewerFormat)
{
    CDataStream ss = Serialized(10);
    ss[1] = 32 + CAddrMan::ADDRMAN_FORMAT_VERSION + 1;
    TestAddrMan addrman;
    EXPECT_THROW(ss >> addrman, std::ios_base::failure);
    EXPECT_EQ(addrman.size(), 0u);
}

TEST(AddrManFormat, RoundTrips)
{
    size_t held = 0;
    CDataStream ss = Serialized(25, &held);
    TestAddrMan addrman;
    ss >> addrman;
    EXPECT_GT(held, 0u);
    EXPECT_EQ(addrman.size(), held);
}

TEST(AddrManFormat, ClearEmptiesEveryTable)
{
    TestAddrMan addrman;
    addrman.MakeDeterministic();
    addrman.Add(CAddress(Address(1)), CNetAddr("252.2.2.2", false));
    ASSERT_NE(addrman.Find(Address(1)), nullptr);

    addrman.Clear();
    EXPECT_EQ(addrman.size(), 0u);
    EXPECT_EQ(addrman.Find(Address(1)), nullptr);
}

TEST(AddrManFormat, AFailedLoadThenClearIsAsGoodAsNew)
{
    // A load that throws part-way leaves entries no table points at. After
    // Clear() the addrman must behave exactly as a new one given the same
    // addresses: no stale entry found, no reused id colliding with one.
    CDataStream full = Serialized(50);
    CDataStream truncated(full.begin(), full.begin() + full.size() / 2, SER_DISK, CLIENT_VERSION);
    TestAddrMan loaded;
    EXPECT_THROW(truncated >> loaded, std::ios_base::failure);
    loaded.Clear();
    loaded.MakeDeterministic();

    TestAddrMan fresh;
    fresh.MakeDeterministic();

    CNetAddr source("252.2.2.3", false);
    for (int i = 1; i <= 50; i++) {
        EXPECT_EQ(loaded.Find(Address(i)), nullptr);
        EXPECT_EQ(loaded.Add(CAddress(Address(i)), source), fresh.Add(CAddress(Address(i)), source));
    }
    EXPECT_GT(fresh.size(), 0u);
    EXPECT_EQ(loaded.size(), fresh.size());
    for (int i = 1; i <= 50; i++)
        EXPECT_EQ(loaded.Find(Address(i)) != nullptr, fresh.Find(Address(i)) != nullptr) << i;
}
