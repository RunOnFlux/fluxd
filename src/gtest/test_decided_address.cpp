// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// The node's decided address: the IPv4 address its peers report, taken by
// majority with at least the chain's DecidedAddressMinPeers() behind it, and the early
// confirm that carries a change of it to the chain.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "fluxnode/fluxnode.h"
#include "net.h"
#include "netbase.h"
#include "utiltime.h"

#include <algorithm>
#include <vector>

namespace {

CNetAddr Addr(const char* ip)
{
    return CNetAddr(ip, false);
}

std::vector<PeerAddressReport> Reports(std::initializer_list<std::pair<NodeId, const char*>> list)
{
    std::vector<PeerAddressReport> reports;
    for (const auto& [id, ip] : list)
        reports.push_back({id, Addr(ip)});
    return reports;
}

// Puts peers reporting the given addresses into vNodes, recomputes the decided
// address, and takes them out again. The CNodes are leaked: ~CNode drives
// FinalizeNode signal wiring that only exists in a fully initialised node.
void UpdateWithPeers(const std::vector<const char*>& addrs)
{
    LOCK(cs_vNodes);
    std::vector<CNode*> added;
    for (const char* ip : addrs) {
        CNode* node = new CNode(INVALID_SOCKET, CAddress(CService("8.8.4.4", 16125, false)), "", /*fInbound=*/true);
        node->addrLocal = CService(ip, 16125, false);
        vNodes.push_back(node);
        added.push_back(node);
    }
    UpdateDecidedAddress();
    for (CNode* node : added)
        vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), node), vNodes.end());
}

} // namespace

TEST(DecidedAddress, MajorityWins)
{
    SelectParams(CBaseChainParams::MAIN);
    // The minority holds the newest peer (id 8); the count decides first.
    auto reports = Reports({{1, "1.2.3.4"}, {2, "5.6.7.8"}, {3, "1.2.3.4"}, {4, "5.6.7.8"},
                            {5, "1.2.3.4"}, {8, "5.6.7.8"}, {7, "1.2.3.4"}});
    CNetAddr addr;
    int nPeers = 0;
    ASSERT_TRUE(DecideAddress(reports, false, addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(nPeers, 4);
}

TEST(DecidedAddress, TieGoesToNewestPeer)
{
    SelectParams(CBaseChainParams::MAIN);
    CNetAddr addr;
    int nPeers = 0;

    // 5.6.7.8's newest reporter (id 6) connected after 1.2.3.4's (id 5).
    auto reports = Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "5.6.7.8"}, {4, "5.6.7.8"},
                            {5, "1.2.3.4"}, {6, "5.6.7.8"}});
    ASSERT_TRUE(DecideAddress(reports, false, addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "5.6.7.8");
    EXPECT_EQ(nPeers, 3);

    // Same tally, newest reporter swapped: the other address wins.
    reports = Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "5.6.7.8"}, {4, "5.6.7.8"},
                       {9, "1.2.3.4"}, {6, "5.6.7.8"}});
    ASSERT_TRUE(DecideAddress(reports, false, addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "1.2.3.4");
}

TEST(DecidedAddress, MainnetNeedsThreeAgreeing)
{
    SelectParams(CBaseChainParams::MAIN);
    ASSERT_EQ(Params().DecidedAddressMinPeers(), 3);
    CNetAddr addr;
    int nPeers = 0;
    EXPECT_FALSE(DecideAddress(Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}}), false, addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "5.6.7.8"}, {4, "5.6.7.8"},
                                        {5, "9.9.9.9"}}), false, addr, nPeers));
    EXPECT_FALSE(DecideAddress({}, false, addr, nPeers));
    ASSERT_TRUE(DecideAddress(Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "1.2.3.4"}}), false, addr, nPeers));
    EXPECT_EQ(nPeers, 3);
}

TEST(DecidedAddress, OneSufficesOnTestnetLabnetAndRegtest)
{
    SelectParams(CBaseChainParams::TESTNET);
    EXPECT_EQ(Params().DecidedAddressMinPeers(), 1);
    SelectParams(CBaseChainParams::LABNET);
    EXPECT_EQ(Params().DecidedAddressMinPeers(), 1);

    SelectParams(CBaseChainParams::REGTEST);
    ASSERT_EQ(Params().DecidedAddressMinPeers(), 1);
    CNetAddr addr;
    int nPeers = 0;
    ASSERT_TRUE(DecideAddress(Reports({{1, "1.2.3.4"}}), false, addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(nPeers, 1);
    EXPECT_FALSE(DecideAddress({}, false, addr, nPeers));
    SelectParams(CBaseChainParams::MAIN);
}

TEST(DecidedAddress, OnlyRoutableIPv4Counts)
{
    SelectParams(CBaseChainParams::MAIN);
    CNetAddr addr;
    int nPeers = 0;
    EXPECT_FALSE(DecideAddress(Reports({{1, "2001:4860::8888"}, {2, "2001:4860::8888"}, {3, "2001:4860::8888"}}), false, addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "10.0.0.1"}, {2, "10.0.0.1"}, {3, "10.0.0.1"}}), false, addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "192.168.1.1"}, {2, "192.168.1.1"}, {3, "192.168.1.1"}}), false, addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "127.0.0.1"}, {2, "127.0.0.1"}, {3, "127.0.0.1"}}), false, addr, nPeers));
    // What a peer behind or reached through a proxy reports.
    EXPECT_FALSE(DecideAddress(Reports({{1, "0.0.0.0"}, {2, "0.0.0.0"}, {3, "0.0.0.0"}}), false, addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "0.0.0.0"}, {2, "0.0.0.0"}, {3, "0.0.0.0"}}), true, addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "2001:4860::8888"}, {2, "2001:4860::8888"}, {3, "2001:4860::8888"}}), true, addr, nPeers));

    // Filtered reports do not count towards a routable address either.
    EXPECT_FALSE(DecideAddress(Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "10.0.0.1"}, {4, "2001:4860::8888"}}), false, addr, nPeers));

    // Regtest admits loopback.
    ASSERT_TRUE(DecideAddress(Reports({{1, "127.0.0.1"}, {2, "127.0.0.1"}, {3, "127.0.0.1"}}), true, addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "127.0.0.1");
}

TEST(DecidedAddress, LyingPeerOutvoted)
{
    SelectParams(CBaseChainParams::MAIN);
    // The newest peer lies; the honest majority stands.
    auto reports = Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "1.2.3.4"}, {4, "6.6.6.6"}});
    CNetAddr addr;
    int nPeers = 0;
    ASSERT_TRUE(DecideAddress(reports, false, addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(nPeers, 3);
}

TEST(DecidedAddress, ExternalIpIgnored)
{
    SelectParams(CBaseChainParams::MAIN);
    SetMockTime(1700000000);
    CService externalIp("9.9.9.9", 16125, false);
    ASSERT_TRUE(AddLocal(externalIp, LOCAL_MANUAL));

    // -externalip alone decides nothing.
    UpdateWithPeers({});
    EXPECT_FALSE(DecidedAddress().IsSet());

    // Peers decide; -externalip does not outvote or join them.
    UpdateWithPeers({"1.2.3.4", "1.2.3.4", "1.2.3.4", "9.9.9.9"});
    DecidedAddressInfo info = DecidedAddress();
    ASSERT_TRUE(info.IsSet());
    EXPECT_EQ(info.address.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(info.nPeers, 3);
    EXPECT_EQ(info.nChanged, 1700000000);

    // Two peers agreeing with -externalip are still too few.
    UpdateWithPeers({"9.9.9.9", "9.9.9.9"});
    EXPECT_FALSE(DecidedAddress().IsSet());

    RemoveLocal(externalIp);
    SetMockTime(0);
}

TEST(DecidedAddress, ChangedTimeMovesOnlyWithTheAddress)
{
    SelectParams(CBaseChainParams::MAIN);
    UpdateWithPeers({});
    SetMockTime(1700000100);
    UpdateWithPeers({"1.2.3.4", "1.2.3.4", "1.2.3.4"});
    ASSERT_EQ(DecidedAddress().nChanged, 1700000100);

    // More peers behind the same address: the count follows, the time does not.
    SetMockTime(1700000200);
    UpdateWithPeers({"1.2.3.4", "1.2.3.4", "1.2.3.4", "1.2.3.4"});
    EXPECT_EQ(DecidedAddress().nPeers, 4);
    EXPECT_EQ(DecidedAddress().nChanged, 1700000100);

    SetMockTime(1700000300);
    UpdateWithPeers({"5.6.7.8", "5.6.7.8", "5.6.7.8"});
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "5.6.7.8");
    EXPECT_EQ(DecidedAddress().nChanged, 1700000300);

    UpdateWithPeers({});
    SetMockTime(0);
}

TEST(DecidedAddress, ConfirmIpCarriesNonDefaultPort)
{
    EXPECT_EQ(FluxnodeConfirmIp("1.2.3.4", FLUXOS_DEFAULT_PORT), "1.2.3.4");
    EXPECT_EQ(FluxnodeConfirmIp("1.2.3.4", 16137), "1.2.3.4:16137");
}

TEST(DecidedAddress, IpChangeConfirmDue)
{
    const int nMin = FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1;

    // Same host, with or without a port in the record: nothing to carry.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4", 100, "1.2.3.4", 100 + 400));
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4:16137", 100, "1.2.3.4", 100 + 400));
    // No decided address: nothing to carry.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4", 100, "", 100 + 400));

    // A changed host is due once the chain accepts an address change.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4:16137", 100, "5.6.7.8", 100 + nMin - 1));
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4:16137", 100, "5.6.7.8", 100 + nMin));
    EXPECT_TRUE(IpChangeConfirmDue("", 100, "5.6.7.8", 100 + nMin));
}

TEST(DecidedAddress, CacheReportsIpChangeConfirm)
{
    SelectParams(CBaseChainParams::MAIN);
    const int nFluxHeight = Params().GetConsensus().vUpgrades[Consensus::UPGRADE_FLUX].nActivationHeight;
    const int nLast = nFluxHeight + 1000;

    FluxnodeCache cache;
    COutPoint out(uint256S("01"), 0);
    FluxnodeCacheData data;
    data.collateralIn = out;
    data.ip = "1.2.3.4";
    data.nLastConfirmedBlockHeight = nLast;
    cache.mapConfirmedFluxnodeData[out] = data;

    // The tip is p_nHeight; the confirm lands in the block after it.
    EXPECT_FALSE(cache.CheckIfNeedsIpChangeConfirm(out, nLast + FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1 - 2, "5.6.7.8"));
    EXPECT_TRUE(cache.CheckIfNeedsIpChangeConfirm(out, nLast + FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1 - 1, "5.6.7.8"));
    EXPECT_FALSE(cache.CheckIfNeedsIpChangeConfirm(out, nLast + 400, "1.2.3.4"));
    // The cadence alone does not report an address change as due.
    EXPECT_FALSE(cache.CheckIfNeedsNextConfirm(out, nLast + FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1));
    // A node that is not confirmed is never due.
    EXPECT_FALSE(cache.CheckIfNeedsIpChangeConfirm(COutPoint(uint256S("02"), 0), nLast + 400, "5.6.7.8"));
}
