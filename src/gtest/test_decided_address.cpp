// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// The node's decided address: the IPv4 address its peers report, taken by
// majority with at least the chain's DecidedAddressMinPeers() behind it; the
// port FluxOS publishes; and the confirm ip made of the two, sent early when it
// changes.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "fluxnode/activefluxnode.h"
#include "fluxnode/fluxnode.h"
#include "net.h"
#include "netbase.h"
#include "utiltime.h"

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <unistd.h>
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
    ASSERT_TRUE(DecideAddress(reports, false, CNetAddr(), addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(nPeers, 4);
}

TEST(DecidedAddress, TieWithoutIncumbentGoesToNewestPeer)
{
    SelectParams(CBaseChainParams::MAIN);
    CNetAddr addr;
    int nPeers = 0;

    // 5.6.7.8's newest reporter (id 6) connected after 1.2.3.4's (id 5).
    auto reports = Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "5.6.7.8"}, {4, "5.6.7.8"},
                            {5, "1.2.3.4"}, {6, "5.6.7.8"}});
    ASSERT_TRUE(DecideAddress(reports, false, CNetAddr(), addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "5.6.7.8");
    EXPECT_EQ(nPeers, 3);

    // Same tally, newest reporter swapped: the other address wins.
    reports = Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "5.6.7.8"}, {4, "5.6.7.8"},
                       {9, "1.2.3.4"}, {6, "5.6.7.8"}});
    ASSERT_TRUE(DecideAddress(reports, false, CNetAddr(), addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "1.2.3.4");

    // An incumbent outside the leaders does not hold the tie: the newest reporter decides.
    reports = Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "5.6.7.8"}, {4, "5.6.7.8"},
                       {5, "1.2.3.4"}, {6, "5.6.7.8"}, {7, "9.9.9.9"}});
    ASSERT_TRUE(DecideAddress(reports, false, Addr("9.9.9.9"), addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "5.6.7.8");
}

TEST(DecidedAddress, IncumbentKeepsTie)
{
    SelectParams(CBaseChainParams::MAIN);
    CNetAddr addr;
    int nPeers = 0;

    // The newest reporter (id 6) backs 5.6.7.8; the incumbent 1.2.3.4 stays, whichever
    // side of it the challenger sorts.
    auto reports = Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "5.6.7.8"}, {4, "5.6.7.8"},
                            {5, "1.2.3.4"}, {6, "5.6.7.8"}});
    ASSERT_TRUE(DecideAddress(reports, false, Addr("1.2.3.4"), addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(nPeers, 3);
    reports = Reports({{1, "5.6.7.8"}, {2, "5.6.7.8"}, {3, "1.2.3.4"}, {4, "1.2.3.4"},
                       {5, "5.6.7.8"}, {6, "1.2.3.4"}});
    ASSERT_TRUE(DecideAddress(reports, false, Addr("5.6.7.8"), addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "5.6.7.8");

    // Through UpdateDecidedAddress: three newer peers for another address tie the
    // decided one and do not move it; a fourth does.
    SetMockTime(1700000400);
    UpdateWithPeers({});
    UpdateWithPeers({"1.2.3.4", "1.2.3.4", "1.2.3.4"});
    ASSERT_EQ(DecidedAddress().address.ToStringIP(), "1.2.3.4");
    UpdateWithPeers({"1.2.3.4", "1.2.3.4", "1.2.3.4", "5.6.7.8", "5.6.7.8", "5.6.7.8"});
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(DecidedAddress().nChanged, 1700000400);
    UpdateWithPeers({"1.2.3.4", "1.2.3.4", "1.2.3.4", "5.6.7.8", "5.6.7.8", "5.6.7.8", "5.6.7.8"});
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "5.6.7.8");

    UpdateWithPeers({});
    SetMockTime(0);
}

TEST(DecidedAddress, MainnetNeedsThreeAgreeing)
{
    SelectParams(CBaseChainParams::MAIN);
    ASSERT_EQ(Params().DecidedAddressMinPeers(), 3);
    CNetAddr addr;
    int nPeers = 0;
    EXPECT_FALSE(DecideAddress(Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}}), false, CNetAddr(), addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "5.6.7.8"}, {4, "5.6.7.8"},
                                        {5, "9.9.9.9"}}), false, CNetAddr(), addr, nPeers));
    EXPECT_FALSE(DecideAddress({}, false, CNetAddr(), addr, nPeers));
    ASSERT_TRUE(DecideAddress(Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "1.2.3.4"}}), false, CNetAddr(), addr, nPeers));
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
    ASSERT_TRUE(DecideAddress(Reports({{1, "1.2.3.4"}}), false, CNetAddr(), addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(nPeers, 1);
    EXPECT_FALSE(DecideAddress({}, false, CNetAddr(), addr, nPeers));
    SelectParams(CBaseChainParams::MAIN);
}

TEST(DecidedAddress, OnlyRoutableIPv4Counts)
{
    SelectParams(CBaseChainParams::MAIN);
    CNetAddr addr;
    int nPeers = 0;
    EXPECT_FALSE(DecideAddress(Reports({{1, "2001:4860::8888"}, {2, "2001:4860::8888"}, {3, "2001:4860::8888"}}), false, CNetAddr(), addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "10.0.0.1"}, {2, "10.0.0.1"}, {3, "10.0.0.1"}}), false, CNetAddr(), addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "192.168.1.1"}, {2, "192.168.1.1"}, {3, "192.168.1.1"}}), false, CNetAddr(), addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "127.0.0.1"}, {2, "127.0.0.1"}, {3, "127.0.0.1"}}), false, CNetAddr(), addr, nPeers));
    // What a peer behind or reached through a proxy reports.
    EXPECT_FALSE(DecideAddress(Reports({{1, "0.0.0.0"}, {2, "0.0.0.0"}, {3, "0.0.0.0"}}), false, CNetAddr(), addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "0.0.0.0"}, {2, "0.0.0.0"}, {3, "0.0.0.0"}}), true, CNetAddr(), addr, nPeers));
    EXPECT_FALSE(DecideAddress(Reports({{1, "2001:4860::8888"}, {2, "2001:4860::8888"}, {3, "2001:4860::8888"}}), true, CNetAddr(), addr, nPeers));

    // Filtered reports do not count towards a routable address either.
    EXPECT_FALSE(DecideAddress(Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "10.0.0.1"}, {4, "2001:4860::8888"}}), false, CNetAddr(), addr, nPeers));

    // Regtest admits loopback.
    ASSERT_TRUE(DecideAddress(Reports({{1, "127.0.0.1"}, {2, "127.0.0.1"}, {3, "127.0.0.1"}}), true, CNetAddr(), addr, nPeers));
    EXPECT_EQ(addr.ToStringIP(), "127.0.0.1");
}

TEST(DecidedAddress, LyingPeerOutvoted)
{
    SelectParams(CBaseChainParams::MAIN);
    // The newest peer lies; the honest majority stands.
    auto reports = Reports({{1, "1.2.3.4"}, {2, "1.2.3.4"}, {3, "1.2.3.4"}, {4, "6.6.6.6"}});
    CNetAddr addr;
    int nPeers = 0;
    ASSERT_TRUE(DecideAddress(reports, false, CNetAddr(), addr, nPeers));
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

    // The ip the confirm would carry is the record's: nothing to carry.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4", 100, "1.2.3.4", 100 + 400));
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4:16137", 100, "1.2.3.4:16137", 100 + 400));
    // No confirm ip: nothing to carry.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4", 100, "", 100 + 400));

    // A changed host, same port, is due once the chain accepts an address change.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4:16137", 100, "5.6.7.8:16137", 100 + nMin - 1));
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4:16137", 100, "5.6.7.8:16137", 100 + nMin));
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4", 100, "5.6.7.8", 100 + nMin));
    EXPECT_TRUE(IpChangeConfirmDue("", 100, "5.6.7.8", 100 + nMin));

    // A changed port, same host, is a change too, to or from the default.
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4:16137", 100, "1.2.3.4:16147", 100 + nMin));
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4:16137", 100, "1.2.3.4", 100 + nMin));
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4", 100, "1.2.3.4:16137", 100 + nMin));
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4", 100, "1.2.3.4:16137", 100 + nMin - 1));

    // Both changed.
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4:16137", 100, "5.6.7.8:16147", 100 + nMin));
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
    EXPECT_TRUE(cache.CheckIfNeedsIpChangeConfirm(out, nLast + 400, "1.2.3.4:16137"));
    // The cadence alone does not report an address change as due.
    EXPECT_FALSE(cache.CheckIfNeedsNextConfirm(out, nLast + FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1));
    // A node that is not confirmed is never due.
    EXPECT_FALSE(cache.CheckIfNeedsIpChangeConfirm(COutPoint(uint256S("02"), 0), nLast + 400, "5.6.7.8"));
}

namespace {

// A port file in a fresh temporary directory, removed with the object.
class PortFile
{
public:
    PortFile()
    {
        dir = std::filesystem::temp_directory_path() / strprintf("flux-port-%d-%d", getpid(), counter++);
        std::filesystem::create_directories(dir);
        path = (dir / "fluxos.json").string();
    }
    ~PortFile() { std::filesystem::remove_all(dir); }
    void Write(const std::string& content)
    {
        std::ofstream(path, std::ios::trunc) << content;
    }
    FluxOSPortInfo Read(bool fDefaultWhenMissing = false) const { return ReadFluxOSPort(path, fDefaultWhenMissing); }

    std::filesystem::path dir;
    std::string path;

private:
    static inline int counter = 0;
};

} // namespace

TEST(DecidedAddress, PortFileParsed)
{
    PortFile file;
    file.Write(R"({"apiPort": 16137, "apiPortHttps": 16138, "uiPort": 16136})");
    FluxOSPortInfo info = file.Read();
    EXPECT_EQ(info.nPort, 16137);
    EXPECT_EQ(info.strSource, "file");

    // Only apiPort matters; the bounds are inclusive.
    file.Write(R"({"apiPort": 1})");
    EXPECT_EQ(file.Read().nPort, 1);
    file.Write(R"({"apiPort": 65535, "uiPort": "x"})");
    EXPECT_EQ(file.Read().nPort, 65535);
    file.Write(R"({"apiPort": 16127})");
    EXPECT_EQ(file.Read(true).nPort, 16127);
    EXPECT_EQ(file.Read(true).strSource, "file");
}

TEST(DecidedAddress, PortFileMalformedIsAbsent)
{
    PortFile file;
    const std::vector<std::string> malformed = {
        "",
        "not json",
        R"({"apiPort": 16127)",
        "[16127]",
        "16127",
        "{}",
        R"({"apiport": 16127})",
        R"({"apiPort": null})",
        R"({"apiPort": "16127"})",
        R"({"apiPort": true})",
        R"({"apiPort": 16127.5})",
        R"({"apiPort": 1.6127e4})",
        R"({"apiPort": 0})",
        R"({"apiPort": -1})",
        R"({"apiPort": 65536})",
        R"({"apiPort": 99999999999999999999})",
        R"({"apiPort": {"port": 16127}})",
        std::string(R"({"apiPort": 16127, "pad": ")") + std::string(5000, 'x') + R"("})",
    };
    for (const std::string& content : malformed) {
        file.Write(content);
        // Even where an absent file would default, a file that is there and wrong is absent.
        for (bool fDefault : {false, true}) {
            const FluxOSPortInfo info = file.Read(fDefault);
            EXPECT_FALSE(info.IsSet()) << content;
            EXPECT_EQ(info.nPort, 0) << content;
            EXPECT_EQ(info.strSource, "none") << content;
            EXPECT_FALSE(info.strReason.empty()) << content;
        }
    }

    // A path that is not a readable file.
    std::filesystem::create_directories(file.path);
    EXPECT_FALSE(file.Read().IsSet());
    EXPECT_FALSE(file.Read(true).IsSet());
}

TEST(DecidedAddress, PortFileAbsentDefaultsOnlyWhereAllowed)
{
    PortFile file;
    FluxOSPortInfo info = file.Read(false);
    EXPECT_FALSE(info.IsSet());
    EXPECT_EQ(info.strSource, "none");
    EXPECT_NE(info.strReason.find("absent"), std::string::npos);

    info = file.Read(true);
    EXPECT_EQ(info.nPort, FLUXOS_DEFAULT_PORT);
    EXPECT_EQ(info.strSource, "default");
}

TEST(DecidedAddress, ConfirmIpNeedsHostAndPort)
{
    if (std::filesystem::exists(FLUXOS_PORT_FILE))
        GTEST_SKIP() << FLUXOS_PORT_FILE << " exists on this host";

    std::string strIp, strMissing;

    // Mainnet: the port file is absent, so the port is.
    SelectParams(CBaseChainParams::MAIN);
    UpdateWithPeers({});
    EXPECT_FALSE(GetConfirmIp(strIp, strMissing));
    EXPECT_NE(strMissing.find("no decided address"), std::string::npos) << strMissing;
    EXPECT_NE(strMissing.find("no FluxOS port"), std::string::npos) << strMissing;

    UpdateWithPeers({"1.2.3.4", "1.2.3.4", "1.2.3.4"});
    EXPECT_FALSE(GetConfirmIp(strIp, strMissing));
    EXPECT_EQ(strMissing.find("no decided address"), std::string::npos) << strMissing;
    EXPECT_NE(strMissing.find("no FluxOS port"), std::string::npos) << strMissing;

    // Regtest: an absent port file reads as the default port, so the host alone decides.
    SelectParams(CBaseChainParams::REGTEST);
    UpdateWithPeers({});
    EXPECT_FALSE(GetConfirmIp(strIp, strMissing));
    EXPECT_NE(strMissing.find("no decided address"), std::string::npos) << strMissing;
    EXPECT_EQ(strMissing.find("no FluxOS port"), std::string::npos) << strMissing;

    UpdateWithPeers({"1.2.3.4"});
    strMissing.clear();
    ASSERT_TRUE(GetConfirmIp(strIp, strMissing)) << strMissing;
    EXPECT_EQ(strIp, "1.2.3.4");

    UpdateWithPeers({});
    SelectParams(CBaseChainParams::MAIN);
}
