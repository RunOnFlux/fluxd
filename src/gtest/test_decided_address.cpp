// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// The node's decided address: the IPv4 address the peers it dialled report, by
// a vote counted one per netgroup of answering peers; the port FluxOS
// publishes; and the confirm ip made of the two, sent early when it changes.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "fluxnode/activefluxnode.h"
#include "fluxnode/fluxnode.h"
#include "net.h"
#include "netbase.h"
#include "tinyformat.h"
#include "utiltime.h"

#include <univalue.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <unistd.h>
#include <vector>

namespace {

const DecidedAddressRules MAINNET_RULES{3, 8, false, false};
const DecidedAddressRules REGTEST_RULES{1, 1, true, true};
const int64_t NO_PONG_YET = std::numeric_limits<int64_t>::max();

CNetAddr Addr(const char* ip)
{
    return CNetAddr(ip, false);
}

std::optional<CNetAddr> Opt(const char* ip)
{
    return Addr(ip);
}

// A peer at strPeer reporting this node at strLocal.
PeerAddressReport Report(NodeId id, const std::string& strPeer, const char* strLocal, bool fInbound = false, bool fVoter = true, bool fLive = true)
{
    return {id, CNetAddr(strPeer.c_str(), false), Addr(strLocal), fInbound, fVoter, fLive};
}

// The i-th of a run of public addresses, each in a /16 of its own.
std::string PeerIp(int i)
{
    return strprintf("%d.%d.0.1", 20 + i / 200, 1 + i % 200);
}

// A tally holding the given votes, every voter having voted.
AddressTally Votes(std::initializer_list<std::pair<const char*, int>> list)
{
    AddressTally tally;
    for (const auto& [ip, n] : list) {
        tally.mapVotes[Addr(ip)] = n;
        tally.nVoters += n;
    }
    return tally;
}

std::string Decide(const AddressTally& tally, const DecidedAddressRules& rules, const char* decided, const char* onChain)
{
    const std::optional<CNetAddr> addr = DecideAddress(tally, rules, decided ? Opt(decided) : std::nullopt, onChain ? Opt(onChain) : std::nullopt);
    return addr ? addr->ToStringIP() : "";
}

struct TestPeer {
    const char* local;      // where it reports this node
    bool fInbound = false;
    bool fSilent = false;   // a ping to it has gone unanswered for a minute
    bool fFeeler = false;
    bool fOneShot = false;
    const char* peer = nullptr; // its own address; a /16 of its own when null
};

std::vector<TestPeer> Dialled(int n, const char* local)
{
    return std::vector<TestPeer>(n, TestPeer{local});
}

std::vector<TestPeer> operator+(std::vector<TestPeer> a, const std::vector<TestPeer>& b)
{
    a.insert(a.end(), b.begin(), b.end());
    return a;
}

// Puts the peers into vNodes, re-evaluates the decided address, and takes them
// out again, returning them for inspection. The CNodes are leaked: ~CNode
// drives FinalizeNode signal wiring that only exists in a fully initialised node.
std::vector<CNode*> UpdateWithPeers(const std::vector<TestPeer>& peers)
{
    LOCK(cs_vNodes);
    std::vector<CNode*> added;
    int i = 0;
    for (const TestPeer& peer : peers) {
        const std::string strPeer = peer.peer ? peer.peer : PeerIp(i);
        i++;
        CNode* node = new CNode(INVALID_SOCKET, CAddress(CService(strPeer.c_str(), 16125, false)), "", peer.fInbound);
        node->addrLocal = CService(peer.local, 16125, false);
        node->fFeeler = peer.fFeeler;
        node->fOneShot = peer.fOneShot;
        if (peer.fSilent) {
            node->nPingNonceSent = 1;
            node->nPingUsecStart = GetTimeMicros() - 60 * 1000000;
        }
        vNodes.push_back(node);
        added.push_back(node);
    }
    UpdateDecidedAddress();
    for (CNode* node : added)
        vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), node), vNodes.end());
    return added;
}

} // namespace

TEST(DecidedAddress, RulesPerChain)
{
    SelectParams(CBaseChainParams::MAIN);
    DecidedAddressRules rules = GetDecidedAddressRules();
    EXPECT_EQ(rules.nMinVotes, 3);
    EXPECT_EQ(rules.nMinVoters, std::min(MAX_OUTBOUND_CONNECTIONS, nMaxConnections) / 2);
    EXPECT_FALSE(rules.fInboundVotes);
    EXPECT_FALSE(rules.fAllowNonRoutable);

    for (const auto& network : {CBaseChainParams::TESTNET, CBaseChainParams::LABNET}) {
        SelectParams(network);
        rules = GetDecidedAddressRules();
        EXPECT_EQ(rules.nMinVotes, 1);
        EXPECT_EQ(rules.nMinVoters, 1);
        EXPECT_FALSE(rules.fInboundVotes);
        EXPECT_FALSE(rules.fAllowNonRoutable);
    }

    SelectParams(CBaseChainParams::REGTEST);
    rules = GetDecidedAddressRules();
    EXPECT_EQ(rules.nMinVotes, 1);
    EXPECT_EQ(rules.nMinVoters, 1);
    EXPECT_TRUE(rules.fInboundVotes);
    EXPECT_TRUE(rules.fAllowNonRoutable);
    SelectParams(CBaseChainParams::MAIN);
}

TEST(DecidedAddress, OnlyDialledPeersVote)
{
    // Twenty inbound peers report one address, three dialled peers another.
    std::vector<PeerAddressReport> reports;
    for (int i = 0; i < 20; i++)
        reports.push_back(Report(i, PeerIp(i), "6.6.6.6", /*fInbound=*/true, /*fVoter=*/false));
    for (int i = 20; i < 23; i++)
        reports.push_back(Report(i, PeerIp(i), "1.2.3.4"));

    const AddressTally tally = TallyAddressVotes(reports, MAINNET_RULES);
    EXPECT_EQ(tally.nVoters, 3);
    EXPECT_EQ(tally.Votes(Addr("1.2.3.4")), 3);
    EXPECT_EQ(tally.Votes(Addr("6.6.6.6")), 0);
    ASSERT_EQ(tally.mapInbound.size(), 1u);
    EXPECT_EQ(tally.mapInbound.at(Addr("6.6.6.6")), 20);

    // A dialled peer of a kind that does not vote is in neither count.
    const AddressTally none = TallyAddressVotes({Report(1, PeerIp(1), "1.2.3.4", false, /*fVoter=*/false)}, MAINNET_RULES);
    EXPECT_EQ(none.nVoters, 0);
    EXPECT_TRUE(none.mapInbound.empty());
}

TEST(DecidedAddress, OneVotePerNetgroup)
{
    // Four peers in 65.108/16 and three in 65.109/16 agree: two votes.
    std::vector<PeerAddressReport> reports = {
        Report(1, "65.108.1.1", "1.2.3.4"), Report(2, "65.108.2.2", "1.2.3.4"),
        Report(3, "65.108.3.3", "1.2.3.4"), Report(4, "65.108.4.4", "1.2.3.4"),
        Report(5, "65.109.1.1", "1.2.3.4"), Report(6, "65.109.2.2", "1.2.3.4"),
        Report(7, "65.109.3.3", "1.2.3.4"),
    };
    AddressTally tally = TallyAddressVotes(reports, MAINNET_RULES);
    EXPECT_EQ(tally.nVoters, 2);
    EXPECT_EQ(tally.Votes(Addr("1.2.3.4")), 2);

    // A netgroup whose peers disagree casts no vote.
    reports.push_back(Report(8, "65.109.9.9", "6.6.6.6"));
    tally = TallyAddressVotes(reports, MAINNET_RULES);
    EXPECT_EQ(tally.nVoters, 1);
    EXPECT_EQ(tally.Votes(Addr("1.2.3.4")), 1);
    EXPECT_EQ(tally.Votes(Addr("6.6.6.6")), 0);
}

TEST(DecidedAddress, OnlyRoutableIPv4Counts)
{
    const auto fVotes = [](const char* strPeer, const char* strLocal, const DecidedAddressRules& rules) {
        return TallyAddressVotes({Report(1, strPeer, strLocal)}, rules).nVoters;
    };
    EXPECT_EQ(fVotes("8.8.4.4", "1.2.3.4", MAINNET_RULES), 1);
    // The reported address.
    for (const char* strLocal : {"2001:4860::8888", "10.0.0.1", "192.168.1.1", "127.0.0.1", "0.0.0.0"})
        EXPECT_EQ(fVotes("8.8.4.4", strLocal, MAINNET_RULES), 0) << strLocal;
    // The peer's own address.
    for (const char* strPeer : {"2001:4860::8888", "10.0.0.1", "192.168.1.1", "127.0.0.1"})
        EXPECT_EQ(fVotes(strPeer, "1.2.3.4", MAINNET_RULES), 0) << strPeer;

    // Regtest admits loopback on both sides, never IPv6 or the unspecified address.
    EXPECT_EQ(fVotes("127.0.0.1", "127.0.0.1", REGTEST_RULES), 1);
    EXPECT_EQ(fVotes("127.0.0.1", "2001:4860::8888", REGTEST_RULES), 0);
    EXPECT_EQ(fVotes("127.0.0.1", "0.0.0.0", REGTEST_RULES), 0);

    // Where loopback peers vote, each is a netgroup of its own.
    const AddressTally tally = TallyAddressVotes({Report(1, "127.0.0.1", "1.2.3.4"), Report(2, "127.0.0.1", "1.2.3.4"),
                                                  Report(3, "127.0.0.1", "5.6.7.8")}, REGTEST_RULES);
    EXPECT_EQ(tally.nVoters, 3);
    EXPECT_EQ(tally.Votes(Addr("1.2.3.4")), 2);
    EXPECT_EQ(tally.Votes(Addr("5.6.7.8")), 1);
}

TEST(DecidedAddress, InboundPeersVoteOnRegtestOnly)
{
    const std::vector<PeerAddressReport> reports = {Report(1, "127.0.0.1", "1.2.3.4", /*fInbound=*/true, /*fVoter=*/true)};
    EXPECT_EQ(TallyAddressVotes(reports, REGTEST_RULES).Votes(Addr("1.2.3.4")), 1);

    // Through UpdateDecidedAddress, which decides who is a voter.
    SelectParams(CBaseChainParams::REGTEST);
    ResetDecidedAddress();
    UpdateWithPeers({TestPeer{"1.2.3.4", /*fInbound=*/true}});
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "1.2.3.4");

    SelectParams(CBaseChainParams::MAIN);
    ResetDecidedAddress();
    std::vector<TestPeer> inbound(20, TestPeer{"6.6.6.6", /*fInbound=*/true});
    UpdateWithPeers(inbound);
    EXPECT_FALSE(DecidedAddress().IsSet());
    ASSERT_EQ(DecidedAddress().mapInbound.size(), 1u);
    EXPECT_EQ(DecidedAddress().mapInbound.at(Addr("6.6.6.6")), 20);
    ResetDecidedAddress();
}

TEST(DecidedAddress, SilentVoterDoesNotCount)
{
    const AddressTally tally = TallyAddressVotes({Report(1, PeerIp(1), "1.2.3.4"), Report(2, PeerIp(2), "1.2.3.4", false, true, /*fLive=*/false)}, MAINNET_RULES);
    EXPECT_EQ(tally.nVoters, 1);
    EXPECT_EQ(tally.Votes(Addr("1.2.3.4")), 1);
}

TEST(DecidedAddress, VoteLiveness)
{
    const int64_t nNow = 1000 * 1000000LL;
    const int64_t nSec = 1000000;

    // No ping outstanding.
    EXPECT_TRUE(AddressVoteIsLive(nNow, 0, 0, NO_PONG_YET));
    // Never ponged: five seconds to answer.
    EXPECT_TRUE(AddressVoteIsLive(nNow, nNow - 5 * nSec, 0, NO_PONG_YET));
    EXPECT_FALSE(AddressVoteIsLive(nNow, nNow - 5 * nSec - 1, 0, NO_PONG_YET));
    // Three times the best round trip is added.
    EXPECT_TRUE(AddressVoteIsLive(nNow, nNow - 5 * nSec - 300000, 0, 100000));
    EXPECT_FALSE(AddressVoteIsLive(nNow, nNow - 5 * nSec - 300001, 0, 100000));
    // Anything received since the ping was sent, however long ago it was sent:
    // a pong this node's message thread has not reached yet.
    EXPECT_TRUE(AddressVoteIsLive(nNow, nNow - 60 * nSec, nNow - 60 * nSec, NO_PONG_YET));
    EXPECT_TRUE(AddressVoteIsLive(nNow, nNow - 60 * nSec, nNow - 59 * nSec, 100000));
    // Bytes from before the ping say nothing.
    EXPECT_FALSE(AddressVoteIsLive(nNow, nNow - 60 * nSec, nNow - 61 * nSec, 100000));
}

TEST(DecidedAddress, FirstDecisionNeedsVotesMajorityAndVoters)
{
    // Eight voters agreeing.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 8}}), MAINNET_RULES, nullptr, nullptr), "1.2.3.4");
    // Too few voters, whatever they say.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 7}}), MAINNET_RULES, nullptr, nullptr), "");
    EXPECT_EQ(Decide(Votes({}), MAINNET_RULES, nullptr, nullptr), "");
    // More than half.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 5}, {"6.6.6.6", 3}}), MAINNET_RULES, nullptr, nullptr), "1.2.3.4");
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 4}, {"6.6.6.6", 4}}), MAINNET_RULES, nullptr, nullptr), "");
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 4}, {"6.6.6.6", 3}, {"9.9.9.9", 3}}), MAINNET_RULES, nullptr, nullptr), "");
    // The minimum votes bind where few voters are needed.
    const DecidedAddressRules threeOfFew{3, 1, false, false};
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 2}}), threeOfFew, nullptr, nullptr), "");
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 3}}), threeOfFew, nullptr, nullptr), "1.2.3.4");

    // One voter decides on regtest.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 1}}), REGTEST_RULES, nullptr, nullptr), "1.2.3.4");
    EXPECT_EQ(Decide(Votes({}), REGTEST_RULES, nullptr, nullptr), "");
}

TEST(DecidedAddress, OnChainAddressNeedsOnlyTheMinimumVotes)
{
    // Three votes agree with the record; eight voters are not needed.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 3}}), MAINNET_RULES, nullptr, "1.2.3.4"), "1.2.3.4");
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 2}}), MAINNET_RULES, nullptr, "1.2.3.4"), "");
    // It stands against a majority for another address below three quarters.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 5}, {"6.6.6.6", 11}}), MAINNET_RULES, nullptr, "1.2.3.4"), "1.2.3.4");
    // It yields to three quarters: a node restarted at a new address.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 4}, {"5.6.7.8", 12}}), MAINNET_RULES, nullptr, "1.2.3.4"), "5.6.7.8");
    // With no votes of its own it is no obstacle to an adoptable address, and is never taken on trust.
    EXPECT_EQ(Decide(Votes({{"5.6.7.8", 8}}), MAINNET_RULES, nullptr, "1.2.3.4"), "5.6.7.8");
    EXPECT_EQ(Decide(Votes({{"5.6.7.8", 7}}), MAINNET_RULES, nullptr, "1.2.3.4"), "");
    // A decided address, not the record, is what is held once there is one.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 3}, {"5.6.7.8", 3}}), MAINNET_RULES, "5.6.7.8", "1.2.3.4"), "5.6.7.8");
}

TEST(DecidedAddress, DecidedAddressStandsBelowThreeQuarters)
{
    // Sixteen voters. Eleven for another address change nothing while three still see the decided one.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 5}, {"6.6.6.6", 11}}), MAINNET_RULES, "1.2.3.4", nullptr), "1.2.3.4");
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 3}, {"6.6.6.6", 5}, {"9.9.9.9", 8}}), MAINNET_RULES, "1.2.3.4", nullptr), "1.2.3.4");
    // Twelve of sixteen is three quarters.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 4}, {"5.6.7.8", 12}}), MAINNET_RULES, "1.2.3.4", nullptr), "5.6.7.8");
    // Three quarters of too few voters is not enough.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 1}, {"5.6.7.8", 6}}), MAINNET_RULES, "1.2.3.4", nullptr), "1.2.3.4");
}

TEST(DecidedAddress, DecidedAddressBelowTheMinimumVotes)
{
    // The node moved: its old address has no votes left and the new one is adoptable.
    EXPECT_EQ(Decide(Votes({{"5.6.7.8", 8}}), MAINNET_RULES, "1.2.3.4", nullptr), "5.6.7.8");
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 2}, {"5.6.7.8", 9}}), MAINNET_RULES, "1.2.3.4", nullptr), "5.6.7.8");
    // Nothing adoptable: it stands, with few votes or none.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 2}, {"5.6.7.8", 5}}), MAINNET_RULES, "1.2.3.4", nullptr), "1.2.3.4");
    EXPECT_EQ(Decide(Votes({{"5.6.7.8", 4}, {"6.6.6.6", 4}}), MAINNET_RULES, "1.2.3.4", nullptr), "1.2.3.4");
    EXPECT_EQ(Decide(Votes({}), MAINNET_RULES, "1.2.3.4", nullptr), "1.2.3.4");
}

TEST(DecidedAddress, LyingVotersNeedAQuarterToHoldAndThreeQuartersToMove)
{
    // A node that moved from 1.2.3.4 to 5.6.7.8, with voters still reporting the old address.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 4}, {"5.6.7.8", 12}}), MAINNET_RULES, "1.2.3.4", nullptr), "5.6.7.8");
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 5}, {"5.6.7.8", 11}}), MAINNET_RULES, "1.2.3.4", nullptr), "1.2.3.4");
    // A node that has not moved, with voters reporting a false address.
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 5}, {"6.6.6.6", 11}}), MAINNET_RULES, "1.2.3.4", nullptr), "1.2.3.4");
    EXPECT_EQ(Decide(Votes({{"1.2.3.4", 4}, {"6.6.6.6", 12}}), MAINNET_RULES, "1.2.3.4", nullptr), "6.6.6.6");
}

TEST(DecidedAddress, DialledPeersDecideThroughUpdate)
{
    SelectParams(CBaseChainParams::MAIN);
    ResetDecidedAddress();
    SetMockTime(1700000400);

    // Seven voters are one short; an eighth decides.
    UpdateWithPeers(Dialled(7, "1.2.3.4"));
    EXPECT_FALSE(DecidedAddress().IsSet());
    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    DecidedAddressInfo info = DecidedAddress();
    ASSERT_TRUE(info.IsSet());
    EXPECT_EQ(info.address.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(info.nVotes, 8);
    EXPECT_EQ(info.nVoters, 8);
    EXPECT_EQ(info.nChanged, 1700000400);

    // Other reports are shown and decide nothing.
    UpdateWithPeers(Dialled(5, "1.2.3.4") + Dialled(11, "6.6.6.6") + std::vector<TestPeer>(4, TestPeer{"9.9.9.9", /*fInbound=*/true}));
    info = DecidedAddress();
    EXPECT_EQ(info.address.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(info.nVotes, 5);
    EXPECT_EQ(info.nVoters, 16);
    ASSERT_EQ(info.mapOther.size(), 1u);
    EXPECT_EQ(info.mapOther.at(Addr("6.6.6.6")), 11);
    ASSERT_EQ(info.mapInbound.size(), 1u);
    EXPECT_EQ(info.mapInbound.at(Addr("9.9.9.9")), 4);

    // With every peer gone the address stands.
    UpdateWithPeers({});
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(DecidedAddress().nVotes, 0);

    ResetDecidedAddress();
    SetMockTime(0);
}

TEST(DecidedAddress, FeelersAndOneShotsDoNotVote)
{
    SelectParams(CBaseChainParams::MAIN);
    ResetDecidedAddress();

    std::vector<TestPeer> peers = Dialled(7, "1.2.3.4");
    TestPeer feeler{"1.2.3.4"};
    feeler.fFeeler = true;
    TestPeer oneShot{"1.2.3.4"};
    oneShot.fOneShot = true;
    UpdateWithPeers(peers + std::vector<TestPeer>{feeler, oneShot});
    EXPECT_FALSE(DecidedAddress().IsSet());
    EXPECT_EQ(DecidedAddress().nVoters, 7);
    ResetDecidedAddress();
}

TEST(DecidedAddress, SilentVotersAreDroppedOnlyWhileTheAddressLacksVotes)
{
    SelectParams(CBaseChainParams::MAIN);
    ResetDecidedAddress();
    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    ASSERT_TRUE(DecidedAddress().IsSet());

    TestPeer silent{"1.2.3.4"};
    silent.fSilent = true;

    // Three still answer: the silent ones lose their votes and keep their connections.
    std::vector<CNode*> nodes = UpdateWithPeers(Dialled(3, "1.2.3.4") + std::vector<TestPeer>(13, silent));
    EXPECT_EQ(DecidedAddress().nVotes, 3);
    for (const CNode* node : nodes)
        EXPECT_FALSE(node->fDisconnect);

    // Two answer: every silent dialled peer is dropped, and no other peer.
    TestPeer silentInbound{"1.2.3.4", /*fInbound=*/true, /*fSilent=*/true};
    nodes = UpdateWithPeers(Dialled(2, "1.2.3.4") + std::vector<TestPeer>(13, silent) + std::vector<TestPeer>{silentInbound});
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(DecidedAddress().nVotes, 2);
    for (size_t i = 0; i < nodes.size(); i++)
        EXPECT_EQ(nodes[i]->fDisconnect, i >= 2 && i < 15) << i;

    ResetDecidedAddress();
}

TEST(DecidedAddress, DissentPingsTheDecidedAddressVoters)
{
    SelectParams(CBaseChainParams::MAIN);
    ResetDecidedAddress();
    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    ASSERT_TRUE(DecidedAddress().IsSet());

    LOCK(cs_vNodes);
    std::vector<CNode*> nodes;
    const auto fAdd = [&](const char* strPeer, const char* strLocal, bool fInbound) {
        CNode* node = new CNode(INVALID_SOCKET, CAddress(CService(strPeer, 16125, false)), "", fInbound);
        node->addrLocal = CService(strLocal, 16125, false);
        vNodes.push_back(node);
        nodes.push_back(node);
        return node;
    };
    CNode* voter = fAdd("20.1.0.1", "1.2.3.4", false);
    CNode* waiting = fAdd("20.2.0.1", "1.2.3.4", false);
    waiting->nPingNonceSent = 1;
    CNode* inbound = fAdd("20.4.0.1", "1.2.3.4", true);

    // A peer that dialled in reports another address: nobody is pinged.
    PeerReportedAddress(fAdd("20.5.0.1", "5.6.7.8", true));
    EXPECT_FALSE(voter->fPingQueued);
    // A voter agreeing with the decided address: nobody is pinged.
    PeerReportedAddress(fAdd("20.6.0.1", "1.2.3.4", false));
    EXPECT_FALSE(voter->fPingQueued);

    // A voter reports another address: the decided address's voters are pinged.
    CNode* dissenter = fAdd("20.3.0.1", "5.6.7.8", false);
    PeerReportedAddress(dissenter);
    EXPECT_TRUE(voter->fPingQueued);
    EXPECT_FALSE(waiting->fPingQueued);   // its ping is already out
    EXPECT_FALSE(dissenter->fPingQueued);
    EXPECT_FALSE(inbound->fPingQueued);

    for (CNode* node : nodes)
        vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), node), vNodes.end());
    ResetDecidedAddress();
}

TEST(DecidedAddress, ExternalIpIgnored)
{
    SelectParams(CBaseChainParams::MAIN);
    ResetDecidedAddress();
    CService externalIp("9.9.9.9", 16125, false);
    ASSERT_TRUE(AddLocal(externalIp, LOCAL_MANUAL));

    // -externalip alone decides nothing.
    UpdateWithPeers({});
    EXPECT_FALSE(DecidedAddress().IsSet());

    // Seven voters agreeing with -externalip are still one short.
    UpdateWithPeers(Dialled(7, "9.9.9.9"));
    EXPECT_FALSE(DecidedAddress().IsSet());

    // Voters decide; -externalip does not join them.
    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "1.2.3.4");
    EXPECT_EQ(DecidedAddress().nVotes, 8);

    RemoveLocal(externalIp);
    ResetDecidedAddress();
}

TEST(DecidedAddress, ChangedTimeMovesOnlyWithTheAddress)
{
    SelectParams(CBaseChainParams::MAIN);
    ResetDecidedAddress();
    SetMockTime(1700000100);
    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    ASSERT_EQ(DecidedAddress().nChanged, 1700000100);

    // More votes behind the same address: the count follows, the time does not.
    SetMockTime(1700000200);
    UpdateWithPeers(Dialled(9, "1.2.3.4"));
    EXPECT_EQ(DecidedAddress().nVotes, 9);
    EXPECT_EQ(DecidedAddress().nChanged, 1700000100);

    SetMockTime(1700000300);
    UpdateWithPeers(Dialled(8, "5.6.7.8"));
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "5.6.7.8");
    EXPECT_EQ(DecidedAddress().nChanged, 1700000300);

    ResetDecidedAddress();
    SetMockTime(0);
}

TEST(DecidedAddress, ConfirmIpCarriesThePort)
{
    EXPECT_EQ(FluxnodeConfirmIp("1.2.3.4", FLUXOS_DEFAULT_PORT), "1.2.3.4:16127");
    EXPECT_EQ(FluxnodeConfirmIp("1.2.3.4", 16137), "1.2.3.4:16137");
}

TEST(DecidedAddress, IpChangeConfirmDue)
{
    const int nMin = FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1;

    // The ip the confirm would carry is the record's: nothing to carry. A record
    // that names no port is the host at 16127.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4:16127", 100, "1.2.3.4:16127", 100 + 400));
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4", 100, "1.2.3.4:16127", 100 + 400));
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4:16137", 100, "1.2.3.4:16137", 100 + 400));
    // No confirm ip: nothing to carry.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4", 100, "", 100 + 400));

    // A changed host, same port, is due once the chain accepts an address change.
    EXPECT_FALSE(IpChangeConfirmDue("1.2.3.4:16137", 100, "5.6.7.8:16137", 100 + nMin - 1));
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4:16137", 100, "5.6.7.8:16137", 100 + nMin));
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4", 100, "5.6.7.8:16127", 100 + nMin));
    EXPECT_TRUE(IpChangeConfirmDue("", 100, "5.6.7.8:16127", 100 + nMin));

    // A changed port, same host, is a change too, to or from the default.
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4:16137", 100, "1.2.3.4:16147", 100 + nMin));
    EXPECT_TRUE(IpChangeConfirmDue("1.2.3.4:16137", 100, "1.2.3.4:16127", 100 + nMin));
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
    EXPECT_FALSE(cache.CheckIfNeedsIpChangeConfirm(out, nLast + FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1 - 2, "5.6.7.8:16127"));
    EXPECT_TRUE(cache.CheckIfNeedsIpChangeConfirm(out, nLast + FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1 - 1, "5.6.7.8:16127"));
    // The record names no port: it is the host at 16127, so the same address is not a change.
    EXPECT_FALSE(cache.CheckIfNeedsIpChangeConfirm(out, nLast + 400, "1.2.3.4:16127"));
    EXPECT_TRUE(cache.CheckIfNeedsIpChangeConfirm(out, nLast + 400, "1.2.3.4:16137"));
    // The cadence alone does not report an address change as due.
    EXPECT_FALSE(cache.CheckIfNeedsNextConfirm(out, nLast + FLUXNODE_CONFIRM_UPDATE_MIN_HEIGHT_IP_CHANGE_V1));
    // A node that is not confirmed is never due.
    EXPECT_FALSE(cache.CheckIfNeedsIpChangeConfirm(COutPoint(uint256S("02"), 0), nLast + 400, "5.6.7.8"));
}

TEST(DecidedAddress, ConfirmedHostIsTheRecordsAddress)
{
    FluxnodeCache cache;
    const auto fRecord = [&](const char* strOut, const char* strIp) {
        COutPoint out(uint256S(strOut), 0);
        FluxnodeCacheData data;
        data.collateralIn = out;
        data.ip = strIp;
        cache.mapConfirmedFluxnodeData[out] = data;
        return out;
    };

    // With a port or without one, the host is the address.
    ASSERT_TRUE(cache.ConfirmedHost(fRecord("01", "1.2.3.4:16137")).has_value());
    EXPECT_EQ(cache.ConfirmedHost(fRecord("01", "1.2.3.4:16137"))->ToStringIP(), "1.2.3.4");
    ASSERT_TRUE(cache.ConfirmedHost(fRecord("02", "5.6.7.8")).has_value());
    EXPECT_EQ(cache.ConfirmedHost(fRecord("02", "5.6.7.8"))->ToStringIP(), "5.6.7.8");
    // No address in the record, nothing an address parses from, or no confirmed record.
    EXPECT_FALSE(cache.ConfirmedHost(fRecord("03", "")).has_value());
    EXPECT_FALSE(cache.ConfirmedHost(fRecord("04", "not an address")).has_value());
    EXPECT_FALSE(cache.ConfirmedHost(COutPoint(uint256S("05"), 0)).has_value());
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

    // Only apiPort matters; every fluxnode API port reads.
    for (int nPort = FLUXOS_DEFAULT_PORT; nPort <= FLUXOS_DEFAULT_PORT + 70; nPort += 10) {
        file.Write(strprintf(R"({"apiPort": %d, "uiPort": "x"})", nPort));
        EXPECT_EQ(file.Read().nPort, nPort) << nPort;
        EXPECT_EQ(file.Read().strSource, "file") << nPort;
    }
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
        // Valid TCP ports that no fluxnode's FluxOS serves on.
        R"({"apiPort": 1})",
        R"({"apiPort": 65535})",
        R"({"apiPort": 16117})",
        R"({"apiPort": 16126})",
        R"({"apiPort": 16128})",
        R"({"apiPort": 16132})",
        R"({"apiPort": 16207})",
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
    std::filesystem::remove(file.path);
    std::filesystem::create_directories(file.path);
    EXPECT_FALSE(file.Read().IsSet());
    EXPECT_FALSE(file.Read(true).IsSet());
}

TEST(DecidedAddress, FluxOSApiPortsAreTheEight)
{
    for (int nPort = FLUXOS_DEFAULT_PORT; nPort <= FLUXOS_DEFAULT_PORT + 70; nPort += 10) {
        EXPECT_TRUE(IsFluxOSApiPort(nPort)) << nPort;
        EXPECT_FALSE(IsFluxOSApiPort(nPort - 1)) << nPort - 1;
        EXPECT_FALSE(IsFluxOSApiPort(nPort + 1)) << nPort + 1;
    }
    EXPECT_FALSE(IsFluxOSApiPort(FLUXOS_DEFAULT_PORT - 10));
    EXPECT_FALSE(IsFluxOSApiPort(FLUXOS_DEFAULT_PORT + 80));
    EXPECT_FALSE(IsFluxOSApiPort(0));
    EXPECT_FALSE(IsFluxOSApiPort(-1));
    EXPECT_FALSE(IsFluxOSApiPort(65535));
    EXPECT_FALSE(IsFluxOSApiPort(99999999999999LL));
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
    // Runs where no FluxOS has published its port.
    ASSERT_FALSE(std::filesystem::exists(FLUXOS_PORT_FILE)) << FLUXOS_PORT_FILE << " exists on this host";

    std::string strIp, strMissing;

    // Mainnet: the port file is absent, so the port is.
    SelectParams(CBaseChainParams::MAIN);
    ResetDecidedAddress();
    EXPECT_FALSE(GetConfirmIp(strIp, strMissing));
    EXPECT_NE(strMissing.find("no decided address"), std::string::npos) << strMissing;
    EXPECT_NE(strMissing.find("no FluxOS port"), std::string::npos) << strMissing;

    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    EXPECT_FALSE(GetConfirmIp(strIp, strMissing));
    EXPECT_EQ(strMissing.find("no decided address"), std::string::npos) << strMissing;
    EXPECT_NE(strMissing.find("no FluxOS port"), std::string::npos) << strMissing;

    // Regtest: an absent port file reads as the default port, so the host alone decides.
    SelectParams(CBaseChainParams::REGTEST);
    ResetDecidedAddress();
    EXPECT_FALSE(GetConfirmIp(strIp, strMissing));
    EXPECT_NE(strMissing.find("no decided address"), std::string::npos) << strMissing;
    EXPECT_EQ(strMissing.find("no FluxOS port"), std::string::npos) << strMissing;

    UpdateWithPeers(Dialled(1, "1.2.3.4"));
    strMissing.clear();
    ASSERT_TRUE(GetConfirmIp(strIp, strMissing)) << strMissing;
    EXPECT_EQ(strIp, "1.2.3.4:16127");

    ResetDecidedAddress();
    SelectParams(CBaseChainParams::MAIN);
}

namespace {

// A fresh temporary directory, removed with the object.
class TempDir
{
public:
    TempDir()
    {
        path = std::filesystem::temp_directory_path() / strprintf("flux-decided-%d-%d", getpid(), counter++);
        std::filesystem::create_directories(path);
    }
    ~TempDir() { std::filesystem::remove_all(path); }

    std::filesystem::path path;

private:
    static inline int counter = 0;
};

std::string ReadText(const std::filesystem::path& path)
{
    std::ifstream file(path);
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

UniValue ReadJson(const std::filesystem::path& path)
{
    const std::string str = ReadText(path);
    UniValue json;
    EXPECT_TRUE(json.read(str)) << str;
    return json;
}

std::vector<std::string> Entries(const std::filesystem::path& dir)
{
    std::vector<std::string> names;
    for (const auto& entry : std::filesystem::directory_iterator(dir))
        names.push_back(entry.path().filename().string());
    std::sort(names.begin(), names.end());
    return names;
}

} // namespace

TEST(DecidedAddress, FileWrittenWithAddressPidAndRpcPort)
{
    TempDir tmp;
    // The directory is created when absent.
    const std::filesystem::path dir = tmp.path / "fluxd";

    DecidedAddressInfo info;
    info.address = Addr("178.79.183.164");
    info.fSet = true;
    info.nChanged = 1792067007;
    std::string strError;
    ASSERT_TRUE(WriteDecidedAddressFile(dir, info, 12345, 16124, strError)) << strError;

    // Written by rename: the final name and nothing else.
    EXPECT_EQ(Entries(dir), std::vector<std::string>{DECIDED_ADDRESS_FILE});
    const UniValue json = ReadJson(dir / DECIDED_ADDRESS_FILE);
    ASSERT_TRUE(json.isObject());
    EXPECT_EQ(json.size(), 3u);
    EXPECT_EQ(find_value(json, "address").get_str(), "178.79.183.164");
    EXPECT_EQ(find_value(json, "pid").get_int(), 12345);
    EXPECT_EQ(find_value(json, "rpcport").get_int(), 16124);

    using std::filesystem::perms;
    EXPECT_EQ(std::filesystem::status(dir / DECIDED_ADDRESS_FILE).permissions() & perms::all, perms(0644));
    EXPECT_EQ(std::filesystem::status(dir).permissions() & perms::all, perms(0755));

    // Nothing decided: an empty address.
    ASSERT_TRUE(WriteDecidedAddressFile(dir, DecidedAddressInfo(), 12345, 16124, strError)) << strError;
    const UniValue none = ReadJson(dir / DECIDED_ADDRESS_FILE);
    EXPECT_EQ(none.size(), 3u);
    EXPECT_EQ(find_value(none, "address").get_str(), "");
    EXPECT_EQ(find_value(none, "rpcport").get_int(), 16124);
    EXPECT_EQ(Entries(dir), std::vector<std::string>{DECIDED_ADDRESS_FILE});
}

TEST(DecidedAddress, FileReplacesAMalformedOne)
{
    TempDir tmp;
    std::ofstream(tmp.path / DECIDED_ADDRESS_FILE) << "{not json";

    DecidedAddressInfo info;
    info.address = Addr("1.2.3.4");
    info.fSet = true;
    info.nChanged = 1700000000;
    std::string strError;
    ASSERT_TRUE(WriteDecidedAddressFile(tmp.path, info, 7, 16124, strError)) << strError;
    EXPECT_EQ(find_value(ReadJson(tmp.path / DECIDED_ADDRESS_FILE), "address").get_str(), "1.2.3.4");
    EXPECT_EQ(Entries(tmp.path), std::vector<std::string>{DECIDED_ADDRESS_FILE});
}

TEST(DecidedAddress, FileWriteFailureReportedNotThrown)
{
    TempDir tmp;
    // The directory's path is a regular file.
    const std::filesystem::path dir = tmp.path / "notadir";
    std::ofstream(dir) << "x";

    std::string strError;
    bool fWritten = true;
    EXPECT_NO_THROW(fWritten = WriteDecidedAddressFile(dir, DecidedAddressInfo(), 7, 16124, strError));
    EXPECT_FALSE(fWritten);
    EXPECT_FALSE(strError.empty());

    // Publishing there logs and carries on.
    EXPECT_NO_THROW(StartPublishingDecidedAddress(dir));
    EXPECT_NO_THROW(StopPublishingDecidedAddress());
    EXPECT_EQ(Entries(tmp.path), std::vector<std::string>{"notadir"});
}

TEST(DecidedAddress, FilePublishedOnChangeAndRemovedOnStop)
{
    SelectParams(CBaseChainParams::MAIN);
    TempDir tmp;
    SetMockTime(1700000500);
    ResetDecidedAddress();

    // At start: nothing decided yet.
    StartPublishingDecidedAddress(tmp.path);
    UniValue json = ReadJson(tmp.path / DECIDED_ADDRESS_FILE);
    EXPECT_EQ(find_value(json, "address").get_str(), "");
    EXPECT_EQ(find_value(json, "pid").get_int(), getpid());

    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    json = ReadJson(tmp.path / DECIDED_ADDRESS_FILE);
    EXPECT_EQ(find_value(json, "address").get_str(), "1.2.3.4");

    // Votes coming and going behind the same address, down to none, leave the file as it is.
    std::ofstream(tmp.path / DECIDED_ADDRESS_FILE) << "untouched";
    UpdateWithPeers(Dialled(9, "1.2.3.4"));
    UpdateWithPeers(Dialled(3, "1.2.3.4"));
    UpdateWithPeers({});
    EXPECT_EQ(ReadText(tmp.path / DECIDED_ADDRESS_FILE), "untouched");
    EXPECT_EQ(DecidedAddress().address.ToStringIP(), "1.2.3.4");

    // A new address rewrites it.
    UpdateWithPeers(Dialled(8, "5.6.7.8"));
    EXPECT_EQ(find_value(ReadJson(tmp.path / DECIDED_ADDRESS_FILE), "address").get_str(), "5.6.7.8");

    StopPublishingDecidedAddress();
    EXPECT_TRUE(Entries(tmp.path).empty());

    // Once stopped, a change writes nothing.
    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    EXPECT_TRUE(Entries(tmp.path).empty());
    ResetDecidedAddress();
    SetMockTime(0);
}

TEST(DecidedAddress, FileRemoval)
{
    TempDir tmp;
    std::string strError;
    ASSERT_TRUE(WriteDecidedAddressFile(tmp.path, DecidedAddressInfo(), 7, 16124, strError)) << strError;
    EXPECT_TRUE(RemoveDecidedAddressFile(tmp.path, strError)) << strError;
    EXPECT_TRUE(Entries(tmp.path).empty());
    // Already gone: not a failure.
    EXPECT_TRUE(RemoveDecidedAddressFile(tmp.path, strError)) << strError;
}

TEST(DecidedAddress, FileWriteFailureLoggedOnce)
{
    DecidedAddressWriteLog log;
    int nLogged = 0;
    for (int i = 0; i < 10; i++)
        nLogged += !log.Outcome(false, "cannot create /run/fluxd: Permission denied").empty();
    EXPECT_EQ(nLogged, 1);

    // A success after failures logs once; later successes log nothing.
    nLogged = 0;
    for (int i = 0; i < 3; i++)
        nLogged += !log.Outcome(true, "").empty();
    EXPECT_EQ(nLogged, 1);

    // Successes alone log nothing; a new failure, and a different reason, each log once.
    DecidedAddressWriteLog fresh;
    EXPECT_TRUE(fresh.Outcome(true, "").empty());
    EXPECT_FALSE(fresh.Outcome(false, "reason a").empty());
    EXPECT_TRUE(fresh.Outcome(false, "reason a").empty());
    EXPECT_FALSE(fresh.Outcome(false, "reason b").empty());
}

TEST(DecidedAddress, PublisherInertUnlessStarted)
{
    SelectParams(CBaseChainParams::MAIN);
    ASSERT_FALSE(IsPublishingDecidedAddress());
    ASSERT_FALSE(std::filesystem::exists(DecidedAddressFileDir() / DECIDED_ADDRESS_FILE));

    ResetDecidedAddress();
    UpdateWithPeers(Dialled(8, "1.2.3.4"));
    ResetDecidedAddress();
    EXPECT_FALSE(IsPublishingDecidedAddress());
    EXPECT_FALSE(std::filesystem::exists(DecidedAddressFileDir() / DECIDED_ADDRESS_FILE));

    TempDir tmp;
    StartPublishingDecidedAddress(tmp.path);
    EXPECT_TRUE(IsPublishingDecidedAddress());
    StopPublishingDecidedAddress();
    EXPECT_FALSE(IsPublishingDecidedAddress());
}
