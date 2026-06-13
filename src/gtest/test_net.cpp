// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "net.h"
#include "netbase.h"
#include "protocol.h"

// CNode::GetEffectiveAddr / GetEffectiveAddrName expose the peer's verified
// .onion once a torauth onion proof has been validated, and the connect-time
// socket address otherwise. addr/addrName stay write-once at connect, so
// concurrent readers never race a reassignment. The torauth onion-proof and
// onion-ban paths depend on this contract.
TEST(NetTests, GetEffectiveAddr)
{
    CService sock("127.0.0.1", 16125, false);
    // Heap-allocated and intentionally not freed: ~CNode drives FinalizeNode
    // signal wiring that only exists in a fully initialized node, not a unit test.
    CNode* node = new CNode(INVALID_SOCKET, CAddress(sock), "127.0.0.1:16125", /*fInbound=*/true);

    // Before verification: the effective address/name is the socket address.
    EXPECT_FALSE(node->fTorAddrVerified);
    EXPECT_FALSE(node->GetEffectiveAddr().IsTor());
    EXPECT_EQ(node->GetEffectiveAddrName(), "127.0.0.1:16125");

    // Record a verified onion, mirroring what the torauthresp handler does.
    CService onion("p6o2vv3o23tvth5ozzlbchgnxgtxkptf47ge43vhrhglpuohfxnbyfid.onion", 16125, false);
    ASSERT_TRUE(onion.IsTor());
    node->torVerifiedAddr = onion;
    node->fTorAddrVerified = true;

    // After verification: the effective address/name is the verified onion.
    EXPECT_TRUE(node->GetEffectiveAddr().IsTor());
    EXPECT_EQ(node->GetEffectiveAddrName(), onion.ToStringIPPort());
}

// A CSubNet built from a v3 onion must match that exact onion and nothing else,
// so bans against an onion peer are effective (it used to be flattened to ::/128
// and Match() returned false for any onion, making onion bans a no-op).
TEST(NetTests, OnionSubnetMatch)
{
    CNetAddr onionA = CService("p6o2vv3o23tvth5ozzlbchgnxgtxkptf47ge43vhrhglpuohfxnbyfid.onion", 0, false);
    CNetAddr onionB = CService("in5ffm447ysvr4q4ma4gdgmychtpcb3emlnbfe4r3mhnb4ctlje6jmyd.onion", 0, false);
    CNetAddr ip4 = CService("1.2.3.4", 0, false);
    ASSERT_TRUE(onionA.IsTor());
    ASSERT_TRUE(onionB.IsTor());
    ASSERT_TRUE(ip4.IsIPv4());

    // A single-onion ban matches that onion only.
    CSubNet banA(onionA.ToString() + "/128");
    ASSERT_TRUE(banA.IsValid());
    EXPECT_TRUE(banA.Match(onionA));
    EXPECT_FALSE(banA.Match(onionB));
    EXPECT_FALSE(banA.Match(ip4));

    // An IPv4 subnet never matches an onion, and still matches IPv4 normally.
    CSubNet ip4net("1.2.3.0/24");
    ASSERT_TRUE(ip4net.IsValid());
    EXPECT_FALSE(ip4net.Match(onionA));
    EXPECT_TRUE(ip4net.Match(CService("1.2.3.99", 0, false)));
}

// v3 onions must be spread across netgroups by the top bits of their pubkey,
// not collapsed into one bucket (which let cheap mass-onion advertising evict
// honest onion entries). Each group is {NET_ONION, nibble} (size 2), and a set
// of distinct onions spans more than one group.
TEST(NetTests, OnionNetGroup)
{
    const char* onions[] = {
        "p6o2vv3o23tvth5ozzlbchgnxgtxkptf47ge43vhrhglpuohfxnbyfid.onion",
        "in5ffm447ysvr4q4ma4gdgmychtpcb3emlnbfe4r3mhnb4ctlje6jmyd.onion",
        "jfb4rhv24cmqi3ccmua2eo623qjv67nbl7jt7zd6mq5xyschv3pgmgyd.onion",
        "4i3jh7kntubirk6jxqizfxkjucjtdcuipn26meabbr76krxpcqou4lad.onion",
        "yksgaaldptn6lxsbem6cdtxmbygq7c3llag3pjv6es5rgrsawhcup2ad.onion",
    };
    std::set<std::vector<unsigned char> > groups;
    for (const char* s : onions) {
        CNetAddr a = CService(s, 0, false);
        ASSERT_TRUE(a.IsTor());
        std::vector<unsigned char> g = a.GetGroup();
        ASSERT_EQ(g.size(), 2u);            // {NET_ONION, pubkey-derived byte}, no longer a lone NET_ONION
        EXPECT_EQ(g[0], (unsigned char)NET_ONION);
        groups.insert(g);
    }
    // Distinct onions must not all collapse into a single netgroup.
    EXPECT_GT(groups.size(), 1u);
    // The same onion always hashes to the same group.
    EXPECT_EQ(CService(onions[0], 0, false).GetGroup(),
              CService(onions[0], 0, false).GetGroup());
}
