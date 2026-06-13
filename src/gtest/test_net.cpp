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
