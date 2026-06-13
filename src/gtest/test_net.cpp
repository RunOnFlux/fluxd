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
