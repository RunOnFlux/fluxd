// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// The outbound slots: the connections a node dials and keeps are capped at the
// slots, and the feeler has a permit of its own beyond them.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "net.h"
#include "netbase.h"
#include "tinyformat.h"

#include <algorithm>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

TEST(OutboundSlots, FeelerRunsWithEverySlotInUse)
{
    EXPECT_EQ(NextOutboundDial(/*fFeelerDue=*/true, /*fSlotsFull=*/true), OutboundDial::Feeler);
    EXPECT_EQ(NextOutboundDial(true, false), OutboundDial::Feeler);
    EXPECT_EQ(NextOutboundDial(false, true), OutboundDial::None);
    EXPECT_EQ(NextOutboundDial(false, false), OutboundDial::Kept);
}

TEST(OutboundSlots, FullCountsOnlyKeptDialledConnections)
{
    LOCK(cs_vNodes);
    std::vector<CNode*> nodes;
    const auto fAdd = [&](int i, bool fInbound) {
        CNode* node = new CNode(INVALID_SOCKET, CAddress(CService(strprintf("20.%d.0.1", 1 + i).c_str(), 16125, false)), "", fInbound);
        vNodes.push_back(node);
        nodes.push_back(node);
        return node;
    };
    for (int i = 0; i < MAX_OUTBOUND_CONNECTIONS - 1; i++)
        fAdd(i, false);
    fAdd(100, true);
    fAdd(101, false)->fFeeler = true;
    fAdd(102, false)->fOneShot = true;
    fAdd(103, false)->fDisconnect = true;
    EXPECT_FALSE(OutboundSlotsFull());

    CNode* last = fAdd(104, false);
    EXPECT_TRUE(OutboundSlotsFull());

    // A listener on loopback, so that a dial succeeds whenever one is made.
    const int nListen = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(nListen, 0);
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(bind(nListen, (sockaddr*)&sin, sizeof(sin)), 0);
    ASSERT_EQ(listen(nListen, 4), 0);
    socklen_t nLen = sizeof(sin);
    ASSERT_EQ(getsockname(nListen, (sockaddr*)&sin, &nLen), 0);
    const CAddress addrListener(CService("127.0.0.1", ntohs(sin.sin_port), false));

    // With the slots full a kept connection is refused; with one free it is made.
    EXPECT_FALSE(OpenNetworkConnection(addrListener));
    EXPECT_EQ(FindNode((CService)addrListener), nullptr);
    last->fDisconnect = true;
    EXPECT_TRUE(OpenNetworkConnection(addrListener));
    CNode* dialled = FindNode((CService)addrListener);
    ASSERT_NE(dialled, nullptr);
    dialled->CloseSocketDisconnect();
    nodes.push_back(dialled);
    close(nListen);

    for (CNode* node : nodes)
        vNodes.erase(std::remove(vNodes.begin(), vNodes.end(), node), vNodes.end());
}
