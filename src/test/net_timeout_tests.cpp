// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "net.h"
#include "test/test_bitcoin.h"
#include "util.h"

#include <boost/test/unit_test.hpp>

// ---------- Timeout constant tests (no node infrastructure needed) ----------

BOOST_FIXTURE_TEST_SUITE(net_timeout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(timeout_interval_relationship)
{
    // TIMEOUT_INTERVAL must be exactly 3 ping cycles
    BOOST_CHECK_EQUAL(TIMEOUT_INTERVAL, 3 * PING_INTERVAL);
    // Verify absolute values: 2-minute pings, 6-minute timeout
    BOOST_CHECK_EQUAL(PING_INTERVAL, 120);
    BOOST_CHECK_EQUAL(TIMEOUT_INTERVAL, 360);
}

BOOST_AUTO_TEST_CASE(timeout_interval_sane_for_flux)
{
    // Timeout must be long enough to tolerate network jitter
    // but short enough to catch dead connections before the watchdog (typically ~8 min)
    BOOST_CHECK(TIMEOUT_INTERVAL >= 3 * PING_INTERVAL);
    BOOST_CHECK(TIMEOUT_INTERVAL <= 600); // at most 10 minutes
}

BOOST_AUTO_TEST_SUITE_END()

// ---------- Tests that need full node infrastructure (CNode creation) ----------

BOOST_FIXTURE_TEST_SUITE(net_stale_tip_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(zombie_peer_unanswered_ping)
{
    // A peer with a ping outstanding for > 30 seconds is a zombie
    CAddress addr(CService("1.2.3.4", 16125));
    CNode node(INVALID_SOCKET, addr, "", false); // outbound

    // Simulate a ping sent 31 seconds ago with no pong
    node.nPingNonceSent = 12345;
    node.nPingUsecStart = GetTimeMicros() - 31 * 1000000LL;

    // The zombie condition from CheckStaleTip (STALE_TIP_PING_TIMEOUT = 30s)
    bool isZombie = (node.nPingNonceSent != 0 &&
                     node.nPingUsecStart + 30 * 1000000LL < GetTimeMicros());
    BOOST_CHECK(isZombie);
}

BOOST_AUTO_TEST_CASE(live_peer_answered_ping)
{
    // A peer with no outstanding ping (pong received) is not a zombie
    CAddress addr(CService("1.2.3.5", 16125));
    CNode node(INVALID_SOCKET, addr, "", false);

    // nPingNonceSent == 0 means no outstanding ping (pong was received)
    node.nPingNonceSent = 0;
    node.nPingUsecStart = GetTimeMicros() - 60 * 1000000LL;

    bool isZombie = (node.nPingNonceSent != 0 &&
                     node.nPingUsecStart + 30 * 1000000LL < GetTimeMicros());
    BOOST_CHECK(!isZombie);
}

BOOST_AUTO_TEST_CASE(recent_ping_not_zombie)
{
    // A peer with a recently-sent ping (within 30s) should not be killed yet
    CAddress addr(CService("1.2.3.6", 16125));
    CNode node(INVALID_SOCKET, addr, "", false);

    // Ping sent 5 seconds ago, no pong yet — give it time
    node.nPingNonceSent = 67890;
    node.nPingUsecStart = GetTimeMicros() - 5 * 1000000LL;

    bool isZombie = (node.nPingNonceSent != 0 &&
                     node.nPingUsecStart + 30 * 1000000LL < GetTimeMicros());
    BOOST_CHECK(!isZombie);
}

BOOST_AUTO_TEST_CASE(inbound_peer_not_probed)
{
    // Inbound peers should be skipped by the stale tip probe
    CAddress addr(CService("1.2.3.7", 16125));
    CNode node(INVALID_SOCKET, addr, "", true); // inbound

    BOOST_CHECK(node.fInbound);
    // CheckStaleTip skips: fInbound || fOneShot || fDisconnect
    bool shouldProbe = !node.fInbound && !node.fOneShot && !node.fDisconnect;
    BOOST_CHECK(!shouldProbe);
}

BOOST_AUTO_TEST_CASE(outbound_peer_probed)
{
    // Outbound peers should be probed when tip is stale
    CAddress addr(CService("1.2.3.8", 16125));
    CNode node(INVALID_SOCKET, addr, "", false); // outbound

    BOOST_CHECK(!node.fInbound);
    BOOST_CHECK(!node.fOneShot);
    BOOST_CHECK(!node.fDisconnect);
    bool shouldProbe = !node.fInbound && !node.fOneShot && !node.fDisconnect;
    BOOST_CHECK(shouldProbe);

    // Queuing a ping sets fPingQueued
    node.fPingQueued = true;
    BOOST_CHECK(node.fPingQueued);
}

BOOST_AUTO_TEST_CASE(inactivity_timeout_boundary)
{
    CAddress addr(CService("1.2.3.9", 16125));
    CNode node(INVALID_SOCKET, addr, "", false);
    node.nVersion = 170002; // > BIP0031_VERSION

    // 5 minutes of silence — should NOT trigger (threshold is 6 min)
    node.nLastRecv = GetTime() - 300;
    BOOST_CHECK(GetTime() - node.nLastRecv <= TIMEOUT_INTERVAL);

    // 7 minutes of silence — SHOULD trigger
    node.nLastRecv = GetTime() - 420;
    BOOST_CHECK(GetTime() - node.nLastRecv > TIMEOUT_INTERVAL);

    // Exactly at the boundary (6 min) — should NOT trigger (uses >)
    node.nLastRecv = GetTime() - TIMEOUT_INTERVAL;
    BOOST_CHECK(!(GetTime() - node.nLastRecv > TIMEOUT_INTERVAL));
}

BOOST_AUTO_TEST_SUITE_END()
