// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "net.h"
#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <filesystem>

BOOST_FIXTURE_TEST_SUITE(net_reseed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(anchor_db_write_read)
{
    // Create test addresses
    std::vector<CAddress> anchorsWrite;
    CAddress addr1(CService("1.2.3.4", 16125));
    addr1.nTime = 1000;
    CAddress addr2(CService("5.6.7.8", 16125));
    addr2.nTime = 2000;
    anchorsWrite.push_back(addr1);
    anchorsWrite.push_back(addr2);

    // Write anchors to disk
    CAnchorDB anchordb;
    BOOST_CHECK(anchordb.Write(anchorsWrite));

    // Read anchors back
    std::vector<CAddress> anchorsRead;
    BOOST_CHECK(anchordb.Read(anchorsRead));

    // Verify round-trip
    BOOST_CHECK_EQUAL(anchorsRead.size(), 2);
    BOOST_CHECK(anchorsRead[0].ToStringIPPort() == addr1.ToStringIPPort());
    BOOST_CHECK(anchorsRead[1].ToStringIPPort() == addr2.ToStringIPPort());

    // File should be deleted after read (one-shot behavior)
    std::filesystem::path pathAnchor = GetDataDir() / "anchors.dat";
    BOOST_CHECK(!std::filesystem::exists(pathAnchor));
}

BOOST_AUTO_TEST_CASE(anchor_db_empty)
{
    // Ensure no anchors.dat exists
    std::filesystem::path pathAnchor = GetDataDir() / "anchors.dat";
    std::filesystem::remove(pathAnchor);

    // Attempt to read non-existent anchors.dat
    std::vector<CAddress> anchors;
    CAnchorDB anchordb;
    BOOST_CHECK(!anchordb.Read(anchors));

    // Vector should be empty
    BOOST_CHECK(anchors.empty());
}

BOOST_AUTO_TEST_CASE(anchor_db_max_limit)
{
    // Write 5 addresses
    std::vector<CAddress> anchorsWrite;
    for (int i = 1; i <= 5; i++) {
        CAddress addr(CService("1.2.3." + std::to_string(i), 16125));
        addr.nTime = i * 1000;
        anchorsWrite.push_back(addr);
    }
    CAnchorDB anchordb;
    BOOST_CHECK(anchordb.Write(anchorsWrite));

    // Read back - all 5 should be present in the file
    std::vector<CAddress> anchorsRead;
    BOOST_CHECK(anchordb.Read(anchorsRead));
    BOOST_CHECK_EQUAL(anchorsRead.size(), 5);

    // In practice, StartNode() caps to MAX_ANCHOR_CONNECTIONS (2),
    // but CAnchorDB itself stores all addresses faithfully
}

BOOST_AUTO_TEST_SUITE_END()
