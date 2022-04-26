// Copyright (C) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "primitives/block.h"


TEST(block_tests, header_size_is_expected) {
    // Dummy header with an empty Equihash solution.
    CBlockHeader header;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << header;

    ASSERT_EQ(ss.size(), CBlockHeader::HEADER_SIZE);
}
