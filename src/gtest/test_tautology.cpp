// Copyright (C) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

TEST(tautologies, seven_eq_seven) {
    ASSERT_EQ(7, 7);
}

TEST(tautologies, DISABLED_ObviousFailure)
{
    FAIL() << "This is expected";
}
