// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <key_io.h>
#include <flux/Address.hpp>
#include <flux/zip32.h>

#include "utiltest.h"

#include <gtest/gtest.h>

TEST(Keys, EncodeAndDecodeSapling)
{
    SelectParams(CBaseChainParams::MAIN);

    auto m = GetTestMasterSaplingSpendingKey();

    for (uint32_t i = 0; i < 1000; i++) {
        auto sk = m.Derive(i);
        {
            std::string sk_string = EncodeSpendingKey(sk);
            EXPECT_EQ(
                sk_string.substr(0, 24),
                Params().Bech32HRP(CChainParams::SAPLING_EXTENDED_SPEND_KEY));

            auto spendingkey2 = DecodeSpendingKey(sk_string);
            EXPECT_TRUE(IsValidSpendingKey(spendingkey2));

            ASSERT_TRUE(boost::get<libflux::SaplingExtendedSpendingKey>(&spendingkey2) != nullptr);
            auto sk2 = boost::get<libflux::SaplingExtendedSpendingKey>(spendingkey2);
            EXPECT_EQ(sk, sk2);
        }
        {
            auto addr = sk.DefaultAddress();

            std::string addr_string = EncodePaymentAddress(addr);
            EXPECT_EQ(
                addr_string.substr(0, 2),
                Params().Bech32HRP(CChainParams::SAPLING_PAYMENT_ADDRESS));

            auto paymentaddr2 = DecodePaymentAddress(addr_string);
            EXPECT_TRUE(IsValidPaymentAddress(paymentaddr2));

            ASSERT_TRUE(boost::get<libflux::SaplingPaymentAddress>(&paymentaddr2) != nullptr);
            auto addr2 = boost::get<libflux::SaplingPaymentAddress>(paymentaddr2);
            EXPECT_EQ(addr, addr2);
        }
    }
}
