// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "checkpoints.h"
#include "coins.h"
#include "emergencyblock.h"
#include "fluxnode/benchmarks.h"
#include "fluxnode/fluxnode.h"
#include "key.h"
#include "key_io.h"
#include "main.h"
#include "pon/pon-fork.h"
#include "random.h"
#include "util.h"

namespace {

class LabNet : public ::testing::Test {
protected:
    void SetUp() override { SelectParams(CBaseChainParams::LABNET); }
    void TearDown() override
    {
        mapArgs.erase("-labnet");
        mapArgs.erase("-testnet");
        mapArgs.erase("-regtest");
        SelectParams(CBaseChainParams::MAIN);
    }
};

} // namespace

TEST_F(LabNet, ItsOwnNetwork)
{
    const CChainParams& lab = Params(CBaseChainParams::LABNET);
    const CChainParams& main = Params(CBaseChainParams::MAIN);
    const CChainParams& test = Params(CBaseChainParams::TESTNET);

    EXPECT_EQ(lab.NetworkIDString(), "labnet");
    EXPECT_EQ(lab.GetDefaultPort(), 36125);
    EXPECT_EQ(BaseParams().RPCPort(), 36124);
    EXPECT_EQ(BaseParams().DataDir(), "labnet");

    EXPECT_NE(lab.GenesisBlock().GetHash(), main.GenesisBlock().GetHash());
    EXPECT_NE(lab.GenesisBlock().GetHash(), test.GenesisBlock().GetHash());
    EXPECT_NE(memcmp(lab.MessageStart(), main.MessageStart(), 4), 0);
    EXPECT_NE(memcmp(lab.MessageStart(), test.MessageStart(), 4), 0);

    // testnet's address prefixes
    EXPECT_EQ(lab.Base58Prefix(CChainParams::PUBKEY_ADDRESS), test.Base58Prefix(CChainParams::PUBKEY_ADDRESS));
    EXPECT_EQ(lab.Base58Prefix(CChainParams::SECRET_KEY), test.Base58Prefix(CChainParams::SECRET_KEY));
    EXPECT_TRUE(IsValidDestination(DecodeDestination(lab.GetDevFundAddress())));
}

TEST_F(LabNet, OneNetworkFlagAtATime)
{
    mapArgs["-labnet"] = "1";
    EXPECT_EQ(NetworkIdFromCommandLine(), CBaseChainParams::LABNET);
    mapArgs["-testnet"] = "1";
    EXPECT_EQ(NetworkIdFromCommandLine(), CBaseChainParams::MAX_NETWORK_TYPES);
    mapArgs.erase("-testnet");
    mapArgs["-regtest"] = "1";
    EXPECT_EQ(NetworkIdFromCommandLine(), CBaseChainParams::MAX_NETWORK_TYPES);
}

TEST_F(LabNet, PremineAtBlockOneThenPoN)
{
    const Consensus::Params& consensus = Params().GetConsensus();

    EXPECT_FALSE(IsPONActive(1));
    EXPECT_TRUE(IsPONActive(2));
    EXPECT_EQ(GetBlockSubsidy(1, consensus), 13020000 * COIN);
    EXPECT_EQ(GetBlockSubsidy(2, consensus), 14 * COIN);
}

TEST_F(LabNet, OnlyTheCurrentCollateralTiers)
{
    int tier = 0;
    EXPECT_TRUE(GetCoinTierFromAmount(5, V2_FLUXNODE_COLLAT_CUMULUS * COIN, tier));
    EXPECT_EQ(tier, CUMULUS);
    EXPECT_FALSE(GetCoinTierFromAmount(5, V1_FLUXNODE_COLLAT_CUMULUS * COIN, tier));
}

TEST_F(LabNet, CompactHeadersAreNeverUsed)
{
    // A node sends compact headers only from below the last checkpoint's height.
    EXPECT_EQ(Checkpoints::GetTotalBlocksEstimate(Params().Checkpoints()), 0);
}

TEST_F(LabNet, EmergencyBlocksNeedALabKey)
{
    EXPECT_EQ(Params().GetEmergencyMinSignatures(), 1);
    EXPECT_EQ(Params().GetEmergencyPublicKeys().size(), 2u);

    CBlockHeader block;
    block.nVersion = CBlockHeader::PON_VERSION;
    block.hashPrevBlock = GetRandHash();
    block.hashMerkleRoot = GetRandHash();
    block.nTime = GetTime();
    block.nBits = 0x1e0ffff0;
    block.nodesCollateral.hash = Params().GetEmergencyCollateralHash();
    block.nodesCollateral.n = 0;

    // Unsigned, and signed by a key that is not a lab emergency key.
    EXPECT_FALSE(ValidateEmergencyBlockSignatures(block));
    CKey other;
    other.MakeNewKey(true);
    std::string error;
    ASSERT_TRUE(CreateEmergencyBlock(block, {other}, error)) << error;
    EXPECT_FALSE(ValidateEmergencyBlockSignatures(block));
}

TEST_F(LabNet, FluxbenchIsToldTheNetwork)
{
    EXPECT_NE(BenchCliCommand().find("-labnet "), std::string::npos);
    SelectParams(CBaseChainParams::TESTNET);
    EXPECT_NE(BenchCliCommand().find("-testnet "), std::string::npos);
    EXPECT_EQ(BenchCliCommand().find("-labnet "), std::string::npos);
    SelectParams(CBaseChainParams::MAIN);
    EXPECT_EQ(BenchCliCommand().find("-testnet "), std::string::npos);
    EXPECT_EQ(BenchCliCommand().find("-labnet "), std::string::npos);
}
