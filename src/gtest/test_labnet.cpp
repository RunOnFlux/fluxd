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
#include "utilstrencodings.h"

namespace {

class LabNet : public ::testing::Test {
protected:
    CKey labKey;
    void SetUp() override
    {
        SelectParams(CBaseChainParams::LABNET);
        labKey.MakeNewKey(true);
        const CPubKey pub = labKey.GetPubKey();
        std::string error;
        ASSERT_TRUE(SetLabNetKey(HexStr(pub.begin(), pub.end()), error)) << error;
    }
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

static CBlockHeader EmergencyHeader()
{
    CBlockHeader block;
    block.nVersion = CBlockHeader::PON_VERSION;
    block.hashPrevBlock = GetRandHash();
    block.hashMerkleRoot = GetRandHash();
    block.nTime = GetTime();
    block.nBits = 0x1e0ffff0;
    block.nodesCollateral.hash = Params().GetEmergencyCollateralHash();
    block.nodesCollateral.n = 0;
    return block;
}

TEST_F(LabNet, EmergencyBlocksAreSignedByTheLabKey)
{
    EXPECT_EQ(Params().GetEmergencyMinSignatures(), 1);
    ASSERT_EQ(Params().GetEmergencyPublicKeys().size(), 1u);

    std::string error;
    CBlockHeader block = EmergencyHeader();
    EXPECT_FALSE(ValidateEmergencyBlockSignatures(block)) << "unsigned";
    ASSERT_TRUE(CreateEmergencyBlock(block, {labKey}, error)) << error;
    EXPECT_TRUE(ValidateEmergencyBlockSignatures(block)) << "signed by the lab key";

    CBlockHeader other = EmergencyHeader();
    CKey otherKey;
    otherKey.MakeNewKey(true);
    ASSERT_TRUE(CreateEmergencyBlock(other, {otherKey}, error)) << error;
    EXPECT_FALSE(ValidateEmergencyBlockSignatures(other)) << "signed by another key";

    // The lab's signature means nothing on another network.
    SelectParams(CBaseChainParams::TESTNET);
    EXPECT_FALSE(ValidateEmergencyBlockSignatures(block)) << "on testnet";
    SelectParams(CBaseChainParams::MAIN);
    EXPECT_FALSE(ValidateEmergencyBlockSignatures(block)) << "on mainnet";
}

TEST_F(LabNet, EachKeyIsItsOwnNetwork)
{
    unsigned char first[4];
    memcpy(first, Params().MessageStart(), 4);

    CKey second;
    second.MakeNewKey(true);
    const CPubKey pub = second.GetPubKey();
    std::string error;
    ASSERT_TRUE(SetLabNetKey(HexStr(pub.begin(), pub.end()), error)) << error;
    EXPECT_NE(memcmp(first, Params().MessageStart(), 4), 0) << "two labs, two magics";
    EXPECT_EQ(Params().GetEmergencyPublicKeys()[0], HexStr(pub.begin(), pub.end()));

    EXPECT_FALSE(SetLabNetKey("zz", error));
    CKey uncompressed;
    uncompressed.MakeNewKey(false);
    const CPubKey u = uncompressed.GetPubKey();
    EXPECT_FALSE(SetLabNetKey(HexStr(u.begin(), u.end()), error)) << "uncompressed";
    EXPECT_FALSE(SetLabNetKey(std::string(66, '0'), error)) << "not a point";
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
