// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAINPARAMS_H
#define BITCOIN_CHAINPARAMS_H

#include "chainparamsbase.h"
#include "consensus/params.h"
#include "primitives/block.h"
#include "protocol.h"

#include <vector>

struct CDNSSeedData {
    std::string name, host;
    CDNSSeedData(const std::string &strName, const std::string &strHost) : name(strName), host(strHost) {}
};

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

struct EHparameters {
    unsigned char n;
    unsigned char k;
    unsigned short int nSolSize;
};

//EH sol size = (pow(2, k) * ((n/(k+1))+1)) / 8;
static const EHparameters eh200_9 = {200,9,1344};
static const EHparameters eh144_5 = {144,5,100};
static const EHparameters zelHash = {125,4,52};
static const EHparameters eh96_5 = {96,5,68};
static const EHparameters eh48_5 = {48,5,36};
static const unsigned int MAX_EH_PARAM_LIST_LEN = 2;

typedef std::map<int, uint256> MapCheckpoints;

struct CCheckpointData {
    MapCheckpoints mapCheckpoints;
    int64_t nTimeLastCheckpoint;
    int64_t nTransactionsLastCheckpoint;
    double fTransactionsPerDay;
};

/**
 * CChainParams defines various tweakable parameters of a given instance of the
 * Bitcoin system. There are three: the main network on which people trade goods
 * and services, the public test network which gets reset from time to time and
 * a regression test mode which is intended for private networks only. It has
 * minimal difficulty to ensure that blocks can be found instantly.
 */
class CChainParams
{
public:
    enum Base58Type {
        PUBKEY_ADDRESS,
        SCRIPT_ADDRESS,
        SECRET_KEY,
        EXT_PUBLIC_KEY,
        EXT_SECRET_KEY,

        ZCPAYMENT_ADDRRESS,
        ZCSPENDING_KEY,
        ZCVIEWING_KEY,

        MAX_BASE58_TYPES
    };

    enum Bech32Type {
        SAPLING_PAYMENT_ADDRESS,
        SAPLING_FULL_VIEWING_KEY,
        SAPLING_INCOMING_VIEWING_KEY,
        SAPLING_EXTENDED_SPEND_KEY,

        MAX_BECH32_TYPES
    };

    const Consensus::Params& GetConsensus() const { return consensus; }
    const CMessageHeader::MessageStartChars& MessageStart() const { return pchMessageStart; }
    const std::vector<unsigned char>& AlertKey() const { return vAlertPubKey; }
    int GetDefaultPort() const { return nDefaultPort; }

    CAmount SproutValuePoolCheckpointHeight() const { return nSproutValuePoolCheckpointHeight; }
    CAmount SproutValuePoolCheckpointBalance() const { return nSproutValuePoolCheckpointBalance; }
    uint256 SproutValuePoolCheckpointBlockHash() const { return hashSproutValuePoolCheckpointBlock; }
    bool ZIP209Enabled() const { return fZIP209Enabled; }

    const CBlock& GenesisBlock() const { return genesis; }
    /** Make miner wait to have peers to avoid wasting work */
    bool MiningRequiresPeers() const { return fMiningRequiresPeers; }
    /** Default value for -checkmempool and -checkblockindex argument */
    bool DefaultConsistencyChecks() const { return fDefaultConsistencyChecks; }
    /** Policy: Filter transactions that do not match well-defined patterns */
    bool RequireStandard() const { return fRequireStandard; }
    int64_t PruneAfterHeight() const { return nPruneAfterHeight; }
    EHparameters eh_epoch_1_params() const { return eh_epoch_1; }
    EHparameters eh_epoch_2_params() const { return eh_epoch_2; }
    EHparameters eh_epoch_3_params() const { return eh_epoch_3; }
    unsigned long eh_epoch_1_end() const {   return GetConsensus().vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight + GetConsensus().eh_epoch_fade_length - 1; }
    unsigned long eh_epoch_2_start() const { return GetConsensus().vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight; }
    unsigned long eh_epoch_2_end() const {   return GetConsensus().vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight + GetConsensus().eh_epoch_fade_length - 1; }
    unsigned long eh_epoch_3_start() const { return GetConsensus().vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight; }
    std::string CurrencyUnits() const { return strCurrencyUnits; }
    uint32_t BIP44CoinType() const { return bip44CoinType; }
    /** Make miner stop after a block is found. In RPC, don't return until nGenProcLimit blocks are generated */
    bool MineBlocksOnDemand() const { return fMineBlocksOnDemand; }
    /** In the future use NetworkIDString() for RPC fields */
    bool TestnetToBeDeprecatedFieldRPC() const { return fTestnetToBeDeprecatedFieldRPC; }
    /** Return the BIP70 network string (main, test or regtest) */
    std::string NetworkIDString() const { return strNetworkID; }
    const std::vector<CDNSSeedData>& DNSSeeds() const { return vSeeds; }
    const std::vector<unsigned char>& Base58Prefix(Base58Type type) const { return base58Prefixes[type]; }
    const std::string& Bech32HRP(Bech32Type type) const { return bech32HRPs[type]; }
    const std::vector<SeedSpec6>& FixedSeeds() const { return vFixedSeeds; }
    const CCheckpointData& Checkpoints() const { return checkpointData; }
    /** Return the founder's reward address and script for a given block height */
    std::string GetFoundersRewardAddressAtHeight(int height) const;
    CScript GetFoundersRewardScriptAtHeight(int height) const;
    std::string GetFoundersRewardAddressAtIndex(int i) const;
    /** Enforce coinbase consensus rule in regtest mode */
    void SetRegTestCoinbaseMustBeProtected() { consensus.fCoinbaseMustBeProtected = true; }


    /** Zelnode Handling **/
    std::string SporkKey() const { return strSporkKey; }
    std::string ZelnodeTestingDummyAddress() const { return strZelnodeTestingDummyAddress; }
    int64_t StartZelnodePayments() const { return nStartZelnodePayments; }
    CBaseChainParams::Network NetworkID() const { return networkID; }


protected:
    CChainParams() {}

    Consensus::Params consensus;
    CMessageHeader::MessageStartChars pchMessageStart;
    //! Raw pub key bytes for the broadcast alert signing key.
    std::vector<unsigned char> vAlertPubKey;
    int nDefaultPort = 0;
    uint64_t nPruneAfterHeight = 0;
    EHparameters eh_epoch_1 = eh200_9;
    EHparameters eh_epoch_2 = eh144_5;
    EHparameters eh_epoch_3 = zelHash;
    // unsigned long eh_epoch_1_endblock = 0;		// Replaced by epoch fade
   // unsigned long eh_epoch_2_startblock = 0;		// Moved to consensus
    std::vector<CDNSSeedData> vSeeds;
    std::vector<unsigned char> base58Prefixes[MAX_BASE58_TYPES];
    std::string bech32HRPs[MAX_BECH32_TYPES];
    std::string strNetworkID;
    std::string strCurrencyUnits;
    uint32_t bip44CoinType;
    CBlock genesis;
    std::vector<SeedSpec6> vFixedSeeds;
    bool fMiningRequiresPeers = false;
    bool fDefaultConsistencyChecks = false;
    bool fRequireStandard = false;
    bool fMineBlocksOnDemand = false;
    bool fTestnetToBeDeprecatedFieldRPC = false;
    CCheckpointData checkpointData;
    std::vector<std::string> vFoundersRewardAddress;

    CAmount nSproutValuePoolCheckpointHeight = 0;
    CAmount nSproutValuePoolCheckpointBalance = 0;
    uint256 hashSproutValuePoolCheckpointBlock;
    bool fZIP209Enabled = false;
    
    /** Zelnode params **/
    std::string strSporkKey;
    std::string strZelnodeTestingDummyAddress;
    int64_t nStartZelnodePayments;
    CBaseChainParams::Network networkID;
};

/**
 * Return the currently selected parameters. This won't change after app
 * startup, except for unit tests.
 */
const CChainParams &Params();

/** Return parameters for the given network. */
CChainParams &Params(CBaseChainParams::Network network);

/** Sets the params returned by Params() to those for the given network. */
void SelectParams(CBaseChainParams::Network network);

/**
 * Looks for -regtest or -testnet and then calls SelectParams as appropriate.
 * Returns false if an invalid combination is given.
 */
bool SelectParamsFromCommandLine();


/**
 * Allows modifying the network upgrade regtest parameters.
 */
void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight);

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params);

#endif // BITCOIN_CHAINPARAMS_H
