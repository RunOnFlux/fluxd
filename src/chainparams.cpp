// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

#include <mutex>
#include "metrics.h"
#include "crypto/equihash.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Zelcash' + blake2s(b'TODO').hexdigest()
 *
 * CBlock(hash=00052461, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=94c7ae, nTime=1516980000, nBits=1f07ffff, nNonce=6796, vtx=1)
 *   CTransaction(hash=94c7ae, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 94c7ae
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Zelcash06f40b01ab1f135bd96c5d72f8e37c7906dc216dcaaa36fcd00ebf9b8e109567";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        strCurrencyUnits = "ZEL";
	bip44CoinType = 19167;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 655350; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
	consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 125000;

	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 125100;

	consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 250000;		// Approx January 12th
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].hashActivationBlock =
                uint256S("0000001d65fa78f2f6c172a51b5aca59ee1927e51f728647fca21b180becfe59");

    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 372500;  // Approx July 2nd - Zel Team Boulder Meetup
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].hashActivationBlock =
                uint256S("00000052e2ac144c2872ff641c646e41dac166ac577bc9b0837f501aba19de4a");

        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nProtocolVersion = 170016;
        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight = 558000;  // 18th March
        // TODO, add the activation block hash after activation


        consensus.nZawyLWMAAveragingWindow = 60;
	consensus.eh_epoch_fade_length = 11;

	eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;

        // The best chain should have at least this much work. 
        // nMinimumChainWork MUST be set to at least the chain work of hashActivationBlock, otherwise the detection of fake alternate chain will have false positives.
        // Updated to match the chainwork associated with upgrade_kamiooka
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000021f5d5da5d73");

        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04025b2cf3a116782a69bb68cb4ae5ba3b7f05069f7139b75573dd28e48f8992d95c118122b618d4943456ad64e7356b0b45b2ef179cbe3d9767a2426662d13d32"); //Zel Technologies GmbH
        nDefaultPort = 16125;
        nPruneAfterHeight = 100000;


        genesis = CreateGenesisBlock(
            1516980000,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001a8c"),
            ParseHex("002794c207f5942df0da515d0f29303a67b87eef343c2df654e3e00a052915289ef3f7842e6da933b2da247cebdee4ea3aabf3bdc33f02c5082633e3bdefc1a9316df787ecaf95a2337c6648e557a73a06fc8dee01479b1b09e350f9c9e2b61bea3736febb24f9f8692552d1a23863f6af2e38926df57e442dbbb69a3719104a70ad2415066ee46355a92a4b980d729e189c1311f4dc99a8cc191f2ae5634f34bfa97a291396d6f001244b9986c92c692986453ea26763767cafbfaeb372aafed3cb5cf5c1ab3f57c4445c85ef68921d568722206b19c1e797d7ce5ba3de50246456ae03fa150b23895e750273ca81cf0754ff4d38546e243bd182f210ae50f627d671b8e46775ed405cb5f2cfa49d5bbc1ed98604c78a5a4b752b72b780434641fbca11cf89183a04a21cc779079ad6f36bae57ca21519672a89e2e335dbc8ce89e85859959f5f4d1bb734abe3aecaa005b0b01020a869d631b01abb168d1b248dfbe3b6d1ad2ffb1fbdc8044e65bf579c3d948c21480dcf3800508ead900065afedae7c072fe5ea5c0a16c7ae78d36ddee0f40b5a6c1c365f66ba0c631ee99e8b9bee301f042f77cd92d6ae3f8937e1a41a38d864fb790121ecaf2d368967a34ca9183f5e7ae193dfb11f11a7931074aefcadac01dcb50b6978dd2cac69df89a656a399bcaade7cfb184b9ca884df3d63a3b8bca1c706602eb8dd2d1432fc79ee7425e35fd8f709d55ef1bab2f2bbe516711cf031ab6f4eee543a67193c81ef2b226d8e6d0d3a222d31811a326954a0a464a2a59ed9751d6f2dcd15da8ffe35fb5b441736c49dd5d75902a067f4c789ecc6e64671da0b67e88cec07f696b1c9828f3859266ca836a76eef5169c351cf1d32d33c918092eeed5f044970171504303629aefc51e63b6d7972b27e7b659e2d7c79f1ff5a6506833e315055f80ed00b42986db8cac0ea48e92ad8d5e3bc555b077f3381bfb53bfa7356195b67baa12cb7f0b0759285f8c9419d98ed33da746c9f6b2d50e0b74ea6311819bc2791bbe3e52ec536b78b80741ec41ae259273b7d3c4050f0bef51330e2ea793210559037ed3a98687ac3c13336f49cdc4a5ea77a40214eb4febbba9fb5e71410715cdb1aa238647a5315d91e97d4bfbc722f69b17332629f7f514cb79369c6132d8aff821e2cad7fd02b002b77eba3fc90f4cf91dd5ef7478acc6f0121966d7139abb672c14313ce69032c897e829417ba8f4c01b0f197144988995fbfb3b63231657798190e57f5a8a0f8643134752c9daf50fd4ab073288817fb1ede7de14007927e61c277b75e2d47294e8e8ae952b9f7a6a3471f4ba859c93852ba3d3e6cb47384d2d613e35641a1ff4d2b916ca8badb0c1c8d8f4629676e23953693b8e9b661b534e2cd34ea832b075c1f21333d1ceda02be8598ac435924d2d2b0d1fd9972f5386d92713e45e00cdc5d321817c7f9d4d966cc1eb5994f7d555107aadbbeb4d2dd24c5965b022dde997f3c5a7f17601b25623dd80836c67c7422e1b2c7a71553fc1d12df0742d986ab085298956c80f75035515922193f5d521db8ae57c05e5b1b801f93e25f5fffad38bb10fd781ab04a6b0a29547db513f3066b55459e061df5279831d9aeaa3b138a03f2a003c92c544e8972969476820419d312028e7c55cfa173fc0bfe414d3cc6ef85dd48c292595920fda320066be5d4eb69e327e37a14d408dddd3d06117abdbcbc36804a3c1fea73a5d4d3dc5c701ed7cf6716179eb94687ec6c73ca0d2c5190a10581566d9d9111152740c46955629a6974de7d0beb05efc3ab91e4fe735081b118cdef4510486e0c370f06ebf6158163d6e1b61280d8f4658618c9e4b9757636c6cc6761a1088f71b57392e9f85e89027a779f6c"),
            0x1f07ffff, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00052461a5006c2e3b74ce48992a08695607912d5604c3eb8da25749b0900444"));
        assert(genesis.hashMerkleRoot == uint256S("0x94c7aed6b2c67f1718006684bfc3b92081a2f19d59075691b189160d6f3aa13a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("vps.zel.network", "singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpsone.zel.network", "bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpstwo.zel.network", "frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vpsthree.zel.network", "newyork.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vps.zelcash.online", "dnsseed.zelcash.online")); // TheTrunk

        // guarantees the first 2 characters, when base58 encoded, are "t1"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1C,0xB8};
        // guarantees the first 2 characters, when base58 encoded, are "t3"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBD};
        // the first character, when base58 encoded, is "5" or "K" or "L" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0x80};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x88,0xB2,0x1E};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x88,0xAD,0xE4};
        // guarantees the first 2 characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0x9A};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first 2 characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAB,0x36};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "za";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewa";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivka";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        strSporkKey = "04f5382d5868ae49aedfd67efce7c0f56a66a9405a2cc13f8ef236aabb3f0f1d00031f9b9ca67edc93044918a1cf265655108bab531e94c7d48918e40a94a34f77";
        networkID = CBaseChainParams::Network::MAIN;
        strZelnodeTestingDummyAddress= "t1Ub8iNuaoCAKTaiVyCh8d3iZ31QJFxnGzU";

        nStartZelnodePaymentsHeight = 558000; // Start paying deterministic zelnodes on height

        strBenchmarkingPublicKey = "042e79d7dd1483996157df6b16c831be2b14b31c69944ea2a585c63b5101af1f9517ba392cee5b1f45a62e9d936488429374535a2f76870bfa8eea6667b13eb39e";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock)
            (5500, uint256S("0x0000000e7724f8bace09dd762657169c10622af4a6a8e959152cd00b9119848e"))
            (35000, uint256S("0x000000004646dd797644b9c67aff320961e95c311b4f26985424b720d09fcaa5"))
            (70000, uint256S("0x00000001edcf7768ed39fac55414e53a78d077b1b41fccdaf9307d7bc219626a"))
            (94071, uint256S("0x00000005ec83876bc5288badf0971ae83ac7c6a286851f7b22a75a03e73b401a")) //Halep won French Open 2018
            (530000, uint256S("0x0000004b4459ec6904e8116d178c357b0f25a7d45c5c5836ce3714791f1ed124")),
            1581212778,     // * UNIX timestamp of last checkpoint block
            1429455,              // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1941            // * estimated number of transactions per day
                            //   total number of tx / (checkpoint block height / (24 * 30))
        };

        // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        // nSproutValuePoolCheckpointHeight = 520633;
        // nSproutValuePoolCheckpointBalance = 22145062442933;
        // fZIP209Enabled = true;
        // hashSproutValuePoolCheckpointBlock = uint256S("0000000000c7b46b6bc04b4cbf87d8bb08722aebd51232619b214f7273f8460e");
    }
};
static CMainParams mainParams;

/**
 * testnet-kamata
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TESTZEL";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 655350; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("0effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // to be slightly above 17
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 1;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
        Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
        Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 70;

	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 140;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 210;

	    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 280;

        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nProtocolVersion = 170016;
        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight = 350;


        consensus.nZawyLWMAAveragingWindow = 60;
	    consensus.eh_epoch_fade_length = 10;

        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044b5cb8fd1db34e2d89a93e7becf3fb35dd08a81bb3080484365e567136403fd4a6682a43d8819522ae35394704afa83de1ef069a3104763fd0ebdbdd505a1386"); //Zel Technologies GmbH

        nDefaultPort = 26125;

        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(
            1582228940, // 2020-2-20-20-2-20
            uint256S("0x000000000000000000000000000000000000000000000000000000000000021c"),
            ParseHex("00069ae382cf568d3f3ba00d15f9d09c8977cd37d90d2c4d612e053e4cdfd4d226db220e51495bfb00d1019180b34c25091fbee2a08e4f08c974a4356760690b00d8da0c8baa3b6902130202e60391a16a5fa1ea08d6d0b63a60ec91dd0790cb432261483fe7fbe9d80d6a07af5599cc6d0b717780184fc0523e5ada8c07134262b9676c0269709501d4403c621cb9a15f55602b400e3fc093034f84ec583f25e6f16a111372ab4f031d6d12270259d7066520f71e63893e8dcedd8db2255272add167e4cd4a0045a6815a16818f9efb075106090b8e47d089dd7d50c838ea4b22caca1fdb866e485f0248c763faada47f8555b8cdb1222e45f2f0a10e3f3dffcb9733090bf2e58eb8f11399ffd7fc58302db98d5d978dac49b88f849ad4af4972b37d3cf2ca1797c28af99b3addc356c460ba6eb161d3304eeef863237c61006b486df070bb29026895172ae79bd9f3018637fe01dbc18d3829a2ed211a7218fcd8f4def308c3a8bd60cb999565f253435f1af115d1d473750c0233fda7aaeff783b8265083a9c0369852a459fe2c093dec6929cfc31cea57a3579fed30add42cfc02260700796ea2d3054dc04020a50c5a8079863b15f68c0e0354bb0aa8f1dd48fec84923d02f1a300d3ec598071a9f0584d918e36ec892450abdfe7d41acfe870624de69f988db06f7790897459c7d9899f290b60f2102a1df05bca84a7f54e746d274625f3322ae5a3eaa02b4565a125c948cf8682396e72494995793bf9379196014fec46c4c3769861808ed6b3fd2b4e57cadb92a7c81fc7fd630c4bae2549aa6efdc02df0f5e1ff20a834d35372301334b214229e872f8ac9415d57d1a325ac539a4a62eb1c685c6478867cf3ea0f999768a0d66fc9e36a35a2f1f768481613da1a99a17739fab0dd2ffe73f58f95ef1a6c2495167b485207dabe48001a200b4a371cf1df817f0b1fb6208d0d77b38d5cf170d83a6b7633a4fb605f44665a314ab5de8dc0ace1091611148705b3fe81e945857291daeb3657c98602cda23a350ed209ba19b6312fdefe765f3de7a16031580eba06145f64bfdf284dca4713335e9735031c71cf36da5f1145c8ed6e69352a7d763be253bd5fc7e1e45660e8d4f2beb98377268bc6303f5de2dd6ce1a35652b7090a8be51d43ef5c779376de1cbabf4758b064259d545524781801e18d005dd2a1ea4d27e1eaf27578c6a5acdf4a27d226293ae7c49d645c07adc8b0dfb0c35e519a6d95e9bb3f4a8bbbc72551e5ab9191d552104620b954523376637077c2e32aa42dec58b07ad0d91e4b93651d74b220070d22171e1b116dda1428082cb54122c27276f283260e1249ed483f97d053a0ad3abc6a032d7b8a5672ad7ec2232010655136e6e1507cbd9fa4a27ec674724a8cf4bdae91e3e34080291899bbb53c209bb3936a9c2d9194de89179396803cdf6bcb5cf9bbaf95b56c613d161c21ff1defe0f056f27e953891fd310aa6760d6f5a5edef8011d8780de5c681261331aed69ee2eccd3bb413cdf55f2e500686b231cbaf451fecdc1327e14bde0973fb4cbd8835b7c31a1a1aaf47eecbb57849ad3eb960cdbd5cdb0e4c53a8d7f10459cbc572faab1ffbd8ca9d0919e0113099339910e897e21fd390f450c3b13b5d198d7306927f258a0297c50daa10a4f29aed6a184df29c0a32a666744bef2c358401350cfb54797a02a35afeba0bfefa865890dded2694d88ad86a5b327662bd7b932c6ce97a7f300bfd8b544316696a4f2e6c197ddf9d0e9b008e3f85427fd6b661970e4177c947fbb6d43324a4f47c26983b55ea90d3bffcbc87c15cab5ba2751314819e7eb21a29b9b915cce6f7cf01ff05936317161b9dae29637d89cb88b55ac74348878b017e7942"),
            0x2007ffff, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0042202a64a929fc25cc10e68615ddbe38007b1b40da08acd3f530f83c79b9d1"));
        assert(genesis.hashMerkleRoot == uint256S("0x94c7aed6b2c67f1718006684bfc3b92081a2f19d59075691b189160d6f3aa13a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("zel-testnet-seed.asoftwaresolution.com", "zel-testnet-seed.asoftwaresolution.com")); // Blondfrogs
        vSeeds.push_back(CDNSSeedData("test.vps.zel.network", "test.singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsone.zel.network", "test.bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpstwo.zel.network", "test.frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsthree.zel.network", "test.newyork.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("vps.testnet.zelcash.online", "dnsseedtestnet.zelcash.online")); // TheTrunk

        // guarantees the first 2 characters, when base58 encoded, are "tm"
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        // guarantees the first 2 characters, when base58 encoded, are "t2"
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        // the first character, when base58 encoded, is "9" or "c" (as in Bitcoin)
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        // guarantees the first 2 characters, when base58 encoded, are "zt"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        // guarantees the first 2 characters, when base58 encoded, are "ST"
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestacadia";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestacadia";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestacadia";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;
        strSporkKey = "0408c6a3a6cacb673fc38f27c75d79c865e1550441ea8b5295abf21116972379a1b49416da07b7d9b40fb9daf8124f309c608dfc79756a5d3c2a957435642f7f1a";
        networkID = CBaseChainParams::Network::TESTNET;
        strZelnodeTestingDummyAddress= "tmXxZqbmvrxeSFQsXmm4N9CKyME767r47fS";
        strBenchmarkingPublicKey = "04d422e01f5acff68504b92df96a9004cf61be432a20efe83fe8a94c1aa730fe7dece5d2e8298f2d5672d4e569c55d9f0a73268ef7b92990d8c014e828a7cc48dd";
        nStartZelnodePaymentsHeight = 350;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1582228940,  // * UNIX timestamp of last checkpoint block
            0,           // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            750          // * estimated number of transactions per day after checkpoint 720 newly mined +30 for txs that users are doing
                         //   total number of tx / (checkpoint block height / (24 * 24))
        };

    // Hardcoded fallback value for the Sprout shielded value pool balance
        // for nodes that have not reindexed since the introduction of monitoring
        // in #2795.
        //nSproutValuePoolCheckpointHeight = 440329;
        //nSproutValuePoolCheckpointBalance = 40000029096803;
        //fZIP209Enabled = true;
        //hashSproutValuePoolCheckpointBlock = uint256S("000a95d08ba5dcbabe881fc6471d11807bcca7df5f1795c99f3ec4580db4279b");

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
        bip44CoinType = 1;
        consensus.fCoinbaseMustBeProtected = false;
        consensus.nSubsidySlowStartInterval = 0;
        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 0; // Turn off adjustment down
        consensus.nDigishieldMaxAdjustUp = 0; // Turn off adjustment up

        consensus.nPowTargetSpacing = 2 * 60;
	    consensus.nPowAllowMinDifficultyBlocksAfterHeight = 0;

        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight =
            Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight =
            Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170006;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nProtocolVersion = 170016;
        consensus.vUpgrades[Consensus::UPGRADE_KAMATA].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        consensus.nZawyLWMAAveragingWindow = 60;
        consensus.eh_epoch_fade_length = 11;

	    eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 26126;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(
            1296688602,
            uint256S("0000000000000000000000000000000000000000000000000000000000000016"),
            ParseHex("02853a9dd062e2356909a0d2b9f0e4873dbf092edd3f00eea317e21222d1f2c414b926ee"),
            0x200f0f0f, 4, 0);

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x01998760a88dc2b5715f69d2f18c1d90e0b604612242d9099eaff3048dd1e0ce"));
        assert(genesis.hashMerkleRoot == uint256S("0x94c7aed6b2c67f1718006684bfc3b92081a2f19d59075691b189160d6f3aa13a"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        networkID = CBaseChainParams::Network::REGTEST;
        strBenchmarkingPublicKey = "04cf3c34f01486bbb34c1a7ca11c2ddb1b3d98698c3f37d54452ff91a8cd5e92a6910ce5fc2cc7ad63547454a965df53ff5be740d4ef4ac89848c2bafd1e40e6b7";

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("94c7aed6b2c67f1718006684bfc3b92081a2f19d59075691b189160d6f3aa13a")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }

    void SetRegTestZIP209Enabled() {
        fZIP209Enabled = true;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }

    // When a developer is debugging turnstile violations in regtest mode, enable ZIP209
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-developersetpoolsizezero")) {
        regTestParams.SetRegTestZIP209Enabled();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}


// Block height must be >0 and <=last founders reward block height
// Index variable i ranges from 0 - (vFoundersRewardAddress.size()-1)
std::string CChainParams::GetFoundersRewardAddressAtHeight(int nHeight) const {
    int maxHeight = consensus.GetLastFoundersRewardBlockHeight();
    assert(nHeight > 0 && nHeight <= maxHeight);

    size_t addressChangeInterval = (maxHeight + vFoundersRewardAddress.size()) / vFoundersRewardAddress.size();
    size_t i = nHeight / addressChangeInterval;
    return vFoundersRewardAddress[i];
}


// Block height must be >0 and <=last founders reward block height
// The founders reward address is expected to be a multisig (P2SH) address
CScript CChainParams::GetFoundersRewardScriptAtHeight(int nHeight) const {
    assert(nHeight > 0 && nHeight <= consensus.GetLastFoundersRewardBlockHeight());

    CTxDestination address = DecodeDestination(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(IsValidDestination(address));
    assert(boost::get<CScriptID>(&address) != nullptr);
    CScriptID scriptID = boost::get<CScriptID>(address); // address is a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}
std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list

    int current_height = (int)blockheight;
    if (current_height < 0)
        current_height = 0;

    // When checking to see if the activation height is above the fade length, we subtract the fade length from the
    // current height and run it through the NetworkUpgradeActive method
    int modified_height = (int)(current_height - params.GetConsensus().eh_epoch_fade_length);
    if (modified_height < 0)
        modified_height = 0;

    // check to see if the block height is greater then the overlap period ( height - fade depth >= Upgrade Height)
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        return 1;
    }

    // check to see if the block height is in the overlap period.
    // The above if statement shows us that we are already below the upgrade height + the fade depth, so now we check
    // to see if we are above just the upgrade height
    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_KAMIOOKA)) {
        ehparams[0]=params.eh_epoch_3_params();
        ehparams[1]=params.eh_epoch_2_params();
        return 2;
    }

    // check to see if the block height is greater then the overlap period (height - fade depth >= Upgrade Height)
    if (NetworkUpgradeActive(modified_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }

    // check to see if the block height is in the overlap period
    // The above if statement shows us that we are already below the upgrade height + the fade depth, so now we check
    // to see if we are above just the upgrade height
    if (NetworkUpgradeActive(current_height, Params().GetConsensus(), Consensus::UPGRADE_EQUI144_5)) {
        ehparams[0]=params.eh_epoch_2_params();
        ehparams[1]=params.eh_epoch_1_params();
        return 2;
    }

    // return the block height is less than the upgrade height params
    ehparams[0]=params.eh_epoch_1_params();
    return 1;
}
