// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
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

    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 373500;  // Approx July 4th - Zel Team Boulder Meetup 

	consensus.nZawyLWMAAveragingWindow = 60;
	consensus.eh_epoch_fade_length = 11;

	eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_3 = zelHash;


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
        nStartZelnodePayments = 1550748576; //Thu, 21 Feb 2019 11:29:36 UTC // Not being used, but could be in the future
        networkID = CBaseChainParams::Network::MAIN;
        strZelnodeTestingDummyAddress= "t1Ub8iNuaoCAKTaiVyCh8d3iZ31QJFxnGzU";

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock)
            (5500, uint256S("0x0000000e7724f8bace09dd762657169c10622af4a6a8e959152cd00b9119848e"))
            (35000, uint256S("0x000000004646dd797644b9c67aff320961e95c311b4f26985424b720d09fcaa5"))
            (70000, uint256S("0x00000001edcf7768ed39fac55414e53a78d077b1b41fccdaf9307d7bc219626a"))
            (94071, uint256S("0x00000005ec83876bc5288badf0971ae83ac7c6a286851f7b22a75a03e73b401a")), //Halep won French Open 2018
            1528556469,     // * UNIX timestamp of last checkpoint block
            248945,              // * total number of transactions between genesis and last checkpoint
                            //   (the tx=... number in the SetBestChain debug.log lines)
            1525            // * estimated number of transactions per day
                            //   total number of tx / (checkpoint block height / (24 * 24))
        };

    }
};
static CMainParams mainParams;

/**
 * Kamiooka-testnet
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
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.nPowTargetSpacing = 2 * 60;

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
        Consensus::NetworkUpgrade::ALWAYS_ACTIVE;

        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
        Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        consensus.vUpgrades[Consensus::UPGRADE_LWMA].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_LWMA].nActivationHeight = 70;

	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nProtocolVersion = 170002;
	    consensus.vUpgrades[Consensus::UPGRADE_EQUI144_5].nActivationHeight = 100;

        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_ACADIA].nActivationHeight = 120;

	    consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nProtocolVersion = 170012;
        consensus.vUpgrades[Consensus::UPGRADE_KAMIOOKA].nActivationHeight = 720;


        consensus.nZawyLWMAAveragingWindow = 60;
	    consensus.eh_epoch_fade_length = 10;

	    //eh_epoch_1 = eh96_5;
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
            1548888451,
            uint256S("0x000000000000000000000000000000000000000000000000000000000000000b"),
            ParseHex("0061731d8ec027c60bfe22531440d7f0b2df6642e611ad5ca66dd26fadaa4411c6d2264abcdb8f7ac96908a3046f4443f84d1d5cf0b3d541864870e5d283070ca2977b3e2f1cc59784a0f9f87c2e30b3edee15ee0667406cd7c3ed265448a51bbef8f11e61b8bbcfae07390c57fa683db5c9d423cb94dbe98d70b878eaa51731736a930bb0d3991d81c2b225e1957ba573052b403da4397027b7a7e7937482c5f0a205a7d1b04bb90090f5265458172b56e245b14bd8b6958dd4af75b96cc5458a3f1bfd57838677c96f68f81255687a797402a1e4fbce62865518d4e0e38d10116cc332d281105e623f552b97f40d4d819673df7407be3282f5a28d03d852eb7353bba2e36b20b6862fbf35c9142f1e1c1be72f7da2e5a437dda88445456005b520034d97ae0b11fff3cd61b8eb0fb7d9ac77ec56df56c31fe0391908da23805a6bebd93d56ce20eebcdb9a87fe9543021701b49a8b1c71df5573708cf477ea0ecd50d61d077f968963d4bf5b6eb9b0b8e6f2832e8bfbf9358b0e013dd7635ead3770e40405a6ab9e45a097bed534306aa7b52a9a4680d6e2e739b6f1689661e3f8c54b06136936b756399ef054783d8c6689db0ee97ea4651a441544b0d98913c2af71a6c6b8f4691595dd3f0f0dafff67181bd96351b2311d18174a098eba7dfc38479e05ae4558b55b7b64d5f73ecce129cb553f951b04372d50fbde0687b5a4643797fdac6d3ea0badaae298c672ddabb9e1ff174c35e936ae2c4e4921543ba1be24ea38a9c5b333058220f7dba301890a010584f2467d3a917b6ba81dcf3a6aa8e67e70dce349341921b5dbe6f1c256ab3c73912778241cefe432114c9473d273dd5b84fa29ae85418b48558e79a57d4f92376231614b009d2962eef1727a21d7b408e7c20b58c4e394ecddb061c7f27d2902c06dcfbd6af28c41d49d101d802c0c321be7d6a0cea24b56f3a379dacded1c71a74e35b1e93abff53e102783325d0cb17c63a78953d22fbdd2bfb4861ec33e569cfd02e279dd89df9ff52bd2707fb2d5cc1b7abc67c656faac6524e9d33ee06bfbe9b64d72fe97c8512fd136cde4a69723ba4440d926d7a4ff63203d3b0522fd749baa8a533badab508756ac9e396b5f13f6d6091d841a6ed952591175c2710e4a306a0e1bbfd161728d658118306d11c64ae02edd5ea4b42f456681cc85c3a561fab45a57ed2e8118fde25db14f48d64cd5257ab9d9bc2cd6b1e771d178c947346b00417c678c34a63333bd1a627d63e021f403423dfa2a3a7dbab2522a64341ba65ac174820063b41ccf4826bbc34ae928be6ba8f14bef896c88b0ad8ac0c2083bf24923011afdbe34c50eacb5c446e1903ce949560c95b6bc058fcb9ea3d66cd2f59366028049a05e45cb6b5e804c8b49ee04d5640077259af030e7e53eae787c7528bd71f9b782a4df39bf661c31f8bb683f0a255d5d746544975cbfb115cb32ecb79072176804f056ba0fd58a10cb515063d6c957d8bc836c106299c55c05f9ab3b5e3e3f746e1c00e92c483043c53ba8d60e9f5545b805074242e6d0b023e58030a6e385b5b0ca428d867da6a485e8c73018ebecf231ae77fd3a9a8789b8162221f56993820fad5b647ad23a5ab2ffa10dcb3190486bd285f75d60bf3372884067c13597804d248b67f756c4832611dcd67128e001ee391a2c8893b130b05d2ec7f791534d694ae7fe8289c27c0b8d3d70aeb4b9553ab31a9438d4c7fea55392013e75db239d3d40b64e7af739e458fecb4aad70fd29437b5c932c5635d618c511f0fdc7a8a0f413a2068dd7c17cf9d8f5760f369496536d58009dd37a8101adf29796df65fcec271d153f1ea2ca7b6abab242257c610369c600782a4a924b253caca6321594b1e"),
            0x2007ffff, 4, 0);
        
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00c1c5904ead2647d0d56e56165ec568b83bee34ce467ae473e75057327e5805"));
        assert(genesis.hashMerkleRoot == uint256S("0x94c7aed6b2c67f1718006684bfc3b92081a2f19d59075691b189160d6f3aa13a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("test.vps.zel.network", "test.singapore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsone.zel.network", "test.bangalore.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpstwo.zel.network", "test.frankfurt.zel.network")); // MilesManley
        vSeeds.push_back(CDNSSeedData("test.vpsthree.zel.network", "test.newyork.zel.network")); // MilesManley
        //vSeeds.push_back(CDNSSeedData("vps.testnet.zelcash.online", "dnsseedtestnet.zelcash.online")); // TheTrunk


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
        nStartZelnodePayments = 1550748576; //Thu, 21 Feb 2019 11:29:36 UTC // Currently not being used.
        networkID = CBaseChainParams::Network::TESTNET;
        strZelnodeTestingDummyAddress= "tmXxZqbmvrxeSFQsXmm4N9CKyME767r47fS";




        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1548888451,  // * UNIX timestamp of last checkpoint block
            0,           // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            750          // * estimated number of transactions per day after checkpoint 720 newly mined +30 for txs that users are doing
                         //   total number of tx / (checkpoint block height / (24 * 24))
        };
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

        consensus.vUpgrades[Consensus::BASE].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE].nActivationHeight =
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

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        networkID = CBaseChainParams::Network::REGTEST;

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
        assert(idx > Consensus::BASE && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
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
