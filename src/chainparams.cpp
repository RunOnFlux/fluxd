// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "crypto/equihash.h"

#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "base58.h"

#include "chainparamsseeds.h"

#include <mutex>
#include "metrics.h"
#include "crypto/equihash.h"
static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
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
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 657850; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 4000;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.zawyLWMAHeight = 125000;
        consensus.nZawyLWMAAveragingWindow = 60;
        /**
         * The message start string should be awesome! ⓩ❤
         */
        pchMessageStart[0] = 0x24;
        pchMessageStart[1] = 0xe9;
        pchMessageStart[2] = 0x27;
        pchMessageStart[3] = 0x64;
        vAlertPubKey = ParseHex("04025b2cf3a116782a69bb68cb4ae5ba3b7f05069f7139b75573dd28e48f8992d95c118122b618d4943456ad64e7356b0b45b2ef179cbe3d9767a2426662d13d32"); //Zel Technologies
        nDefaultPort = 16125;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 125110;
        eh_epoch_2_startblock = 125100;


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
        vSeeds.push_back(CDNSSeedData("zelcash.tech", "dnsseed.zelcash.tech")); // Zelcash
        vSeeds.push_back(CDNSSeedData("node.zel.cash", "seed.zel.cash")); // Zelcash
        vSeeds.push_back(CDNSSeedData("node1.zel.cash", "dns.zel.cash")); // Zelcash
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

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

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
 * Testnet (v4)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        strCurrencyUnits = "TEL";
        consensus.fCoinbaseMustBeProtected = true;
        consensus.nSubsidySlowStartInterval = 5000;
        consensus.nSubsidyHalvingInterval = 657850; // 2.5 years
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 400;
        consensus.powLimit = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nDigishieldAveragingWindow = 17;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nDigishieldAveragingWindow);
        consensus.nDigishieldMaxAdjustDown = 32; // 32% adjustment down
        consensus.nDigishieldMaxAdjustUp = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2 * 60;
        consensus.zawyLWMAHeight = 500;
        consensus.nZawyLWMAAveragingWindow = 60;
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x1a;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xbf;
        vAlertPubKey = ParseHex("044b5cb8fd1db34e2d89a93e7becf3fb35dd08a81bb3080484365e567136403fd4a6682a43d8819522ae35394704afa83de1ef069a3104763fd0ebdbdd505a1386"); //Zel Technologies
        nDefaultPort = 26125;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        eh_epoch_1 = eh200_9;
        eh_epoch_2 = eh144_5;
        eh_epoch_1_endblock = 610;
        eh_epoch_2_startblock = 600;

        genesis = CreateGenesisBlock(
            1521043405,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000018"),
            ParseHex("004a3716c0cc99afe4d9b2eb5075e6fe20c8d45df45cf7a7a877f7a129c80f369f57bd4aab32fbfa4c7d157f9c9114dd977bb50cb7d123cba86e312e7f237e382de3dcd7b49167eea8664fdbe65b5f27d27a8d4902894b9c2f19ea65b842a0d28392be2cdc9e473f1109a143aac1043bb85063b1c036594470799e269e8b040d20de9a42843f3ed4d12b1820d32ccc365d81b428bb15f743f77767ce79f35d01eeaaf280af3dce15016bcc6cba18e00bef535040e7cc41a8b4ffd6568d4614e6d706316b05d39da7acf3dc325efd55fb72e60af5451d8bae6f93b2bef7997a65d6ab8097dfc22a11acad82505d1ef7029fd214ab9dc7a2795119bc0103674a86971cf30f9b473127b70d85627c0ed70b811af10da59d4cf55768eab6f417796652401a7860b10fe7db801058a60d72bd739bc45d453948bd3e54a5373ce1eb1e2f8fc3d7f3e8c5b9f3bfca7bb43c772a027a621d951e19b33f3963165850d1db85433e7d6e0dbe0924fc096b926514c3dd9de188f6e71f3c591307efa52a961eaf295b0dd26318ba0c8967443939d62441b75e9c6ea9eff49ae69a787041cdd9895215fe050b694b39cb4e84953a890d9174e99a5f37b3a066344b7c7b6a8ec72bd8ad24cf2ed3c91584c1f03cd21336dea2972987a55827c93dfa5a5d43416d3d21843a9fdbf1f6de6f31b2f495db1fbe07e5efae5f1435045484c679dad1e1916241f631ca8bd99fba6e338620356c6ed889f5e92b01436836b730a21fe75144f60aeda1876b4d80cf0792329a4a3fbe7ccc3e48aae72ff1d6569badf183b95155ed18eea00e410cf927a108c6e6e5b5d747f19e7e32a05ca0b763a5fdbe863010d5260d01db54acf284820aa5fa7b2cd03e6e68c6240de51d8fd52b3eab6c7360e0be7dde30ea3bbda0394a94f13a0ec76caead88abe7eeb3169c0ab689bd00fa76b347a08773928cc1a33c2365f52878ea436731477d8f602994e7cf03a362b25e0ca4dfa6abfeb50481f40e1312d40b6faca1696790d5450421fe659e1a549404a45083b29806d2a7d4197a32101bd78f3f0e39172065e41f558960f63faacd75a1d075f8c35435d22fa380b6739ff6c6a7fa7ef23ccf0f4ffc8c3a10829ef098a82f0b58c342beb35862c706d81d8a1a11a8ec33092272f9466cf5600f2c84ad8bc3503b9103705b9b004dead88dd6c2cb1fd7b96b04b03d4cd61c151566b9ec3359e5ce285577f70e1eed213b74710ecd7b4837d4bc2d1026d4e6c9fcfb55c9b2d18b3b12b88f31d98bc389652de67384cff141c5fe77719b171eb6579aec2855afd5a266a4fefe125f3fb813603b99f244f7f6e86de2b51696f2ce9fbf85861e659f229e4f715e1b9fd96588125e6fcef40211a1d6f0b826a4b1dfd8f0de9db6ab34986d470205d33cf34055027ee4f2a2e1a68fffda506291987ebe472b1b796b2698b97ab5e14db7169f926e853cba392ed6b927c90fbd82f783a9bc0166e3f431c6537621a26a18c9231cd7e9c02563369147adf3d24335ff4d204054f5590613363f339cb97b714b51b795729fb877a1d209561a54b2570eb57749b23a941569fe3519ca1d2f10dc2dcf9c0b89792bc9d622a44e28629985a3216f9b2b3cb2a38b1a95e0e181df06aa5a603fd3651c9e4282038455c5171a82d2f87225e064508279d704cecccf76d35f53b69f9c35159098205ada592a61053e599512c613cb7619c3e1097134fe2af4a7225bd3b36c4a2873fb0960e3f5dd45473486ecb88522c5083774f707dfabfab35bee979f11f174fe3c8b92136c78381812ba8a3cc2241d3321e2e3a1a33c68f6a1fd36343308c95ecb1882dd1b988ef4d6e27f91e681f29853a21b6badfd39ded1c532558336b7f74b42eb9b39ac93"),
            0x2007ffff, 4, 0);
        
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0092081791f347d184d6d0d7d1544d99d0f51fb2948ffd2d6b3b620d8e18405a"));
        assert(genesis.hashMerkleRoot == uint256S("0x94c7aed6b2c67f1718006684bfc3b92081a2f19d59075691b189160d6f3aa13a"));

        vFixedSeeds.clear();
        vSeeds.clear();
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

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock),
            1521043405,  // * UNIX timestamp of last checkpoint block
            0,           // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            750          // * estimated number of transactions per day after checkpoint 720 newly mined +30 for txs that users are doing
                         //   total number of tx / (checkpoint block height / (24 * 24))
        };
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test TODO
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        strCurrencyUnits = "REG";
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
        consensus.zawyLWMAHeight = 1;
        consensus.nZawyLWMAAveragingWindow = 60;

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0xe8;
        pchMessageStart[2] = 0x3f;
        pchMessageStart[3] = 0x5f;
        nDefaultPort = 26126;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 1000;
        eh_epoch_1 = eh48_5;
        eh_epoch_2 = eh48_5;
        eh_epoch_1_endblock = 1;
        eh_epoch_2_startblock = 1;

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

    CBitcoinAddress address(GetFoundersRewardAddressAtHeight(nHeight).c_str());
    assert(address.IsValid());
    assert(address.IsScript());
    CScriptID scriptID = boost::get<CScriptID>(address.Get()); // Get() returns a boost variant
    CScript script = CScript() << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
    return script;
}

std::string CChainParams::GetFoundersRewardAddressAtIndex(int i) const {
    assert(i >= 0 && i < vFoundersRewardAddress.size());
    return vFoundersRewardAddress[i];
}

int validEHparameterList(EHparameters *ehparams, unsigned long blockheight, const CChainParams& params){
    //if in overlap period, there will be two valid solutions, else 1.
    //The upcoming version of EH is preferred so will always be first element
    //returns number of elements in list
    if(blockheight>=params.eh_epoch_2_start() && blockheight>params.eh_epoch_1_end()){
        ehparams[0]=params.eh_epoch_2_params();
        return 1;
    }
    if(blockheight<params.eh_epoch_2_start()){
        ehparams[0]=params.eh_epoch_1_params();
        return 1;
    }
    ehparams[0]=params.eh_epoch_2_params();
    ehparams[1]=params.eh_epoch_1_params();
    return 2;
}