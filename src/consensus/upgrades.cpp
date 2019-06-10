// Copyright (c) 2019 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/upgrades.h"

/**
 * General information about each network upgrade.
 * Ordered by Consensus::UpgradeIndex.
 */
const struct NUInfo NetworkUpgradeInfo[Consensus::MAX_NETWORK_UPGRADES] = {
    {
        /*.nBranchId =*/ 0,
        /*.strName =*/ "Base",
        /*.strInfo =*/ "The Zelcash network at launch",
    },
    {
        /*.nBranchId =*/ 0x74736554,
        /*.strName =*/ "Test dummy",
        /*.strInfo =*/ "Test dummy info",
    },
     {
        /*.nBranchId =*/ 0x76b809bb,
        /*.strName =*/ "LWMA",
        /*.strInfo =*/ "Zelcash upgraded to LWMA difficulty algorithm",
    },
     {
        /*.nBranchId =*/ 0x76b809bb,
        /*.strName =*/ "Equihash 144/5",
        /*.strInfo =*/ "Zelcash PoW Change to Equihash 144/5",
    },	
    {
        /*.nBranchId =*/ 0x76b809bb,
        /*.strName =*/ "Acadia",
        /*.strInfo =*/ "The Zelcash Acadia Update",
    },
    {
        /*.nBranchId =*/ 0x76b809bb,
        /*.strName =*/ "Kamiooka",
        /*.strInfo =*/ "Zel Kamiooka Upgrade, PoW change to ZelHash and update for ZelNodes",
    }
};

const uint32_t SPROUT_BRANCH_ID = NetworkUpgradeInfo[Consensus::BASE].nBranchId;

UpgradeState NetworkUpgradeState(
    int nHeight,
    const Consensus::Params& params,
    Consensus::UpgradeIndex idx)
{
    assert(nHeight >= 0);
    assert(idx >= Consensus::BASE && idx < Consensus::MAX_NETWORK_UPGRADES);
    auto nActivationHeight = params.vUpgrades[idx].nActivationHeight;

    if (nActivationHeight == Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT) {
        return UPGRADE_DISABLED;
    } else if (nHeight >= nActivationHeight) {
        // From ZIP 200:
        //
        // ACTIVATION_HEIGHT
        //     The non-zero block height at which the network upgrade rules will come
        //     into effect, and be enforced as part of the blockchain consensus.
        //
        //     For removal of ambiguity, the block at height ACTIVATION_HEIGHT - 1 is
        //     subject to the pre-upgrade consensus rules, and would be the last common
        //     block in the event of a persistent pre-upgrade branch.
        return UPGRADE_ACTIVE;
    } else {
        return UPGRADE_PENDING;
    }
}

bool NetworkUpgradeActive(
    int nHeight,
    const Consensus::Params& params,
    Consensus::UpgradeIndex idx)
{
    return NetworkUpgradeState(nHeight, params, idx) == UPGRADE_ACTIVE;
}

int CurrentEpoch(int nHeight, const Consensus::Params& params) {
    for (auto idxInt = Consensus::MAX_NETWORK_UPGRADES - 1; idxInt >= Consensus::BASE; idxInt--) {
        if (NetworkUpgradeActive(nHeight, params, Consensus::UpgradeIndex(idxInt))) {
            return idxInt;
        }
    }
    // Base case
    return Consensus::BASE;
}

uint32_t CurrentEpochBranchId(int nHeight, const Consensus::Params& params) {
    return NetworkUpgradeInfo[CurrentEpoch(nHeight, params)].nBranchId;
}

bool IsConsensusBranchId(int branchId) {
    for (int idx = Consensus::BASE; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (branchId == NetworkUpgradeInfo[idx].nBranchId) {
            return true;
        }
    }
    return false;
}

bool IsActivationHeight(
    int nHeight,
    const Consensus::Params& params,
    Consensus::UpgradeIndex idx)
{
    assert(idx >= Consensus::BASE && idx < Consensus::MAX_NETWORK_UPGRADES);

    // Don't count Base as an activation height
    if (idx == Consensus::BASE) {
        return false;
    }

    return nHeight >= 0 && nHeight == params.vUpgrades[idx].nActivationHeight;
}

bool IsActivationHeightForAnyUpgrade(
    int nHeight,
    const Consensus::Params& params)
{
    if (nHeight < 0) {
        return false;
    }

    // Don't count Base as an activation height
    for (int idx = Consensus::BASE + 1; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (nHeight == params.vUpgrades[idx].nActivationHeight)
            return true;
    }

    return false;
}

boost::optional<int> NextEpoch(int nHeight, const Consensus::Params& params) {
    if (nHeight < 0) {
        return boost::none;
    }

    // Sprout is never pending
    for (auto idx = Consensus::BASE + 1; idx < Consensus::MAX_NETWORK_UPGRADES; idx++) {
        if (NetworkUpgradeState(nHeight, params, Consensus::UpgradeIndex(idx)) == UPGRADE_PENDING) {
            return idx;
        }
    }

    return boost::none;
}

boost::optional<int> NextActivationHeight(
    int nHeight,
    const Consensus::Params& params)
{
    auto idx = NextEpoch(nHeight, params);
    if (idx) {
        return params.vUpgrades[idx.get()].nActivationHeight;
    }
    return boost::none;
}
