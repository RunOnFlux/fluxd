// Copyright (c) 2019 The Zel developers
// Copyright (c) 2019 The Zcash developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASH_UTIL_TEST_H
#define ZELCASH_UTIL_TEST_H

#include "key_io.h"
#include "wallet/wallet.h"
#include "flux/JoinSplit.hpp"
#include "flux/Note.hpp"
#include "flux/NoteEncryption.hpp"
#include "flux/zip32.h"

// Sprout
CWalletTx GetValidSproutReceive(ZCJoinSplit& params,
                                const libflux::SproutSpendingKey& sk,
                                CAmount value,
                                bool randomInputs,
                                uint32_t versionGroupId = SAPLING_VERSION_GROUP_ID,
                                int32_t version = SAPLING_TX_VERSION);
CWalletTx GetInvalidCommitmentSproutReceive(ZCJoinSplit& params,
                                const libflux::SproutSpendingKey& sk,
                                CAmount value,
                                bool randomInputs,
                                uint32_t versionGroupId = SAPLING_VERSION_GROUP_ID,
                                int32_t version = SAPLING_TX_VERSION);
libflux::SproutNote GetSproutNote(ZCJoinSplit& params,
                                   const libflux::SproutSpendingKey& sk,
                                   const CTransaction& tx, size_t js, size_t n);
CWalletTx GetValidSproutSpend(ZCJoinSplit& params,
                              const libflux::SproutSpendingKey& sk,
                              const libflux::SproutNote& note,
                              CAmount value);

// Sapling
static const std::string T_SECRET_REGTEST = "cND2ZvtabDbJ1gucx9GWH6XT9kgTAqfb6cotPt5Q5CyxVDhid2EN";

struct TestSaplingNote {
    libflux::SaplingNote note;
    SaplingMerkleTree tree;
};

const Consensus::Params& RegtestActivateAcadia();

void RegtestDeactivateAcadia();

libflux::SaplingExtendedSpendingKey GetTestMasterSaplingSpendingKey();

CKey AddTestCKeyToKeyStore(CBasicKeyStore& keyStore);

/**
 * Generate a dummy SaplingNote and a SaplingMerkleTree with that note's commitment.
 */
TestSaplingNote GetTestSaplingNote(const libflux::SaplingPaymentAddress& pa, CAmount value);

CWalletTx GetValidSaplingReceive(const Consensus::Params& consensusParams,
                                 CBasicKeyStore& keyStore,
                                 const libflux::SaplingExtendedSpendingKey &sk,
                                 CAmount value);

#endif // ZELCASH_UTIL_TEST_H
