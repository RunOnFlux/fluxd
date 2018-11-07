// Copyright (c) 2018 The Zelcash developers
// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASH_UTIL_TEST_H
#define ZELCASH_UTIL_TEST_H

#include "wallet/wallet.h"
#include "zelcash/JoinSplit.hpp"
#include "zelcash/Note.hpp"
#include "zelcash/NoteEncryption.hpp"
#include "zelcash/zip32.h"

// Sprout
CWalletTx GetValidSproutReceive(ZCJoinSplit& params,
                                const libzelcash::SproutSpendingKey& sk,
                                CAmount value,
                                bool randomInputs,
                                int32_t version = 2);
libzelcash::SproutNote GetSproutNote(ZCJoinSplit& params,
                                   const libzelcash::SproutSpendingKey& sk,
                                   const CTransaction& tx, size_t js, size_t n);
CWalletTx GetValidSproutSpend(ZCJoinSplit& params,
                              const libzelcash::SproutSpendingKey& sk,
                              const libzelcash::SproutNote& note,
                              CAmount value);

// Sapling
struct TestSaplingNote {
    libzelcash::SaplingNote note;
    SaplingMerkleTree tree;
};

const Consensus::Params& ActivateSapling();

void DeactivateAcadia();

libzelcash::SaplingExtendedSpendingKey GetMasterSaplingSpendingKey();

/**
 * Generate a dummy SaplingNote and a SaplingMerkleTree with that note's commitment.
 */
TestSaplingNote GetTestSaplingNote(const libzelcash::SaplingPaymentAddress& pa, CAmount value);

CWalletTx GetValidSaplingTx(const Consensus::Params& consensusParams,
                            const libzelcash::SaplingExtendedSpendingKey &sk,
                            CAmount value);

#endif // ZELCASH_UTIL_TEST_H