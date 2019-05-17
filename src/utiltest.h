// Copyright (c) 2018 The Zelcash developers
// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
const Consensus::Params& ActivateAcadia();

void DeactivateAcadia();

CWalletTx GetValidSaplingTx(const Conesnsus::Params& consensusParams,
                            const libzelcash::SaplingExtendedSpendingKey &sk,
                            CAmount value);