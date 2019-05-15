// Copyright (c) 2019 The Zel developers
// Copyright (c) 2019 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "zelcash/JoinSplit.hpp"
#include "zelcash/Note.hpp"
#include "zelcash/NoteEncryption.hpp"

CWalletTx GetValidReceive(ZCJoinSplit& params,
                          const libzelcash::SproutSpendingKey& sk, CAmount value,
                          bool randomInputs,
                          int32_t version = 2);
libzelcash::SproutNote GetNote(ZCJoinSplit& params,
                       const libzelcash::SproutSpendingKey& sk,
                       const CTransaction& tx, size_t js, size_t n);
CWalletTx GetValidSpend(ZCJoinSplit& params,
                        const libzelcash::SproutSpendingKey& sk,
                        const libzelcash::SproutNote& note, CAmount value);
