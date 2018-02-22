// Copyright (c) 2016 The Zelcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/wallet.h"
#include "zelcash/JoinSplit.hpp"
#include "zelcash/Note.hpp"
#include "zelcash/NoteEncryption.hpp"

CWalletTx GetValidReceive(ZCJoinSplit& params,
                          const libzelcash::SpendingKey& sk, CAmount value,
                          bool randomInputs);
libzelcash::Note GetNote(ZCJoinSplit& params,
                       const libzelcash::SpendingKey& sk,
                       const CTransaction& tx, size_t js, size_t n);
CWalletTx GetValidSpend(ZCJoinSplit& params,
                        const libzelcash::SpendingKey& sk,
                        const libzelcash::Note& note, CAmount value);
