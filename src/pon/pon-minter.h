// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PON_MINTER_H
#define BITCOIN_PON_MINTER_H

#include "primitives/block.h"
#include "primitives/transaction.h"

class CChainParams;

// Start the PON minting thread
void StartPONMinter(const CChainParams& chainparams);

// Stop the PON minting thread
void StopPONMinter();

// Check if PON minting is running
bool IsPONMinterRunning();

#endif // BITCOIN_PON_MINTER_H