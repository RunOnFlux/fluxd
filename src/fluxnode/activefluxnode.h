// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASHNODES_ACTIVEFLUXNODE_H
#define ZELCASHNODES_ACTIVEFLUXNODE_H


#include "init.h"
#include "key.h"
#include "fluxnode/fluxnode.h"
#include "net.h"
#include "fluxnode/obfuscation.h"
#include "sync.h"
#include "wallet/wallet.h"

#define ACTIVE_FLUXNODE_INITIAL 0 // initial state
#define ACTIVE_FLUXNODE_STARTED 4

class ActiveFluxnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    /// Get FLUX input that can be used for the Fluxnode
    bool GetFluxNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage);
    bool GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey);

    /// Get 10000 FLUX input that can be used for the Fluxnode
    bool GetFluxNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey);

public:
    // Initialized by init.cpp
    // Keys for the main Fluxnode
    CPubKey pubKeyFluxnode;

    // Initialized while registering Fluxnode
    CTxIn vin;

    // This is the zelnode OutPoint
    COutPoint deterministicOutPoint;

    std::string notCapableReason;

    int8_t nActiveFluxNodeTxVersion;

    ActiveFluxnode()
    {
        notCapableReason = "";
    }



    /** Deterministric Fluxnode functions **/

    vector<std::pair<COutput, CAmount>> SelectCoinsFluxnode();

    // Manage my active deterministic Fluxnode
    void ManageDeterministricFluxnode();

    bool BuildDeterministicStartTx(std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, CMutableTransaction& mutTransaction);
    void BuildDeterministicConfirmTx(CMutableTransaction& mutTransaction, const int nUpdateType);
    bool SignDeterministicStartTx(CMutableTransaction& mutableTransaction, std::string& errorMessage);
    bool SignDeterministicConfirmTx(CMutableTransaction& mutableTransaction, std::string& errorMessage);

    bool CheckDefaultPort(std::string strService, std::string& strErrorRet, std::string strContext);

    void EnforceActiveFluxNodeTxVersion();

    int nLastTriedToConfirm;
};
#endif //ZELCASHNODES_ACTIVEFLUXNODE_H
