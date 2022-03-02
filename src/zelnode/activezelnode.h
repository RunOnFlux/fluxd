// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASHNODES_ACTIVEZELNODE_H
#define ZELCASHNODES_ACTIVEZELNODE_H


#include "init.h"
#include "key.h"
#include "zelnode/zelnode.h"
#include "net.h"
#include "zelnode/obfuscation.h"
#include "sync.h"
#include "wallet/wallet.h"

#define ACTIVE_ZELNODE_INITIAL 0 // initial state
#define ACTIVE_ZELNODE_STARTED 4

class ActiveFluxnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    /// Get ZEL input that can be used for the Fluxnode
    bool GetZelNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage);
    bool GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey);

    /// Get 10000 ZEL input that can be used for the Fluxnode
    bool GetZelNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey);

public:
    // Initialized by init.cpp
    // Keys for the main Fluxnode
    CPubKey pubKeyFluxnode;

    // Initialized while registering Fluxnode
    CTxIn vin;

    // This is the zelnode OutPoint
    COutPoint deterministicOutPoint;

    std::string notCapableReason;


    ActiveFluxnode()
    {
        notCapableReason = "";
    }

    /** Deterministric Fluxnode functions **/

    vector<std::pair<COutput, CAmount>> SelectCoinsFluxnode();

    //Manage my active deterministic zelnode
    void ManageDeterministricFluxnode();

    bool BuildDeterministicStartTx(std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, CMutableTransaction& mutTransaction);
    void BuildDeterministicConfirmTx(CMutableTransaction& mutTransaction, const int nUpdateType);
    bool SignDeterministicStartTx(CMutableTransaction& mutableTransaction, std::string& errorMessage);
    bool SignDeterministicConfirmTx(CMutableTransaction& mutableTransaction, std::string& errorMessage);

    bool CheckDefaultPort(std::string strService, std::string& strErrorRet, std::string strContext);

    int nLastTriedToConfirm;
};
#endif //ZELCASHNODES_ACTIVEZELNODE_H
