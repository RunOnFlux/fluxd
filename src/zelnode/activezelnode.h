// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2019 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
#define ACTIVE_ZELNODE_SYNC_IN_PROCESS 1
#define ACTIVE_ZELNODE_INPUT_TOO_NEW 2
#define ACTIVE_ZELNODE_NOT_CAPABLE 3
#define ACTIVE_ZELNODE_STARTED 4

class ActiveZelnode
{
private:
    // critical section to protect the inner data structures
    mutable CCriticalSection cs;

    /// Ping Zelnode
    bool SendZelnodePing(std::string& errorMessage);

    /// Create Zelnode broadcast, needs to be relayed manually after that
    bool CreateBroadcast(CTxIn vin, CService service, CKey key, CPubKey pubKey, CKey keyZelnode, CPubKey pubKeyZelnode, std::string& errorMessage, ZelnodeBroadcast &znb);

    /// Get 10000 ZEL input that can be used for the Zelnode
    bool GetZelNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey, std::string strTxHash, std::string strOutputIndex);
    bool GetVinFromOutput(COutput out, CTxIn& vin, CPubKey& pubkey, CKey& secretKey);

public:
    // Initialized by init.cpp
    // Keys for the main Zelnode
    CPubKey pubKeyZelnode;

    // Initialized while registering Zelnode
    CTxIn vin;
    CService service;

    int status;
    std::string notCapableReason;

    ActiveZelnode()
    {
        status = ACTIVE_ZELNODE_INITIAL;
    }

    /// Manage status of main zelnode
    void ManageStatus();
    std::string GetStatus();

    /// Create Zelnode broadcast, needs to be relayed manually after that
    bool CreateBroadcast(std::string strService, std::string strKey, std::string strTxHash, std::string strOutputIndex, std::string& errorMessage, ZelnodeBroadcast &znb, bool fOffline = false);

    /// Get 10000 ZEL input that can be used for the Zelnode
    bool GetZelNodeVin(CTxIn& vin, CPubKey& pubkey, CKey& secretKey);
    vector<std::pair<COutput, CAmount>> SelectCoinsZelnode();

    /// Enable cold wallet mode (run a Zelnode with no funds)
    bool EnableHotColdZelnode(CTxIn& vin, CService& addr);
};
#endif //ZELCASHNODES_ACTIVEZELNODE_H
