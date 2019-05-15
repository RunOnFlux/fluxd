// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include "main.h"
#include "zelnode/payments.h"
#include "zelnode/zelnodesync.h"
#include "zelnode/zelnodeman.h"
#include "zelnode/obfuscationrelay.h"
#include "sync.h"

class CTxIn;
class CObfuScationSigner;
class ActiveZelnode;


extern CObfuScationSigner obfuScationSigner;
extern std::string strZelnodePrivKey;
extern ActiveZelnode activeZelnode;

bool GetTestingCollateralScript(std::string strAddress, CScript& script);

/** Helper object for signing and checking signatures
 */
class CObfuScationSigner
{
public:
    /// Is the inputs associated with this public key? (and there is 10000 ZEL = BASIC, 25000 ZEL = SUPER, 100000 ZEL = BAMF - checking if valid zelnode)
    bool IsVinAssociatedWithPubkey(CTxIn& vin, CPubKey& pubkey, int& nNodeTier);
    /// Set the private/public key values, returns true if successful
    bool GetKeysFromSecret(std::string strSecret, CKey& keyRet, CPubKey& pubkeyRet);
    /// Set the private/public key values, returns true if successful
    bool SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey);
    /// Sign the message, returns true if successful
    bool SignMessage(std::string strMessage, std::string& errorMessage, std::vector<unsigned char>& vchSig, CKey key);
    /// Verify the message, returns true if succcessful
    bool VerifyMessage(CPubKey pubkey, std::vector<unsigned char>& vchSig, std::string strMessage, std::string& errorMessage);
};

void ThreadCheckZelnodes();

#endif
