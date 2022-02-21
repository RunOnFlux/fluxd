// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include "main.h"
#include "sync.h"
#include "key.h"

class CTxIn;
class CObfuScationSigner;

extern CObfuScationSigner obfuScationSigner;
extern std::string strZelnodePrivKey;

bool GetTestingCollateralScript(std::string strAddress, CScript& script);

/** Helper object for signing and checking signatures
 */
class CObfuScationSigner
{
public:
    /// Set the private/public key values, returns true if successful
    bool SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey);
    /// Sign the message, returns true if successful
    bool SignMessage(std::string strMessage, std::string& errorMessage, std::vector<unsigned char>& vchSig, CKey key);
    /// Verify the message, returns true if succcessful
    bool VerifyMessage(const CPubKey& pubkey, const std::vector<unsigned char>& vchSig, const std::string& strMessage, std::string& errorMessage);
};

#endif
