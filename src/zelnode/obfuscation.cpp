// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "zelnode/obfuscation.h"
#include "coincontrol.h"
#include "init.h"
#include "main.h"
#include "script/sign.h"
#include "ui_interface.h"
#include "util.h"
#include "key_io.h"
#include "activezelnode.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <algorithm>
#include <boost/assign/list_of.hpp>
#include <openssl/rand.h>

using namespace std;
using namespace boost;

// A helper object for signing messages from Zelnodes
CObfuScationSigner obfuScationSigner;

bool GetTestingCollateralScript(std::string strAddress, CScript& script)
{
    if (!IsValidDestinationString(strAddress)) {
        LogPrintf("GetTestingCollateralScript - Invalid collateral address\n");
        return false;
    }

    auto dest = DecodeDestination(strAddress);
    script = GetScriptForDestination(dest);
    return true;
}

bool CObfuScationSigner::SetKey(std::string strSecret, std::string& errorMessage, CKey& key, CPubKey& pubkey)
{
    key = DecodeSecret(strSecret);

    if (!key.IsValid()) {
        errorMessage = _("Invalid private key.");
        return false;
    }

    pubkey = key.GetPubKey();
    return true;
}

bool CObfuScationSigner::SignMessage(std::string strMessage, std::string& errorMessage, vector<unsigned char>& vchSig, CKey key)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    if (!key.SignCompact(ss.GetHash(), vchSig)) {
        errorMessage = _("Signing failed.");
        return false;
    }

    return true;
}

bool CObfuScationSigner::VerifyMessage(const CPubKey& pubkey, const vector<unsigned char>& vchSig, const std::string& strMessage, std::string& errorMessage)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey2;
    if (!pubkey2.RecoverCompact(ss.GetHash(), vchSig)) {
        errorMessage = _("Error recovering public key.");
        return false;
    }

    if (pubkey2.GetID() != pubkey.GetID())
        LogPrintf("CObfuScationSigner::VerifyMessage -- keys don't match: %s %s\n", pubkey2.GetID().ToString(), pubkey.GetID().ToString());

    return (pubkey2.GetID() == pubkey.GetID());
}

