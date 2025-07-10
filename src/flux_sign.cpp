#include <script/sign.h>
#include <script/standard.h>
#include <primitives/transaction.h>
#include <key.h>
#include <keystore.h>
#include <pubkey.h>
#include <hash.h>
#include <base58.h>
#include <script/script.h>
#include "utilstrencodings.h"
#include <core_io.h>
#include <map>
#include <string>
#include "flux_sign.h"

/** Default for consensus from main.h */
static const unsigned int SAPLING_CONSENSUS_BRANCH = 0x76b809bb;
static CBasicKeyStore keystore;

bool MatchPayToPubKeyHash(const CScript& script, std::vector<unsigned char>& pubKeyHashOut)
{
    opcodetype opcode;
    std::vector<unsigned char> data;
    CScript::const_iterator pc = script.begin();

    if (!script.GetOp(pc, opcode) || opcode != OP_DUP) return false;
    if (!script.GetOp(pc, opcode) || opcode != OP_HASH160) return false;
    if (!script.GetOp(pc, opcode, data) || data.size() != 20) return false;
    if (!script.GetOp(pc, opcode) || opcode != OP_EQUALVERIFY) return false;
    if (!script.GetOp(pc, opcode) || opcode != OP_CHECKSIG) return false;
    if (pc != script.end()) return false;

    pubKeyHashOut = data;
    return true;
}

bool MatchPayToMultisig(const CScript& script, std::vector<CPubKey>& pubkeysOut, unsigned int& requiredSigsOut)
{
    CScript::const_iterator pc = script.begin();
    opcodetype opcode;
    std::vector<unsigned char> data;

    if (!script.GetOp(pc, opcode)) return false;
    if (opcode < OP_1 || opcode > OP_16) return false;
    requiredSigsOut = opcode - OP_1 + 1;

    while (true) {
        if (!script.GetOp(pc, opcode, data)) return false;
        if (data.size() == 0) break;
        pubkeysOut.emplace_back(data.begin(), data.end());
    }

    if (opcode < OP_1 || opcode > OP_16) return false;
    unsigned int totalPubKeys = opcode - OP_1 + 1;

    if (!script.GetOp(pc, opcode) || opcode != OP_CHECKMULTISIG) return false;
    if (pc != script.end()) return false;

    return pubkeysOut.size() == totalPubKeys;
}

bool SignPKHInput(
    CMutableTransaction& tx,
    int inputIndex,
    const CScript& utxoScriptPubKey,
    const CAmount amount,
    const CBasicKeyStore& keystore)
{
    std::cout << "ScriptPubKey " << utxoScriptPubKey.ToString() << " amount " << amount << std::endl;
    uint256 sighash = SignatureHash(utxoScriptPubKey, tx, inputIndex, SIGHASH_ALL, amount, SAPLING_CONSENSUS_BRANCH);

    std::vector<unsigned char> pubKeyHash;
    if (!MatchPayToPubKeyHash(utxoScriptPubKey, pubKeyHash)) {
        return false;
    }

    if (pubKeyHash.size() != 20) {
        std::cerr << "Invalid pubKeyHash size\n";
        return false;
    }

    CKeyID keyID{uint160(pubKeyHash)};
    CKey key;
    if (!keystore.GetKey(keyID, key)) {
        return false;
    }

    std::vector<unsigned char> sig;
    if (!key.Sign(sighash, sig)) {
        return false;
    }
    sig.push_back(SIGHASH_ALL);

    CPubKey pubkey = key.GetPubKey();
    std::vector<unsigned char> pubkeyBytes(pubkey.begin(), pubkey.end());
    std::cout << "Pubkey: " << HexStr(pubkeyBytes) << std::endl;
    std::cout << "Pubkey Hash160: " << HexStr(Hash160(pubkeyBytes)) << std::endl;
    CScript scriptSig;
    scriptSig << sig << pubkeyBytes;

    tx.vin[inputIndex].scriptSig = scriptSig;
    return true;
}

bool SignMultisigInput(
    CMutableTransaction& tx,
    int inputIndex,
    const CScript& utxoScriptPubKey,
    const CAmount amount,
    const CBasicKeyStore& keystore)
{
    uint256 sighash = SignatureHash(utxoScriptPubKey, tx, inputIndex, SIGHASH_ALL, amount, SAPLING_CONSENSUS_BRANCH);
    std::vector<CPubKey> pubkeys;
    unsigned int requiredSigs;
    if (!MatchPayToMultisig(utxoScriptPubKey, pubkeys, requiredSigs)) {
        return false;
    }

    std::vector<std::vector<unsigned char>> vSigs;
    vSigs.push_back({}); // OP_0 due to CHECKMULTISIG bug

    unsigned int nSigned = 0;
    for (const CPubKey& pubkey : pubkeys) {
        CKey key;
        if (!keystore.GetKey(pubkey.GetID(), key)) continue;

        std::vector<unsigned char> sig;
        if (!key.Sign(sighash, sig)) continue;
        sig.push_back(SIGHASH_ALL);
        vSigs.push_back(sig);

        if (++nSigned >= requiredSigs) break;
    }

    if (nSigned < requiredSigs) return false;

    CScript scriptSig;
    for (const auto& sig : vSigs) scriptSig << sig;
    scriptSig << utxoScriptPubKey;
    tx.vin[inputIndex].scriptSig = scriptSig;

    return true;
}

bool SignInput(
    CMutableTransaction& tx,
    int inputIndex,
    const CScript& utxoScriptPubKey,
    const CAmount amount,
    const CBasicKeyStore& keystore)
{
    std::vector<unsigned char> dummy;
    if (MatchPayToPubKeyHash(utxoScriptPubKey, dummy)) {
        return SignPKHInput(tx, inputIndex, utxoScriptPubKey, amount, keystore);
    }
    return SignMultisigInput(tx, inputIndex, utxoScriptPubKey, amount, keystore);
}

bool WIFToCKey(const std::string& wif, CKey& keyOut)
{
    std::vector<unsigned char> decoded;
    if (!DecodeBase58Check(wif, decoded)) return false;
    if (decoded.size() != 33 && decoded.size() != 34) return false;
    if (decoded[0] != 0x80) return false;
    bool fCompressed = decoded.size() == 34 && decoded[33] == 0x01;
    std::vector<unsigned char> keyData(decoded.begin() + 1, decoded.begin() + 33);
    keyOut.Set(keyData.begin(), keyData.end(), fCompressed);
    return keyOut.IsValid();
}

std::string signTransaction(const std::string& Arg_unsigned_tx,
                            const std::map<std::string, std::pair<std::string, CAmount>>& prevouts)
{
    std::vector<unsigned char> txData = ParseHex(Arg_unsigned_tx);
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CMutableTransaction tx;
    ssData >> tx;

    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint& prevout = tx.vin[i].prevout;
        std::string key = prevout.hash.GetHex() + ":" + std::to_string(prevout.n);
        auto it = prevouts.find(key);
        if (it == prevouts.end()) throw std::runtime_error("Missing prevout for input " + std::to_string(i));
        std::vector<unsigned char> scriptBytes = ParseHex(it->second.first);
        CScript scriptPubKey(scriptBytes.begin(), scriptBytes.end());
        CAmount amount = it->second.second;
        std::string str(scriptBytes.begin(), scriptBytes.end());
        std::cout << HexStr(str.begin(), str.end()) << std::endl;
        if (!SignInput(tx, i, scriptPubKey, amount, keystore)) {
            throw std::runtime_error("Failed to sign input " + std::to_string(i));
        }
    }
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx.begin(), ssTx.end());
}

bool flux_sign_init(std::string wifKey) {
    bool ok = false;
    ECC_Start();

    CKey key;
    if (!WIFToCKey(wifKey, key)) {
        std::cerr << wifKey << " WIF Private key not valid!" << std::endl;
    } else {
        keystore.AddKey(key);
        ok = true;
    }
    return ok;
}

