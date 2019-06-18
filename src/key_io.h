// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2016-2019 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KEYIO_H
#define BITCOIN_KEYIO_H

#include <chainparams.h>
#include <key.h>
#include <pubkey.h>
#include <script/standard.h>
#include <zelcash/Address.hpp>
#include <zelcash/zip32.h>

#include <string>

CKey DecodeSecret(const std::string& str);
std::string EncodeSecret(const CKey& key);

CExtKey DecodeExtKey(const std::string& str);
std::string EncodeExtKey(const CExtKey& extkey);
CExtPubKey DecodeExtPubKey(const std::string& str);
std::string EncodeExtPubKey(const CExtPubKey& extpubkey);

std::string EncodeDestination(const CTxDestination& dest);
CTxDestination DecodeDestination(const std::string& str);
bool IsValidDestinationString(const std::string& str);
bool IsValidDestinationString(const std::string& str, const CChainParams& params);

std::string EncodePaymentAddress(const libzelcash::PaymentAddress& zaddr);
libzelcash::PaymentAddress DecodePaymentAddress(const std::string& str);
bool IsValidPaymentAddressString(const std::string& str);

std::string EncodeViewingKey(const libzelcash::ViewingKey& vk);
libzelcash::ViewingKey DecodeViewingKey(const std::string& str);

std::string EncodeSpendingKey(const libzelcash::SpendingKey& zkey);
libzelcash::SpendingKey DecodeSpendingKey(const std::string& str);

#endif // BITCOIN_KEYIO_H
