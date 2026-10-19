// Copyright (c) 2018 The Bitcoin Core developers
// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQRPC_H
#define BITCOIN_ZMQ_ZMQRPC_H

#include <univalue.h>

class CRPCTable;

UniValue getzmqnotifications(const UniValue& params, bool fHelp);

void RegisterZMQRPCCommands(CRPCTable& tableRPC);

#endif // BITCOIN_ZMQ_ZMQRPC_H
