// Copyright (c) 2018 The Bitcoin Core developers
// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "zmq/zmqrpc.h"

#include "rpc/server.h"
#include "utilstrencodings.h"
#include "zmq/zmqnotificationinterface.h"

#include <stdexcept>

UniValue getzmqnotifications(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getzmqnotifications\n"
            "\nReturns the ZeroMQ notifications this node is publishing.\n"
            "\nResult:\n"
            "[                         (json array of objects)\n"
            "  {\n"
            "    \"type\": \"pubhashtx\",   (string) the notification\n"
            "    \"address\": \"...\"       (string) the address it publishes on\n"
            "  }\n"
            "  ,...\n"
            "]\n"
            "\nAn empty array means nothing is published: no -zmqpub option was given, or one\n"
            "failed to start, which turns every notification off. A notification that fails\n"
            "to publish later leaves the array.\n"
            "\nExamples:\n"
            + HelpExampleCli("getzmqnotifications", "")
            + HelpExampleRpc("getzmqnotifications", ""));

    UniValue result(UniValue::VARR);
    if (g_zmq_notification_interface != NULL) {
        for (const auto& notifier : g_zmq_notification_interface->GetActiveNotifiers()) {
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("type", notifier.first);
            obj.pushKV("address", notifier.second);
            result.push_back(obj);
        }
    }
    return result;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "zmq",                "getzmqnotifications",    &getzmqnotifications,    true  },
};

void RegisterZMQRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
