// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "zmq/zmqnotificationinterface.h"
#include "zmq/zmqrpc.h"

#include <filesystem>
#include <map>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;

class ZMQRPC : public ::testing::Test {
protected:
    fs::path dir;

    void SetUp() override {
        dir = fs::temp_directory_path() / fs::path("flux-gtest-zmq-" + std::to_string(getpid()));
        fs::create_directories(dir);
        ASSERT_EQ(g_zmq_notification_interface, nullptr);
    }

    void TearDown() override {
        delete g_zmq_notification_interface;
        g_zmq_notification_interface = NULL;
        fs::remove_all(dir);
    }

    std::string Ipc(const std::string& name) {
        return "ipc://" + (dir / name).string();
    }
};

TEST_F(ZMQRPC, NothingConfiguredIsEmpty) {
    UniValue result = getzmqnotifications(UniValue(UniValue::VARR), false);
    ASSERT_TRUE(result.isArray());
    EXPECT_EQ(result.size(), 0u);
}

TEST_F(ZMQRPC, ListsEachPublishingNotifier) {
    std::map<std::string, std::string> args = {
        {"-zmqpubhashblock", Ipc("hashblock")},
        {"-zmqpubfluxnodestatus", Ipc("status")},
        {"-rpcport", "16124"},
    };
    g_zmq_notification_interface = CZMQNotificationInterface::CreateWithArguments(args);
    ASSERT_NE(g_zmq_notification_interface, nullptr);

    UniValue result = getzmqnotifications(UniValue(UniValue::VARR), false);
    ASSERT_EQ(result.size(), 2u);
    std::map<std::string, std::string> seen;
    for (size_t i = 0; i < result.size(); i++) {
        const UniValue& n = result[i];
        ASSERT_EQ(n.getKeys().size(), 2u);
        seen[n["type"].get_str()] = n["address"].get_str();
    }
    EXPECT_EQ(seen["pubhashblock"], Ipc("hashblock"));
    EXPECT_EQ(seen["pubfluxnodestatus"], Ipc("status"));
}

TEST_F(ZMQRPC, OneNotifierFailingToStartTurnsZMQOff) {
    std::map<std::string, std::string> args = {
        {"-zmqpubhashblock", Ipc("hashblock")},
        {"-zmqpubrawtx", "not-an-endpoint"},
    };
    g_zmq_notification_interface = CZMQNotificationInterface::CreateWithArguments(args);
    EXPECT_EQ(g_zmq_notification_interface, nullptr);
    EXPECT_EQ(getzmqnotifications(UniValue(UniValue::VARR), false).size(), 0u);
}

TEST_F(ZMQRPC, RefusesParametersAndAnswersHelp) {
    UniValue one(UniValue::VARR);
    one.push_back(1);
    EXPECT_THROW(getzmqnotifications(one, false), std::runtime_error);
    EXPECT_THROW(getzmqnotifications(UniValue(UniValue::VARR), true), std::runtime_error);
}
