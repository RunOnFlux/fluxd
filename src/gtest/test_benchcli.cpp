// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <string>

#include "fluxnode/benchmarks.h"
#include "util.h"

namespace {

// What /bin/sh makes of `printf '%s\n' <words>`: one line per word.
std::string ShellWords(const std::string& words)
{
    std::string out;
    FILE* p = popen(("printf '%s\\n' " + words).c_str(), "r");
    char buf[512];
    while (p && fgets(buf, sizeof(buf), p))
        out += buf;
    if (p)
        pclose(p);
    return out;
}

struct BenchCliArgs {
    std::filesystem::path dir;
    BenchCliArgs()
    {
        dir = std::filesystem::temp_directory_path() /
              ("test_benchcli_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir);
        mapArgs["-datadir"] = dir.string();
        ClearDatadirCache();
    }
    ~BenchCliArgs()
    {
        mapArgs.erase("-fluxbenchsocket");
        mapArgs.erase("-datadir");
        mapArgs.erase("-testnet");
        ClearDatadirCache();
        std::filesystem::remove_all(dir);
    }
};

} // namespace

TEST(BenchCli, NoSocketMeansTheCliDefaults)
{
    BenchCliArgs args;
    std::string cmd = BenchCliCommand();

    EXPECT_EQ(cmd.find("-rpcunixsocket"), std::string::npos);
    EXPECT_EQ(cmd.find("-datadir"), std::string::npos);
}

TEST(BenchCli, SocketAndDatadirArePassed)
{
    BenchCliArgs args;
    mapArgs["-fluxbenchsocket"] = "/run/fluxbenchd/node.sock";
    mapArgs["-testnet"] = "1";
    std::string cmd = BenchCliCommand();

    EXPECT_NE(cmd.find("-testnet -rpcunixsocket='/run/fluxbenchd/node.sock' -datadir='" + args.dir.string() + "' "),
              std::string::npos);
}

TEST(BenchCli, ASocketPathStaysOneWord)
{
    BenchCliArgs args;
    mapArgs["-fluxbenchsocket"] = "/run/x'; touch /tmp/benchcli-injected; '";
    std::string cmd = BenchCliCommand();
    std::string words = cmd.substr(cmd.find("-rpcunixsocket="));

    EXPECT_EQ(ShellWords(words),
              "-rpcunixsocket=/run/x'; touch /tmp/benchcli-injected; '\n-datadir=" + args.dir.string() + "\n");
    EXPECT_FALSE(std::filesystem::exists("/tmp/benchcli-injected"));
}
