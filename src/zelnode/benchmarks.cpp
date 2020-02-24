// Copyright (c) 2019 The Zelcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <util.h>
#include <utiltime.h>
#include "benchmarks.h"
#include <regex>
#include <univalue/include/univalue.h>
#include <rpc/protocol.h>
#include <core_io.h>
#include "zelnode/zelnode.h"

#include <boost/filesystem.hpp>

namespace filesys = boost::filesystem;


#define SYSTEM_BENCH_MIN_MAJOR_VERSION 0
#define SYSTEM_BENCH_MIN_MINOR_VERSION 4
#define SYSTEM_BENCH_MIN_PATCH_VERSION 12

Benchmarks benchmarks;
bool fZelStartedBench = false;
std::string strBenchmarkPathing = "/usr/local/bin"; // Default path
std::string strBenchmarkCliPathing = "/usr/local/bin"; // Default path

std::string strTestnetSring = "-testnet ";

bool FindBenchmarkPath(std::string& path, const std::string filename)
{
    filesys::path pathObj(path + "/" + filename);
    if (filesys::exists(pathObj) && filesys::is_regular_file(pathObj)) {
        return true;
    }

    char const* home = getenv("HOME");
    path = strprintf("%s", home);
    filesys::path pathObj2(path + "/" + filename);
    if (filesys::exists(pathObj2) && filesys::is_regular_file(pathObj2)) {
        return true;
    }

    path = "./src";
    filesys::path pathObj3(path + "/" + filename);
    if (filesys::exists(pathObj3) && filesys::is_regular_file(pathObj3)) {
        return true;
    }

    return false;
}

std::string GetBenchCliPath()
{
    // The space at the end is so parameters can be added easily
    return strBenchmarkCliPathing + "/zelbench-cli ";
}

std::string GetBenchDaemonPath()
{
    // The space at the end is so parameters can be added easily
    return strBenchmarkCliPathing + "/zelbenchd ";
}


std::string GetStdoutFromCommand(std::string cmd,bool redirect_stdout, bool redirect_devnull) {

    std::string data;
    FILE * stream;
    const int max_buffer = 250;
    char buffer[max_buffer];
    if (redirect_devnull) {
        cmd.append(" 2>/dev/null"); // Do we want STDERR?
    } else if (redirect_stdout) {
        cmd.append(" 2>&1"); // Do we want STDERR?
    }

    stream = popen(cmd.c_str(), "r");
    if (stream) {
        while (!feof(stream))
            if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
        pclose(stream);
    }
    return data;
}

void RunCommand(std::string cmd) {

    std::string data;
    FILE * stream;
    const int max_buffer = 250;
    char buffer[max_buffer];
    //cmd.append(" 2>&1"); // Do we want STDERR?

    stream = popen(cmd.c_str(), "r");
    if (stream) {
        pclose(stream);
    }
}

// for string delimiter
std::vector<std::string> split (std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find (delimiter, pos_start)) != std::string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back (token);
    }

    res.push_back (s.substr (pos_start));
    return res;
}

bool IsZelBenchdRunning()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;

    std::string strBenchmarkStatus = GetStdoutFromCommand(GetBenchCliPath() + testnet + "getstatus true", false, true);

    UniValue response;
    response.read(strBenchmarkStatus);

    if (response.exists("status")) {
        UniValue value = response["status"];
        if (value.get_str() == "online") {
            return true;
        }
    }

    return false;
}

void StartZelBenchd()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;
    RunCommand(GetBenchDaemonPath() + testnet + "&");
    MilliSleep(4000);
    fZelStartedBench = true;
    LogPrintf("ZelBenchd Started\n");
}


void StopZelBenchd()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;
    int value = std::system(std::string(GetBenchCliPath() + testnet + "stop").c_str());
}

std::string GetBenchmarks()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;

    if (IsZelBenchdRunning()) {
        std::string strBenchmarkStatus = GetStdoutFromCommand(GetBenchCliPath() + testnet + "getbenchmarks");

        return strBenchmarkStatus;
    }

    return "ZelBenchd not running";
}

std::string GetZelBenchdStatus()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;

    if (IsZelBenchdRunning()) {
        std::string strBenchmarkStatus = GetStdoutFromCommand(GetBenchCliPath() + testnet + "getstatus");

        return strBenchmarkStatus;
    }

    return "ZelBenchd not running";
}

bool GetBenchmarkSignedTransaction(const CTransaction& tx, CTransaction& signedTx, std::string& error)
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;

    if (IsZelBenchdRunning()) {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << tx;
        std::string txHexStr = HexStr(ss.begin(), ss.end());
        std::string response = GetStdoutFromCommand(GetBenchCliPath() + testnet + "signzelnodetransaction " + txHexStr, true);

        UniValue signedresponse;
        signedresponse.read(response);

        if (signedresponse.exists("status")) {
            UniValue status = signedresponse["status"];
            if (status.get_str() != "complete") {
                error = "Benchmarking hasn't completed, please wait until benchmarking has completed. Current status : " + status.get_str();
                return false;
            }
        }

        if (signedresponse.exists("tier")) {
            UniValue tier = signedresponse["tier"];
        }

        if (signedresponse.exists("hex")) {
            UniValue hex = signedresponse["hex"];
            response = hex.get_str();
        }

        if (!DecodeHexTx(signedTx, response)) {
            error = "Failed to decode zelnode broadcast";
            return false;
        }

        if (!CheckBenchmarkSignature(signedTx)) {
            error = "Failed to verify benchmarked signature";
            return false;
        }

        return true;
    }

    error = "ZelBenchd isn't running";
    return false;
}



