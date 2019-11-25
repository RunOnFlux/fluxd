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


#define SYSTEM_BENCH_MIN_MAJOR_VERSION 0
#define SYSTEM_BENCH_MIN_MINOR_VERSION 4
#define SYSTEM_BENCH_MIN_PATCH_VERSION 12

Benchmarks benchmarks;
bool fZelStartedBench = false;
std::regex re_version("sysbench ([0-9.]+)");

std::string sysbenchversion = "sysbench --version";
// This downloads the script, we have the current script as a string in benchmarks.h
// The same script is in the contrib/devtools/nench.sh for testing
//std::string nenchtest = "wget -qO- wget.racing/nench.sh | sudo bash";
std::string sysbenchinstall_1 = "sudo apt -y install sysbench";
std::string sysbenchinstall_2 = "sudo apt install sysbench";
std::string sysbenchfetch = "curl -s https://packagecloud.io/install/repositories/akopytov/sysbench/script.deb.sh | sudo bash";

std::string strTestnetSring = "-testnet ";


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


bool CheckSysBenchInstalled()
{
    std::string result = GetStdoutFromCommand(sysbenchversion);

    std::smatch version_match;
    // Get CPU metrics
    if (std::regex_search(result, version_match, re_version) && version_match.size() > 1) {
        return true;
    }

    return false;
}

bool CheckSysBenchVersion()
{
    std::string result = GetStdoutFromCommand(sysbenchversion);

    std::smatch version_match;
    // Get CPU metrics
    if (std::regex_search(result, version_match, re_version) && version_match.size() > 1) {
        // Split by period (1.0.16 - > [1,0,16])
        std::vector<std::string> vec = split(version_match.str(1), ".");

        if (vec.size() >= 1) benchmarks.nMajorVersion = stoi(vec[0]);
        if (vec.size() >= 2) benchmarks.nMinorVersion = stoi(vec[1]);
        if (vec.size() >= 3) benchmarks.nPatchVersion = stoi(vec[2]);

        // Check major version number
        if (vec.size() >= 1) {

            if (benchmarks.nMajorVersion < SYSTEM_BENCH_MIN_MAJOR_VERSION)
                return false;
            if (benchmarks.nMajorVersion > SYSTEM_BENCH_MIN_MAJOR_VERSION) {
                benchmarks.fVersionValid = true;
                return true;
            }
        }

        // Check minor version number
        if (vec.size() >= 2) {
            if (benchmarks.nMinorVersion < SYSTEM_BENCH_MIN_MINOR_VERSION)
                return false;
            if (benchmarks.nMinorVersion > SYSTEM_BENCH_MIN_MINOR_VERSION) {
                benchmarks.fVersionValid = true;
                return true;
            }
        }

        // Check patch version number
        if (vec.size() >= 3) {
            if (benchmarks.nPatchVersion < SYSTEM_BENCH_MIN_PATCH_VERSION)
                return false;
            if (benchmarks.nPatchVersion >= SYSTEM_BENCH_MIN_PATCH_VERSION) {
                benchmarks.fVersionValid = true;
                return true;
            }
        }

        return false;
    }

    return false;
}

void SetupSysBench()
{
    /** Install and check sysbench version */
    LogPrintf("---sysbench system setup starting\n");
    // install the system package and sysbench
    if (!CheckSysBenchInstalled()) {
        InstallSysBenchPackage();
        InstallSysBench_1();
        if(!CheckSysBenchInstalled())
            InstallSysBench_2();
    } else {
        LogPrintf("---sysbench already installed\n");
    }

    // calling install should upgrade the sysbench
    if (!CheckSysBenchVersion()) {
        InstallSysBench_1();
        InstallSysBench_2();
        if (!CheckSysBenchVersion()) {
            LogPrintf("---sysbench latest version failed check: %d.%d.%d\n", benchmarks.nMajorVersion, benchmarks.nMinorVersion, benchmarks.nPatchVersion);
        }
    } else {
        LogPrintf("---sysbench found version: %d.%d.%d\n", benchmarks.nMajorVersion, benchmarks.nMinorVersion, benchmarks.nPatchVersion);
    }

    LogPrintf("---sysbench system setup completed\n");
}


void InstallSysBenchPackage()
{
    LogPrintf("---Fetching sysbench\n");
    std::string getpackage = GetStdoutFromCommand(sysbenchfetch);
    LogPrintf("---Finished Fetching sysbench\n");

    //LogPrintf("GetPackage : %s", getpackage);
}

void InstallSysBench_1()
{
    LogPrintf("---Installing sysbench 1\n");
    std::string installsysbench = GetStdoutFromCommand(sysbenchinstall_1);
    LogPrintf("---Finished Installing sysbench 1\n");

    //LogPrintf("InstallSysbench 1 : %s", installsysbench);
}

void InstallSysBench_2()
{
    LogPrintf("---Installing sysbench 2\n");
    std::string installsysbench = GetStdoutFromCommand(sysbenchinstall_2);
    LogPrintf("---Finished Installing sysbench 2 \n");

    //LogPrintf("InstallSysbench 2 : %s", installsysbench);
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

bool IsBenchmarkdRunning()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;

    std::string strBenchmarkStatus = GetStdoutFromCommand("./src/benchmark-cli " + testnet + "getstatus true", false, true);

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

void StartBenchmarkd()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;
    RunCommand("./src/benchmarkd " + testnet + "&");
    MilliSleep(4000);
    fZelStartedBench = true;
    LogPrintf("Benchmarkd Started\n");
}


void StopBenchmarkd()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;
    int value = std::system(std::string("./src/benchmark-cli " + testnet + "stop").c_str());
}

std::string GetBenchmarks()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;

    if (IsBenchmarkdRunning()) {
        std::string strBenchmarkStatus = GetStdoutFromCommand("./src/benchmark-cli " + testnet + "getbenchmarks");

        return strBenchmarkStatus;
    }

    return "Benchmarkd not running";
}

std::string GetBenchmarkdStatus()
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;

    if (IsBenchmarkdRunning()) {
        std::string strBenchmarkStatus = GetStdoutFromCommand("./src/benchmark-cli " + testnet + "getstatus");

        return strBenchmarkStatus;
    }

    return "Benchmarkd not running";
}

bool GetBenchmarkSignedTransaction(const CTransaction& tx, CTransaction& signedTx, std::string& error)
{
    std::string testnet = "";
    if (GetBoolArg("-testnet", false))
        testnet = strTestnetSring;

    if (IsBenchmarkdRunning()) {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << tx;
        std::string txHexStr = HexStr(ss.begin(), ss.end());
        std::string response = GetStdoutFromCommand("./src/benchmark-cli " + testnet + "signzelnodetransaction " + txHexStr, true);

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

    error = "Benchmarkd isn't running";
    return false;
}



