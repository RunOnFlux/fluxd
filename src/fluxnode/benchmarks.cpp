// Copyright (c) 2019 The Zelcash Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <util.h>
#include <utiltime.h>
#include <regex>
#include <univalue/include/univalue.h>
#include <rpc/protocol.h>
#include <core_io.h>
#include <filesystem>

#include "fluxnode/fluxnode.h"
#include "benchmarks.h"

#include "activefluxnode.h"
#include "fluxnode.h"
#include "../coins.h"
#include "../main.h"
#include "../timedata.h"
#include "../primitives/transaction.h"

#if defined(__linux)
#  include <libgen.h>         // dirname
#  include <unistd.h>         // readlink
#  include <linux/limits.h>   // PATH_MAX
#endif


namespace filesys = std::filesystem;


#define SYSTEM_BENCH_MIN_MAJOR_VERSION 0
#define SYSTEM_BENCH_MIN_MINOR_VERSION 4
#define SYSTEM_BENCH_MIN_PATCH_VERSION 12

Benchmarks benchmarks;
bool fFluxStartedBench = false;
std::string strPath = "";

/** The network flag fluxbench needs to match this node's network. */
static std::string BenchNetworkFlag()
{
    switch (Params().NetworkID()) {
    case CBaseChainParams::TESTNET:
        return "-testnet ";
    case CBaseChainParams::LABNET:
        return "-labnet ";
    default:
        return "";
    }
}

std::string GetSelfPath()
{
    #if defined(__linux)
        char result[ PATH_MAX ];
        ssize_t count = readlink( "/proc/self/exe", result, PATH_MAX - 1 );

        const char *path;

        if (count != -1) {
            result[count] = '\0';
            path = dirname(result);
            return std::string(path);
        }

        return "";
    #endif

    return "";
}

bool FindBenchmarkPath(std::string filename, std::string file_path )
{
   
    filesys::path pathObj(file_path + "/" + filename);
    if (filesys::exists(pathObj) && filesys::is_regular_file(pathObj)) {
        return true;
    }
    return false;
}

std::string GetBenchCliPath()
{
   
    if (FindBenchmarkPath("fluxbench-cli", strPath)) {
        return strPath + "/fluxbench-cli ";
    }

    if (FindBenchmarkPath("zelbench-cli", strPath)) {
        return strPath + "/zelbench-cli ";
    }

    return strPath + "/fluxbench-cli ";

}

/** Single-quotes a word for /bin/sh. */
static std::string ShellQuote(const std::string& word)
{
    std::string quoted = "'";
    for (char c : word) {
        if (c == '\'')
            quoted += "'\\''";
        else
            quoted += c;
    }
    return quoted + "'";
}

bool BenchmarkStatusSignable(const std::string& status)
{
    // fluxbench reports passed/bypassed for a labnet signature made without the FluxOS code-hash
    // list or a measurement cycle; every node still verifies the signature itself.
    return status == "complete" || (Params().NetworkID() == CBaseChainParams::LABNET && status == "passed/bypassed");
}

std::string BenchCliCommand()
{
    std::string cmd = GetBenchCliPath() + BenchNetworkFlag();

    const std::string socket = GetArg("-fluxbenchsocket", "");
    if (!socket.empty()) {
        // The cli reads its conf from -datadir and refuses a datadir that does not exist; fluxd's
        // own datadir always exists, and fluxbench.conf is optional there.
        cmd += "-rpcunixsocket=" + ShellQuote(socket) + " ";
        cmd += "-datadir=" + ShellQuote(GetDataDir(false).string()) + " ";
    }
    return cmd;
}

std::string GetBenchDaemonPath()
{
    // The space at the end is so parameters can be added easily
    if (FindBenchmarkPath("fluxbenchd", strPath)) {
       return strPath + "/fluxbenchd ";
    }

    if (FindBenchmarkPath("zelbenchd", strPath)) {
        return strPath + "/zelbenchd ";
    }

    return strPath + "/fluxbenchd ";

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

bool IsFluxBenchdRunning()
{
    std::string strBenchmarkStatus = GetStdoutFromCommand(BenchCliCommand() + "getstatus true", false, true);

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

void StartFluxBenchd()
{
    RunCommand(GetBenchDaemonPath() + BenchNetworkFlag() + "&");
    MilliSleep(4000);
    fFluxStartedBench = true;
    LogPrintf("Benchmark Started\n");
}


void StopFluxBenchd()
{
    int value = std::system(std::string(BenchCliCommand() + "stop").c_str());
}

std::string GetBenchmarks()
{
    if (IsFluxBenchdRunning()) {
        std::string strBenchmarkStatus = GetStdoutFromCommand(BenchCliCommand() + "getbenchmarks");

        return strBenchmarkStatus;
    }

    return "Benchmark not running";
}

std::string GetFluxBenchdStatus()
{
    if (IsFluxBenchdRunning()) {
        std::string strBenchmarkStatus = GetStdoutFromCommand(BenchCliCommand() + "getstatus");

        return strBenchmarkStatus;
    }

    return "Benchmark not running";
}

bool GetBenchmarkSignedTransaction(const CTransaction& tx, CTransaction& signedTx, std::string& error)
{
    // TESTNET ONLY
    if (IsTestnetBenchmarkBypassActive()) {
        CMutableTransaction mutTx(tx);
        const CCoins* coins = pcoinsTip->AccessCoins(activeFluxnode.deterministicOutPoint.hash);
        if (coins && coins->IsAvailable(activeFluxnode.deterministicOutPoint.n)) {
            int nTier = 0;
            GetCoinTierFromAmount(chainActive.Height(), coins->vout[activeFluxnode.deterministicOutPoint.n].nValue, nTier);
            mutTx.benchmarkTier = nTier;
            mutTx.benchmarkSigTime = GetAdjustedTime();
        }
        signedTx = CTransaction(mutTx);
        LogPrintf("Testnet - Bypass Benchmark Request for signature\n");
        return true;
    }

    if (IsFluxBenchdRunning()) {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << tx;
        std::string txHexStr = HexStr(ss.begin(), ss.end());
        std::string response = GetStdoutFromCommand(BenchCliCommand() + "signfluxnodetransaction " + txHexStr, true);

        UniValue signedresponse;
        signedresponse.read(response);

        if (signedresponse.exists("status")) {
            UniValue status = signedresponse["status"];
            if (!BenchmarkStatusSignable(status.get_str())) {
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
            error = "Failed to decode fluxnode broadcast";
            return false;
        }

        if (!CheckBenchmarkSignature(signedTx)) {
            error = "Failed to verify benchmarked signature";
            return false;
        }

        return true;
    }

    

    error = "Benchd isn't running";
    return false;
}
