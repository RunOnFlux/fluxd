// Copyright (c) 2019 The Zelcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <vector>

#ifndef ZELCASH_BENCHMARKS_H
#define ZELCASH_BENCHMARKS_H

class Benchmarks;
class CTransaction;
extern Benchmarks benchmarks;
extern bool fZelStartedBench;
extern std::string strBenchmarkPathing;
extern std::string strBenchmarkCliPathing;

class Benchmarks {
public:
    int nMajorVersion;
    int nMinorVersion;
    int nPatchVersion;
    bool fVersionValid;
};

bool FindBenchmarkPath(std::string& path, const std::string filename);
std::string GetBenchCliPath();
std::string GetBenchDaemonPath();

bool IsZelBenchdRunning();
void StartZelBenchd();
void StopZelBenchd();
std::string GetBenchmarks();
std::string GetZelBenchdStatus();
bool GetBenchmarkSignedTransaction(const CTransaction& tx, CTransaction& signedTx, std::string& error);

std::string GetStdoutFromCommand(std::string cmd, bool redirect_stdout = false, bool redirect_devnull = false);
void RunCommand(std::string cmd);

// Parsing help functions
std::vector<std::string> split(std::string s, std::string delimiter);
#endif //ZELCASH_BENCHMARKS_H
