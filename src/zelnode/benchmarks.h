//
// Created by anderson on 2/13/19.
//

#include <vector>

#ifndef ZELCASH_BENCHMARKS_H
#define ZELCASH_BENCHMARKS_H

class Benchmarks;

extern bool fBenchmarkComplete;
extern bool fBenchmarkFailed;
extern Benchmarks benchmarks;

class Benchmarks {
public:
    // Nench
    int nNumberOfCores;
    int nAmountofRam;
    float nSSD;
    float nIOPS;
    float nDDWrite;

    // Sysbench
    float nEventsPerSecond;
    int nMajorVersion;
    int nMinorVersion;
    int nPatchVersion;
    bool fVersionValid;

    Benchmarks() {
        SetNull();
    }

    void SetNull() {
        nNumberOfCores = 0;
        nAmountofRam = 0;
        nSSD = 0;
        nIOPS = 0;
        nDDWrite = 0;
        nEventsPerSecond = 0;
        nMajorVersion = 0;
        nMinorVersion = 0;
        nPatchVersion = 0;
        fVersionValid = false;
    }

    bool IsNenchCheckComplete();
    bool IsSysBenchCheckComplete();
    std::string NenchResultToString();
};

bool CheckBenchmarks(int tier);

void ThreadBenchmarkZelnode();

void SetupSysBench();
bool CheckSysBenchInstalled();
bool CheckSysBenchVersion();
void RunSysBenchTest();
void RunNenchTest();
void InstallSysBenchPackage();
void InstallSysBench();

std::string GetStdoutFromCommand(std::string cmd);


// Parsing help functions
std::vector<std::string> split(std::string s, std::string delimiter);


#endif //ZELCASH_BENCHMARKS_H
