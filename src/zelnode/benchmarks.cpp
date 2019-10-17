// Copyright (c) 2019 The Zelcash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <util.h>
#include <utiltime.h>
#include "benchmarks.h"
#include <regex>
#include "zelnode/zelnode.h"

#define SYSTEM_BENCH_MIN_MAJOR_VERSION 1
#define SYSTEM_BENCH_MIN_MINOR_VERSION 0
#define SYSTEM_BENCH_MIN_PATCH_VERSION 16


bool fBenchmarkComplete = false;
bool fBenchmarkFailed = false;
Benchmarks benchmarks;

std::regex re_cpu("CPU cores:[^0-9]*([0-9]+)\\n");
std::regex re_ram("RAM:[^0-9]*([0-9.]+)G\\n");
std::regex re_ssd("([0-9.]+)(G|T|M)\\s*(SSD|HDD)\\n");
std::regex re_iops(".*?([0-9.]+).?(k?).?iops,");
std::regex re_dd("average:.* ([0-9.]+)");
std::regex re_version("sysbench ([0-9.]+)");
std::regex re_eps("events per second:[^0-9.]+([0-9.]+)\\n");

std::string sysbenchversion = "sysbench --version";
// This downloads the script, we have the current script as a string in benchmarks.h
// The same script is in the contrib/devtools/nench.sh for testing
//std::string nenchtest = "wget -qO- wget.racing/nench.sh | sudo bash";
std::string sysbenchinstall = "sudo apt -y install sysbench";
std::string sysbenchfetch = "curl -s https://packagecloud.io/install/repositories/akopytov/sysbench/script.deb.sh | sudo bash";

bool Benchmarks::IsNenchCheckComplete()
{
    return nNumberOfCores && (nSSD || nHDD) && nAmountofRam && nIOPS && nDDWrite;
}

bool Benchmarks::IsSysBenchCheckComplete()
{
    return nEventsPerSecond;
}

std::string Benchmarks::NenchResultToString()
{
    return "Current nench Stats: \n"
           "CPU Cores : " + std::to_string(benchmarks.nNumberOfCores) + "\n"
         + "RAM : " + std::to_string(benchmarks.nAmountofRam) + " G\n"
         + "SSD : " + std::to_string(benchmarks.nSSD) + " G\n"
         + "HDD : " + std::to_string(benchmarks.nHDD) + " G\n"
         + "IOPS : " + std::to_string(benchmarks.nIOPS) + "\n"
         + "DD_WRITE : " + std::to_string(benchmarks.nDDWrite) + " MiB/s\n";
}

void ThreadBenchmarkZelnode()
{
    // Make this thread recognisable as the wallet flushing thread
    RenameThread("zelcash-zelnode-benchmarking");
    LogPrintf("Starting Zelnodes Benchmarking Thread\n");

    if (fBenchmarkComplete) {
        return;
    }

    /** Setup sysbench */
    SetupSysBench();

    if (!benchmarks.fVersionValid) {
        fBenchmarkFailed = true;
        LogPrintf("---Sysbench version failed verification\n");
        return;
    }

    /** Run the nench System Test */
    RunNenchTest();

    /** Check the nench Results */
    if (!benchmarks.IsNenchCheckComplete()) {
        fBenchmarkFailed = true;
        LogPrintf("---Failed Getting nench Stats:  %s\n", benchmarks.NenchResultToString());
        return;
    }

    /** Run the sysbench System Test */
    RunSysBenchTest();

    /** Check the sysbench Results */
    if (!benchmarks.IsSysBenchCheckComplete()) {
        fBenchmarkFailed = true;
        LogPrintf("---Failed Getting sysbench stats\n");
        return;
    }

    fBenchmarkComplete = true;
}

std::string GetStdoutFromCommand(std::string cmd) {

    std::string data;
    FILE * stream;
    const int max_buffer = 250;
    char buffer[max_buffer];
    //cmd.append(" 2>&1"); // Do we want STDERR?

    stream = popen(cmd.c_str(), "r");
    if (stream) {
        while (!feof(stream))
            if (fgets(buffer, max_buffer, stream) != NULL) data.append(buffer);
        pclose(stream);
    }
    return data;
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

void RunNenchTest()
{
    LogPrintf("---Starting nench test\n");
    std::smatch cpu_match;
    std::smatch ram_match;
    std::smatch ssd_match;
    std::smatch iops_match;
    std::smatch ddwrite_match;

    std::string result = GetStdoutFromCommand(strNenchScript + " | sudo bash");

    // Get CPU metrics
    if (std::regex_search(result, cpu_match, re_cpu) && cpu_match.size() > 1) {
        benchmarks.nNumberOfCores = stoi(cpu_match.str(1));
        LogPrintf("---Found cores: %d\n", benchmarks.nNumberOfCores);
    }

    // Get RAM metrics
    if (std::regex_search(result, ram_match, re_ram) && ram_match.size() > 1) {
        benchmarks.nAmountofRam = stof(ram_match.str(1));
        LogPrintf("---Found ram: %d\n", benchmarks.nAmountofRam);
    }

    std::string copy = result;
    // Get SSD metrics
    while (regex_search(copy, ssd_match, re_ssd) && ssd_match.size() > 1)
    {
        // Default for Gigabyte
        float multiplier = 1;

        if (ssd_match.str(2) == "M") { // Megabytes
            multiplier = 0.0001;
        } else if (ssd_match.str(2) == "T") { // Terabyte
            multiplier = 1000;
        }

        if (ssd_match.str(3) == "SSD") {
            float num = stof(ssd_match.str(1)) * multiplier;
            benchmarks.nSSD += num;
            LogPrintf("---Found SSD: %0.6f G\n", num);
        } else if (ssd_match.str(3) == "HDD") {
            float num = stof(ssd_match.str(1)) * multiplier;
            benchmarks.nHDD += num;
            LogPrintf("---Found HDD: %0.6f G\n", num);
        }
        copy = ssd_match.suffix();
    }

    // Get IOPS metrics
    if (std::regex_search(result, iops_match, re_iops) && iops_match.size() > 1) {
        float multiplier= 1;
        if (iops_match.str(2) == "k")
            multiplier = 1000;
        float num = stof(iops_match.str(1)) * multiplier;

        benchmarks.nIOPS = num;
        LogPrintf("---Found iops: %u\n", benchmarks.nIOPS);
    }

    // Get DD_WRITE metrics
    if (std::regex_search(result, ddwrite_match, re_dd) && ddwrite_match.size() > 1) {
        benchmarks.nDDWrite = stof(ddwrite_match.str(1));
        LogPrintf("---Found DD_WRITE: %u\n", benchmarks.nDDWrite);
    }

    LogPrintf("---Finished nench test\n");
}

void SetupSysBench()
{
    /** Install and check sysbench version */
    LogPrintf("---sysbench system setup starting\n");
    // install the system package and sysbench
    if (!CheckSysBenchInstalled()) {
        InstallSysBenchPackage();
        InstallSysBench();
    } else {
        LogPrintf("---sysbench already installed\n");
    }

    // calling install should upgrade the sysbench
    if (!CheckSysBenchVersion()) {
        InstallSysBench();
        if (!CheckSysBenchVersion()) {
            LogPrintf("---sysbench latest version failed check: %d.%d.%d\n", benchmarks.nMajorVersion, benchmarks.nMinorVersion, benchmarks.nPatchVersion);
        }
    } else {
        LogPrintf("---sysbench found version: %d.%d.%d\n", benchmarks.nMajorVersion, benchmarks.nMinorVersion, benchmarks.nPatchVersion);
    }

    LogPrintf("---sysbench system setup completed\n");
}

void RunSysBenchTest()
{

    LogPrintf("---Starting sysbench test\n");
    std::string command = "sysbench --test=cpu --threads=" + std::to_string(benchmarks.nNumberOfCores) + " --cpu-max-prime=60000 --time=20 run";

    std::string result = GetStdoutFromCommand(command);

    std::smatch eps_batch;

    // Get CPU metrics
    if (std::regex_search(result, eps_batch, re_eps) && eps_batch.size() > 1) {
        benchmarks.nEventsPerSecond = stof(eps_batch.str(1));
        LogPrintf("---Found eps: %u\n", benchmarks.nEventsPerSecond);
    }
    LogPrintf("---Finished sysbench test\n");
}

void InstallSysBenchPackage()
{
    LogPrintf("---Fetching sysbench\n");
    std::string getpackage = GetStdoutFromCommand(sysbenchfetch);
    LogPrintf("---Finished Fetching sysbench\n");

    //LogPrintf("GetPackage : %s", getpackage);
}

void InstallSysBench()
{
    LogPrintf("---Installing sysbench\n");
    std::string installsysbench = GetStdoutFromCommand(sysbenchinstall);
    LogPrintf("---Finished Installing sysbench\n");

    //LogPrintf("InstallSysbench : %s", installsysbench);
}

bool CheckBenchmarks(int tier)
{
    if (tier == Zelnode::BAMF) {
        return !(/**benchmarks.nNumberOfCores < 8 ||*/ benchmarks.nAmountofRam < 30 || (benchmarks.nSSD + benchmarks.nHDD) < 600 || benchmarks.nEventsPerSecond < 500 || benchmarks.nIOPS < 700 || benchmarks.nDDWrite < 200); // bamf spec
    } else if (tier == Zelnode::SUPER)
        return !(/**benchmarks.nNumberOfCores < 4 ||*/ benchmarks.nAmountofRam < 7 || (benchmarks.nSSD + benchmarks.nHDD) < 150 || benchmarks.nEventsPerSecond < 250 || benchmarks.nIOPS < 700 || benchmarks.nDDWrite < 200); // super spec
    else if (tier == Zelnode::BASIC)
        return !(/**benchmarks.nNumberOfCores < 2 ||*/ benchmarks.nAmountofRam < 3 || (benchmarks.nSSD + benchmarks.nHDD) < 50 || benchmarks.nEventsPerSecond < 130 || benchmarks.nIOPS < 700 || benchmarks.nDDWrite < 200); // basic spec

    return false;
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




