// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uint256.h"

#include <atomic>
#include <mutex>
#include <string>

struct AtomicCounter {
    std::atomic<uint64_t> value;

    AtomicCounter() : value {0} { }

    void increment(){
        ++value;
    }

    void decrement(){
        --value;
    }

    int get() const {
        return value.load();
    }
};

class AtomicTimer {
private:
    std::mutex mtx;
    uint64_t threads;
    int64_t start_time;
    int64_t total_time;

public:
    AtomicTimer() : threads(0), start_time(0), total_time(0) {}

    /**
     * Starts timing on first call, and counts the number of calls.
     */
    void start();

    /**
     * Counts number of calls, and stops timing after it has been called as
     * many times as start().
     */
    void stop();

    bool running();

    uint64_t threadCount();

    double rate(const AtomicCounter& count);
};

extern AtomicCounter transactionsValidated;
extern AtomicCounter ehSolverRuns;
extern AtomicCounter solutionTargetChecks;
extern AtomicTimer miningTimer;

void TrackMinedBlock(uint256 hash);

void MarkStartTime();
double GetLocalSolPS();
int EstimateNetHeightInner(int height, int64_t tipmediantime,
                           int heightLastCheckpoint, int64_t timeLastCheckpoint,
                           int64_t genesisTime, int64_t targetSpacing);

void TriggerRefresh();

void ConnectMetricsScreen();
void ThreadShowMetricsScreen();

/**
 * Heart image: https://commons.wikimedia.org/wiki/File:Heart_coraz%C3%B3n.svg
 * License: CC BY-SA 3.0
 *
 * Rendering options:
 * Zel: img2txt -W 40 -H 20 -f utf8 -d none -g 0.7 Zel-logo.png (active)
 * Heart: img2txt -W 40 -H 20 -f utf8 -d none 2000px-Heart_corazón.svg.png
 */
const std::string METRICS_ART =
"              [0;1;30;90;44m@@@@@@@@@@@@[0m              \n"
"         [0;1;30;90;44m@@@@@@@@@@@@@@@@@@@@@@[0m         \n"
"       [0;1;30;90;44m@@@@@@@@@@@@@@@@@@@@@@@@@@[0m       \n"
"     [0;1;30;90;44m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@[0m     \n"
"   [0;1;30;90;44m@@@@@@@@@@@@@@@@[0;36;5;40;100m  [0;1;30;90;44m@@@@@@@@@@@@@@@@[0m   \n"
"  [0;1;30;90;44m@@@@@@@@@@@@@[0;36;5;40;100m8[0;1;30;90;47m8[0;1;37;97;47mX[0;37;5;47;107m.  .[0;1;37;97;47mS[0;1;30;90;47m8[0;36;5;40;100m8[0;1;30;90;44m@@@@@@@@@@@@@[0m  \n"
" [0;1;30;90;44m@@@@@@@@@@@[0;36;5;40;100m@[0;1;30;90;47m;[0;37;5;47;107m@          @[0;1;30;90;47m;[0;36;5;40;100m@[0;1;30;90;44m@@@@@@@@@@@[0m \n"
" [0;1;30;90;44m@@@@@@@@@@@[0;1;30;90;47mX[0;37;5;47;107m              [0;1;30;90;47mX[0;1;30;90;44m@@@@@@@@@@@[0m \n"
"[0;1;30;90;44m@@@@@@@@[0;36;5;40;100m@[0;1;30;90;47m8[0;1;37;97;47mX[0;37;5;47;107m%[0;1;37;97;47m;  [0;37;5;47;107m8        8[0;1;37;97;47m [0;1;30;90;47m:[0;1;37;97;47m:[0;37;5;47;107m%[0;1;37;97;47m@[0;1;30;90;47m@[0;36;5;40;100mX[0;1;30;90;44m@@@@@@@@[0m\n"
"[0;1;30;90;44m@@@@@[0;36;5;40;100mS[0;1;37;97;47m [0;37;5;47;107mX      .[0;1;37;97;47m8 [0;1;30;90;47m%[0;37;5;47;107m    [0;1;30;90;47mS:[0;1;37;97;47m@[0;37;5;47;107m.      S[0;1;37;97;47m [0;36;5;40;100mt[0;1;30;90;44m@@@@@[0m\n"
"[0;1;30;90;44m@@@@@[0;1;37;97;47m [0;37;5;47;107m           [0;37;5;40;100mX[0;37;5;47;107m    [0;36;5;40;100m [0;37;5;47;107m           [0;1;37;97;47m.[0;1;30;90;44m@@@@@[0m\n"
"[0;1;30;90;44m@@@@@[0;1;37;97;47m [0;37;5;47;107m           [0;37;5;40;100mX[0;37;5;47;107m    [0;36;5;40;100m [0;37;5;47;107m           [0;1;37;97;47m.[0;1;30;90;44m@@@@@[0m\n"
" [0;1;30;90;44m@@@@[0;1;37;97;47m [0;37;5;47;107m           [0;36;5;40;100m [0;37;5;47;107m8  8[0;36;5;40;100m:[0;37;5;47;107m           [0;1;37;97;47m.[0;1;30;90;44m@@@@[0m \n"
" [0;1;30;90;44m@@@@[0;36;5;40;100m8[0;1;30;90;47m@[0;1;37;97;47m@[0;37;5;47;107m.     t[0;1;37;97;47m:[0;37;5;40;100mX[0;1;30;90;44m8@[0;34;5;40;100m88[0;1;30;90;44m@8[0;37;5;40;100mX[0;1;37;97;47m.[0;37;5;47;107mt     .[0;1;37;97;47m8[0;1;30;90;47mX[0;36;5;40;100m8[0;1;30;90;44m@@@@[0m \n"
"  [0;1;30;90;44m@@@@@@X[0;36;5;40;100m [0;1;37;97;47m 8[0;1;30;90;47m%[0;36;5;40;100mt[0;1;30;90;44m8@@@@@@@@@@@[0;36;5;40;100m%[0;1;30;90;47mS[0;1;37;97;47m8:[0;37;5;40;100mX[0;1;30;90;44mX@@@@@@[0m  \n"
"   [0;1;30;90;44m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@[0m   \n"
"     [0;1;30;90;44m@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@[0m     \n"
"       [0;1;30;90;44m@@@@@@@@@@@@@@@@@@@@@@@@@@[0m       \n"
"         [0;1;30;90;44m@@@@@@@@@@@@@@@@@@@@@@[0m         \n"
"              [0;1;30;90;44m@@@@@@@@@@@@[0m              ";