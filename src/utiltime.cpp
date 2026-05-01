// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "utiltime.h"

#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>

using namespace std;

static int64_t nMockTime = 0; //!< For unit testing

int64_t GetTime()
{
    if (nMockTime) return nMockTime;

    return time(NULL);
}

int64_t GetMockableTimeMicros()
{
    if (nMockTime) return nMockTime * 1000000;
    return GetTimeMicros();
}

void SetMockTime(int64_t nMockTimeIn)
{
    nMockTime = nMockTimeIn;
}

int64_t GetTimeMillis()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t GetTimeMicros()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
}

void MilliSleep(int64_t n)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(n));
}

std::string DateTimeStrFormat(const char* pszFormat, int64_t nTime)
{
    // Using C++20 chrono instead of boost::posix_time
    std::time_t time = static_cast<std::time_t>(nTime);
    std::tm* tm = std::gmtime(&time);

    std::stringstream ss;
    ss.imbue(std::locale::classic());
    ss << std::put_time(tm, pszFormat);
    return ss.str();
}
