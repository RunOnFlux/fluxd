// Copyright (c) 2009-2010 Satoshi Nakamoto
#include <vector>
#include <thread>
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <string>

#include "flux/JoinSplit.hpp"

class CScheduler;
class CWallet;

namespace boost
{
class thread_group;
} // namespace boost

extern CWallet* pwalletMain;
extern ZCJoinSplit* pfluxParams;

void StartShutdown();
bool ShutdownRequested();
/** Interrupt threads */
void Interrupt(std::vector<std::thread>& threadGroup);
void Shutdown();
bool AppInit2(std::vector<std::thread>& threadGroup, CScheduler& scheduler);

/** The help message mode determines what help message to show */
enum HelpMessageMode {
    HMM_BITCOIND
};

/** Help for options shared between UI and daemon (for -help) */
std::string HelpMessage(HelpMessageMode mode);

#endif // BITCOIN_INIT_H
