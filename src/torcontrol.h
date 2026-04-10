// Copyright (c) 2015 The Bitcoin Core developers
#include <vector>
#include <thread>
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

/**
 * Functionality for communicating with Tor.
 */
#ifndef BITCOIN_TORCONTROL_H
#define BITCOIN_TORCONTROL_H

#include "scheduler.h"

extern const std::string DEFAULT_TOR_CONTROL;
static const bool DEFAULT_LISTEN_ONION = true;

void StartTorControl(std::vector<std::thread>& threadGroup, CScheduler& scheduler);
void InterruptTorControl();
void StopTorControl();

/** Get the raw 64-byte ed25519 secret key for the local Tor hidden service.
 *  Returns false if the key is not yet available.  sk is in libsodium
 *  crypto_sign format (suitable for crypto_sign_detached). */
bool GetTorServiceEd25519Key(unsigned char sk[64], unsigned char pk[32]);

/** Get our .onion service ID (56-char base32, without ".onion" suffix).
 *  Returns empty string if not available. */
std::string GetTorServiceID();

#endif /* BITCOIN_TORCONTROL_H */
