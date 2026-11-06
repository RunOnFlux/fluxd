// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_FLUXNODE_BENCHSOCKET_H
#define FLUX_FLUXNODE_BENCHSOCKET_H

#include <string>

#include <univalue/include/univalue.h>

/**
 * One JSON-RPC call to fluxbench on its Unix socket. On ArcaneOS fluxd and fluxbench each run from
 * their own image, so neither has the other's binaries beside it.
 *
 * Answers as fluxbench-cli prints the reply: a string result as it is, anything else as indented
 * JSON. Empty when the socket cannot be reached or the reply cannot be read; the error's message
 * when fluxbench refuses the call.
 */
std::string BenchSocketCall(const std::string& socketPath, const std::string& method, const UniValue& params);

#endif // FLUX_FLUXNODE_BENCHSOCKET_H
