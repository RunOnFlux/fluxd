// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_CACHE_H
#define FLUX_CACHE_H

#include <string>

class UniValue;

class CRPCFluxnodeCache {
public:
    // RPC listfluxnodes
    static int64_t nHeight;
    static UniValue list;
    static std::string filter;

    static void ClearFluxnodeListCache();
    static void SetFluxnodeListCache(int64_t nHeight, UniValue& list, std::string& filter);

};


#endif //FLUX_CACHE_H
