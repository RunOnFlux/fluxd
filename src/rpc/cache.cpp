//
// Created by main on 10/3/23.
//

#include "cache.h"
#include <univalue.h>

// Define the static mutex
CCriticalSection CRPCFluxnodeCache::cs_cache;

void CRPCFluxnodeCache::ClearFluxnodeListCache()
{
    LOCK(cs_cache);
    nHeight = -1;
    list = NullUniValue;
    filter = "";
}

void CRPCFluxnodeCache::SetFluxnodeListCache(int64_t pHeight, UniValue& pList, std::string& pFilter)
{
    LOCK(cs_cache);
    nHeight = pHeight;
    list = pList;
    filter = pFilter;
}

UniValue CRPCFluxnodeCache::GetFluxnodeListCache(const std::string& strFilter, int64_t nCurrentHeight)
{
    LOCK(cs_cache);

    // Check if cache is valid for this request
    if (strFilter == filter && nHeight == nCurrentHeight) {
        // Make a copy of the list while holding the lock
        // This prevents corruption from concurrent access
        UniValue cachedList = list;
        return cachedList;
    }

    // Cache miss - return null
    return NullUniValue;
}
