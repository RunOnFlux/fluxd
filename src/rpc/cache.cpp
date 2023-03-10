//
// Created by main on 10/3/23.
//

#include "cache.h"
#include <univalue.h>

void CRPCFluxnodeCache::ClearFluxnodeListCache()
{
    nHeight = -1;
    list = NullUniValue;
    filter = "";
}

void CRPCFluxnodeCache::SetFluxnodeListCache(int64_t pHeight, UniValue& pList, std::string& pFilter)
{
    nHeight = pHeight;
    list = pList;
    filter = pFilter;
}
