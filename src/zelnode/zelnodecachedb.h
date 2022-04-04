//
// Created by ja on 11/14/19.
//

#ifndef ZELCASH_FLUXNODECACHEDB_H
#define ZELCASH_FLUXNODECACHEDB_H

#include "dbwrapper.h"
#include <boost/filesystem/path.hpp>

class FluxnodeCacheData;
class COutPoint;
class CFluxnodeTxBlockUndo;

class CDeterministicFluxnodeDB : public CDBWrapper
{
public:
    CDeterministicFluxnodeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

private:
    CDeterministicFluxnodeDB(const CDeterministicFluxnodeDB&);
    void operator=(const CDeterministicFluxnodeDB&);

public:
    bool WriteFluxnodeCacheData(const FluxnodeCacheData& data);
    bool ReadFluxnodeCacheData(const COutPoint& outpoint, FluxnodeCacheData& data);
    bool EraseFluxnodeCacheData(const COutPoint& outpoint);
    bool FluxnodeCacheDataExists(const COutPoint& outpoint);

    bool LoadFluxnodeCacheData();

    bool WriteBlockUndoFluxnodeData(const uint256& p_blockHash, CFluxnodeTxBlockUndo& p_undoData);
    bool ReadBlockUndoFluxnodeData(const uint256 &p_blockHash, CFluxnodeTxBlockUndo& p_undoData);
};

#endif //ZELCASH_FLUXNODECACHEDB_H
