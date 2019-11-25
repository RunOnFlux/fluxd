//
// Created by ja on 11/14/19.
//

#ifndef ZELCASH_ZELNODECACHEDB_H
#define ZELCASH_ZELNODECACHEDB_H

#include "dbwrapper.h"
#include <boost/filesystem/path.hpp>

class ZelnodeCacheData;
class COutPoint;
class CZelnodeTxBlockUndo;

class CDeterministicZelnodeDB : public CDBWrapper
{
public:
    CDeterministicZelnodeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

private:
    CDeterministicZelnodeDB(const CDeterministicZelnodeDB&);
    void operator=(const CDeterministicZelnodeDB&);

public:
    bool WriteZelnodeCacheData(const ZelnodeCacheData& data);
    bool ReadZelnodeCacheData(const COutPoint& outpoint, ZelnodeCacheData& data);
    bool EraseZelnodeCacheData(const COutPoint& outpoint);
    bool ZelnodeCacheDataExists(const COutPoint& outpoint);

    bool LoadZelnodeCacheData();

    bool WriteBlockUndoZelnodeData(const uint256& p_blockHash, CZelnodeTxBlockUndo& p_undoData);
    bool ReadBlockUndoZelnodeData(const uint256 &p_blockHash, CZelnodeTxBlockUndo& p_undoData);
};

#endif //ZELCASH_ZELNODECACHEDB_H
