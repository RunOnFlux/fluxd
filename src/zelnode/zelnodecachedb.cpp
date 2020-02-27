//
// Created by ja on 11/14/19.
//

#include "zelnode/zelnodecachedb.h"
#include "zelnode.h"
#include "undo.h"
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>

static const char DB_ZELNODE_CACHE_DATA = 'd';
static const char BLOCK_ZELNODE_UNDO_DATA = 'u';

CDeterministicZelnodeDB::CDeterministicZelnodeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "determ_zelnodes", nCacheSize, fMemory, fWipe) {}

bool CDeterministicZelnodeDB::WriteZelnodeCacheData(const ZelnodeCacheData& data)
{
    LogPrint("dzelnode", "Wrote zelnodedata %s to database\n", data.collateralIn.ToString());
    return Write(std::make_pair(DB_ZELNODE_CACHE_DATA, data.collateralIn), data);
}

bool CDeterministicZelnodeDB::ReadZelnodeCacheData(const COutPoint& outpoint, ZelnodeCacheData& data)
{
    return Read(std::make_pair(DB_ZELNODE_CACHE_DATA, data.collateralIn), data);
}

bool CDeterministicZelnodeDB::EraseZelnodeCacheData(const COutPoint& outpoint)
{
    return Erase(std::make_pair(DB_ZELNODE_CACHE_DATA, outpoint));
}

bool CDeterministicZelnodeDB::ZelnodeCacheDataExists(const COutPoint& outpoint)
{
    return Exists(std::make_pair(DB_ZELNODE_CACHE_DATA, outpoint));
}

bool CDeterministicZelnodeDB::LoadZelnodeCacheData()
{
    boost::scoped_ptr<CDBIterator> pcursor(NewIterator());

    pcursor->Seek(std::make_pair(DB_ZELNODE_CACHE_DATA, COutPoint()));

    LOCK(g_zelnodeCache.cs);
    // Load mapBlockIndex
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, uint256> key;
        if (pcursor->GetKey(key) && key.first == DB_ZELNODE_CACHE_DATA) {
            ZelnodeCacheData data;
            if (pcursor->GetValue(data)) {

                g_zelnodeCache.LoadData(data);

                pcursor->Next();
            } else {
                return error("LoadZelnodeCacheData() : failed to read value");
            }
        } else {
            break;
        }
    }

    LogPrint("dzelnode","%s : Size of mapStartTxTracker: %s\n", __func__, g_zelnodeCache.mapStartTxTracker.size());
    LogPrint("dzelnode", "%s : Size of mapStartTxDosTracker: %s\n", __func__, g_zelnodeCache.mapStartTxDosTracker.size());
    LogPrint("dzelnode", "%s : Size of mapConfirmedZelnodeData: %s\n", __func__, g_zelnodeCache.mapConfirmedZelnodeData.size());

    return true;
}

bool CDeterministicZelnodeDB::WriteBlockUndoZelnodeData(const uint256& p_blockHash, CZelnodeTxBlockUndo& p_undoData)
{
    return Write(std::make_pair(BLOCK_ZELNODE_UNDO_DATA, p_blockHash), p_undoData);
}

bool CDeterministicZelnodeDB::ReadBlockUndoZelnodeData(const uint256 &p_blockHash, CZelnodeTxBlockUndo &p_undoData)
{
    // If it exists, return the read value.
    if (Exists(std::make_pair(BLOCK_ZELNODE_UNDO_DATA, p_blockHash)))
        return Read(std::make_pair(BLOCK_ZELNODE_UNDO_DATA, p_blockHash), p_undoData);

    // If it doesn't exist, we just return true because we don't want to fail just because it didn't exist in the db
    return true;
}