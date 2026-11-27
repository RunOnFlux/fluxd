// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

//
// Created by ja on 11/14/19.
//

#ifndef ZELCASH_FLUXNODECACHEDB_H
#define ZELCASH_FLUXNODECACHEDB_H

#include "dbwrapper.h"
#include "serialize.h"
#include "uint256.h"
#include <filesystem>

class FluxnodeCacheData;
class COutPoint;
class CFluxnodeTxBlockUndo;
class CFluxnodeDelegates;

// Fluxnode undo records are retained for this many blocks below the active tip;
// CleanupOldFluxnodeData prunes anything older. Recovery relies on it both to
// bound how far it rewinds and to tell a pruned record from a legitimately
// empty one. ~720 blocks/day * 7 days.
static const int ONE_WEEK_OF_BLOCK_COUNT = 5040;

struct FluxnodeSyncState {
    uint256 bestBlockHash;
    int nHeight;

    FluxnodeSyncState() : nHeight(0) {}
    FluxnodeSyncState(const uint256& hash, int height) : bestBlockHash(hash), nHeight(height) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(bestBlockHash);
        READWRITE(nHeight);
    }
};

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
    bool ExistsBlockUndoFluxnodeData(const uint256& p_blockHash);

    bool WriteFluxnodeDelegates(const COutPoint& outpoint, const CFluxnodeDelegates& delegates);
    bool ReadFluxnodeDelegates(const COutPoint& outpoint, CFluxnodeDelegates& delegates);
    bool EraseFluxnodeDelegate(const COutPoint& outpoint);
    bool FluxnodeDelegateExists(const COutPoint& outpoint);

    bool CleanupOldFluxnodeData();

    // Batch write support
    void WriteBatchFluxnodeData(CDBBatch& batch, const FluxnodeCacheData& data);
    void EraseBatchFluxnodeData(CDBBatch& batch, const COutPoint& outpoint);
    void WriteBatchDelegates(CDBBatch& batch, const COutPoint& outpoint, const CFluxnodeDelegates& delegates);
    void EraseBatchDelegates(CDBBatch& batch, const COutPoint& outpoint);
    void WriteBatchSyncState(CDBBatch& batch, const FluxnodeSyncState& syncState);

    bool ReadSyncState(FluxnodeSyncState& syncState);
};

#endif //ZELCASH_FLUXNODECACHEDB_H
