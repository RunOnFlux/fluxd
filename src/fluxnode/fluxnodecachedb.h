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
#include <boost/filesystem/path.hpp>

class FluxnodeCacheData;
class COutPoint;
class CFluxnodeTxBlockUndo;
class CFluxnodeDelegates;

/** Tracks the block height/hash that the fluxnode cache was last synced to.
 *  Used to detect inconsistency between coins DB and fluxnode DB after crashes.
 */
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

    bool WriteFluxnodeDelegates(const COutPoint& outpoint, const CFluxnodeDelegates& delegates);
    bool ReadFluxnodeDelegates(const COutPoint& outpoint, CFluxnodeDelegates& delegates);
    bool EraseFluxnodeDelegate(const COutPoint& outpoint);
    bool FluxnodeDelegateExists(const COutPoint& outpoint);

    bool CleanupOldFluxnodeData();

    // Sync state methods for crash recovery detection
    bool WriteSyncState(const FluxnodeSyncState& syncState);
    bool ReadSyncState(FluxnodeSyncState& syncState);

    // Batch write support for atomic operations
    void WriteBatchFluxnodeData(CDBBatch& batch, const FluxnodeCacheData& data);
    void EraseBatchFluxnodeData(CDBBatch& batch, const COutPoint& outpoint);
    void WriteBatchDelegates(CDBBatch& batch, const COutPoint& outpoint, const CFluxnodeDelegates& delegates);
    void EraseBatchDelegates(CDBBatch& batch, const COutPoint& outpoint);
    void WriteBatchSyncState(CDBBatch& batch, const FluxnodeSyncState& syncState);
};

#endif //ZELCASH_FLUXNODECACHEDB_H
