// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// Tests for FluxnodeCache persistence. M7 regression: a forced PersistToDisk
// must write the sync-state marker even when the cache has nothing dirty —
// recovery repairs a stale marker via PersistToDisk(tip, true), which
// previously no-op'd (dirty sets are empty at init), so the node re-entered
// recovery on every restart.

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparams.h"
#include "fluxnode/fluxnode.h"
#include "fluxnode/fluxnodecachedb.h"
#include "main.h"
#include "uint256.h"

TEST(FluxnodeCacheDB, ForcedPersistWritesMarkerWhenClean)
{
    SelectParams(CBaseChainParams::REGTEST);
    CDeterministicFluxnodeDB* pOldDB = pFluxnodeDB;
    pFluxnodeDB = new CDeterministicFluxnodeDB(1 << 20, true /*fMemory*/, true /*fWipe*/);

    uint256 hash = uint256S("ab");
    CBlockIndex tip;
    tip.phashBlock = &hash;
    tip.nHeight = 4242;

    FluxnodeCache cache;

    // Unforced persist with a clean cache stays a no-op: no marker appears.
    cache.PersistToDisk(&tip, false);
    FluxnodeSyncState syncState;
    EXPECT_FALSE(pFluxnodeDB->ReadSyncState(syncState));

    // Forced persist writes the marker even though nothing is dirty.
    cache.PersistToDisk(&tip, true);
    ASSERT_TRUE(pFluxnodeDB->ReadSyncState(syncState));
    EXPECT_EQ(syncState.nHeight, 4242);
    EXPECT_EQ(syncState.bestBlockHash, hash);

    delete pFluxnodeDB;
    pFluxnodeDB = pOldDB;
}
