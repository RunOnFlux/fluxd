// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// Tests for FluxnodeCache persistence: a forced PersistToDisk must write the
// sync-state marker even when the cache has nothing dirty. Crash recovery
// repairs a stale marker via PersistToDisk(tip, true) while the cache is
// still clean at init — if the forced write silently skipped, the stale
// marker would survive and the node would re-enter recovery on every
// restart.

#include <gtest/gtest.h>

#include "chain.h"
#include "chainparams.h"
#include "fluxnode/fluxnode.h"
#include "fluxnode/fluxnodecachedb.h"
#include "main.h"
#include "uint256.h"
#include "undo.h"

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

// CleanupOldFluxnodeData can prune an undo record by height; afterwards
// ReadBlockUndoFluxnodeData reads back an EMPTY record with success (correct for
// the live disconnect path, where an absent record means the block changed no
// fluxnode state). Crash recovery cannot tolerate that ambiguity — a pruned
// record would make it silently under-rewind — so it probes existence instead,
// which must report a missing record as absent rather than empty-but-present.
TEST(FluxnodeCacheDB, ExistsBlockUndoDistinguishesAbsentFromEmpty)
{
    SelectParams(CBaseChainParams::REGTEST);
    CDeterministicFluxnodeDB* pOldDB = pFluxnodeDB;
    pFluxnodeDB = new CDeterministicFluxnodeDB(1 << 20, true /*fMemory*/, true /*fWipe*/);

    uint256 absent = uint256S("cd");
    uint256 present = uint256S("ab");

    // Absent record: the read still succeeds (empty), so existence is what
    // recovery must rely on to detect a pruned record.
    CFluxnodeTxBlockUndo undo;
    EXPECT_TRUE(pFluxnodeDB->ReadBlockUndoFluxnodeData(absent, undo));
    EXPECT_FALSE(pFluxnodeDB->ExistsBlockUndoFluxnodeData(absent));

    // A written record is reported present.
    CFluxnodeTxBlockUndo toWrite;
    ASSERT_TRUE(pFluxnodeDB->WriteBlockUndoFluxnodeData(present, toWrite));
    EXPECT_TRUE(pFluxnodeDB->ExistsBlockUndoFluxnodeData(present));

    delete pFluxnodeDB;
    pFluxnodeDB = pOldDB;
}

// A confirmed record's ip is a bare host or host:port. CountNetworks counts each
// record under its host's network either way, and a record whose host does not
// parse under none.
TEST(FluxnodeCacheCount, CountNetworksReadsHostWithAndWithoutPort)
{
    SelectParams(CBaseChainParams::REGTEST);
    FluxnodeCache cache;

    const std::vector<std::string> vIps = {
        "1.2.3.4",
        "1.2.3.4:16137",
        "5.6.7.8:16127",
        "2606:4700:4700::1111",
        "[2606:4700:4700::1111]:16137",
        "not an address",
        "not-an-address:16137",
    };
    for (size_t i = 0; i < vIps.size(); i++) {
        FluxnodeCacheData data;
        data.ip = vIps[i];
        cache.mapConfirmedFluxnodeData[COutPoint(uint256S("cc"), static_cast<uint32_t>(i))] = data;
    }

    int ipv4 = 0, ipv6 = 0, onion = 0;
    std::vector<int> vNodeCount(GetNumberOfTiers());
    cache.CountNetworks(ipv4, ipv6, onion, vNodeCount);

    EXPECT_EQ(ipv4, 3);
    EXPECT_EQ(ipv6, 2);
    EXPECT_EQ(onion, 0);
}
