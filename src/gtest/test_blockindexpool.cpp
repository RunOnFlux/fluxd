// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// Tests for the fluxnode block-index memory work:
//  - CBlockIndexPool (the segmented, file-backed arena, blockindex.arena) incl. the
//    exhaustion -> nullptr path that triggers the heap fallback, and the
//    Initialize-failure path (unsupported dir) that also falls back to heap.
//  - The CBlockIndex HeaderData split: pruning frees only the rebuildable
//    block-file fields and MUST keep the resident consensus state
//    (nCachedBranchId, value pools, sprout anchors) — the regression that
//    caused the RewindBlockIndex crash-loop.
//  - CDiskBlockIndex serialization round-trip — guards the "no on-disk-format
//    change / no reindex" property after the field moves.

#include <gtest/gtest.h>

#include "chain.h"
#include "blockindexpool.h"
#include "chainparams.h"
#include "clientversion.h"
#include "main.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "streams.h"
#include "uint256.h"
#include "util.h"

#include <filesystem>
#include <optional>

#include <unistd.h>

// The entry's header as held in memory, whole or not.
static CBlockHeader InMemoryHeader(const CBlockIndex& index) {
    CBlockHeader header;
    (void)index.ResidentHeader(header);
    return header;
}

namespace {

CBlockHeader MakePopulatedHeader()
{
    CBlockHeader h;
    h.nVersion = CBlockHeader::PON_VERSION;          // exercise PON collateral/sig fields
    h.hashPrevBlock = uint256S("11");
    h.hashMerkleRoot = uint256S("22");
    h.hashFinalSaplingRoot = uint256S("33");
    h.nTime = 1700000000;
    h.nBits = 0x1d00ffff;
    h.nNonce = uint256S("44");
    h.nSolution = std::vector<unsigned char>{1, 2, 3, 4, 5};
    h.nodesCollateral = COutPoint(uint256S("55"), 7);
    h.vchBlockSig = std::vector<unsigned char>{9, 8, 7, 6};
    return h;
}

} // namespace

// ---- arena -----------------------------------------------------------------

TEST(BlockIndexPool, AllocateAcrossChunksContainsDestroy)
{
    CBlockIndexPool pool;
    // Tiny chunk (2 entries) so a handful of allocations spans several chunks.
    ASSERT_TRUE(pool.Initialize(sizeof(CBlockIndex), sizeof(uint256), 2, "/tmp"));
    EXPECT_EQ(pool.Capacity(), (size_t)2);    // first chunk mapped at init
    EXPECT_EQ(pool.Size(), (size_t)0);

    std::vector<void*> ptrs;
    for (int i = 0; i < 5; i++) {
        void* p = pool.AllocateEntry();       // segmented: adds a chunk when full
        ASSERT_NE(p, nullptr);
        ptrs.push_back(p);
    }
    EXPECT_EQ(pool.Size(), (size_t)5);
    EXPECT_EQ(pool.Capacity(), (size_t)6);    // grew to 3 chunks of 2

    // Every handed-out pointer (across all chunks) is recognized; hashes too.
    for (int i = 0; i < 5; i++) {
        EXPECT_TRUE(pool.Contains(ptrs[i]));
        EXPECT_NE(pool.HashAt(i), nullptr);
    }
    int onStack = 0;
    EXPECT_FALSE(pool.Contains(&onStack));
    EXPECT_FALSE(pool.Contains(nullptr));

    pool.DestroyAll([](void*) {});            // no objects constructed; just reset
    EXPECT_EQ(pool.Size(), (size_t)0);
}

TEST(BlockIndexPool, InitializeFailsGracefullyOnBadDir)
{
    CBlockIndexPool pool;
    // Creating the backing file in a nonexistent directory fails -> Initialize
    // returns false -> caller uses plain heap allocation (master behavior).
    EXPECT_FALSE(pool.Initialize(sizeof(CBlockIndex), sizeof(uint256), 4,
                                 "/nonexistent/flux/arena/path"));
}

// ---- HeaderData split / pruning --------------------------------------------

TEST(BlockIndex, PruneFreesBlockFileDataKeepsResidentState)
{
    CBlockHeader h = MakePopulatedHeader();
    CBlockIndex idx(h);

    // Resident consensus/index state (NOT in the prunable HeaderData).
    idx.nCachedBranchId = (uint32_t)0x76b809bb;
    idx.hashSproutAnchor = uint256S("aa");
    idx.hashFinalSproutRoot = uint256S("bb");
    idx.nSproutValue = 111;
    idx.nChainSproutValue = 222;
    idx.nSaplingValue = 333;
    idx.nChainSaplingValue = 444;
    idx.hashPON = uint256S("cc");

    ASSERT_TRUE(idx.HasHeaderData());
    EXPECT_EQ(InMemoryHeader(idx).hashMerkleRoot, h.hashMerkleRoot);

    // Simulate the load-time prune.
    idx.FreeHeaderData();
    EXPECT_FALSE(idx.HasHeaderData());

    // The resident state MUST survive the prune. (If nCachedBranchId did not,
    // RewindBlockIndex would treat every block as unvalidated and trigger a
    // full-chain rewind/abort — the crash-loop this regression-tests.)
    EXPECT_EQ(idx.nCachedBranchId, std::optional<uint32_t>(0x76b809bb));
    EXPECT_EQ(idx.hashSproutAnchor, uint256S("aa"));
    EXPECT_EQ(idx.hashFinalSproutRoot, uint256S("bb"));
    EXPECT_EQ(idx.nSproutValue, std::optional<CAmount>(111));
    EXPECT_EQ(idx.nChainSproutValue, std::optional<CAmount>(222));
    EXPECT_EQ(idx.nSaplingValue, (CAmount)333);
    EXPECT_EQ(idx.nChainSaplingValue, std::optional<CAmount>(444));
    // The cached PON hash is the fork-choice comparator key for PON entries;
    // if it did not survive the prune, equal-work ties on a restarted
    // fluxnode would hash zeroed headers and resolve against the network.
    EXPECT_EQ(idx.hashPON, uint256S("cc"));
}

TEST(BlockIndex, ResidentHeaderNotWholeAfterPrune)
{
    CBlockHeader h = MakePopulatedHeader();
    CBlockIndex idx(h);

    CBlockHeader before = InMemoryHeader(idx);
    EXPECT_EQ(before.hashMerkleRoot, h.hashMerkleRoot);
    EXPECT_EQ(before.nNonce, h.nNonce);
    EXPECT_EQ(before.nSolution, h.nSolution);

    CBlockHeader whole;
    EXPECT_TRUE(idx.ResidentHeader(whole));

    idx.FreeHeaderData();
    CBlockHeader after;
    EXPECT_FALSE(idx.ResidentHeader(after));

    // Once pruned the block-file fields read empty and the entry says its header is not
    // whole: a caller serving headers takes the block file's (GetFullBlockHeader).
    EXPECT_TRUE(after.nSolution.empty());
    EXPECT_EQ(after.hashMerkleRoot, uint256());
    // Always-resident header scalars remain correct.
    EXPECT_EQ(after.nVersion, h.nVersion);
    EXPECT_EQ(after.nTime, h.nTime);
    EXPECT_EQ(after.nBits, h.nBits);
}

TEST(BlockIndex, CopyDeepCopiesHeaderDataAndResidentFields)
{
    CBlockHeader h = MakePopulatedHeader();
    CBlockIndex a(h);
    a.nCachedBranchId = (uint32_t)0x12345678;
    a.nSproutValue = 999;

    CBlockIndex b(a);                    // copy ctor (deep-copies pHeaderData)
    ASSERT_TRUE(b.HasHeaderData());
    EXPECT_NE(b.pHeaderData, a.pHeaderData);             // independent allocation
    EXPECT_EQ(b.pHeaderData->nNonce, a.pHeaderData->nNonce);
    EXPECT_EQ(b.nCachedBranchId, std::optional<uint32_t>(0x12345678));
    EXPECT_EQ(b.nSproutValue, std::optional<CAmount>(999));

    a.FreeHeaderData();                  // mutating a must not affect b
    EXPECT_TRUE(b.HasHeaderData());
    EXPECT_EQ(InMemoryHeader(b).hashMerkleRoot, h.hashMerkleRoot);
}

TEST(BlockIndex, RestoreHeaderDataAfterPruneSerializesIdentically)
{
    // A pruned-then-restored entry must produce a byte-identical
    // CDiskBlockIndex record to one that was never pruned: the flush path
    // restores dirty-but-pruned entries from disk before serialization, and
    // any divergence here would overwrite a good leveldb record with wrong
    // header fields.
    CBlockHeader h = MakePopulatedHeader();
    h.hashPrevBlock = uint256();
    CBlockIndex idx(h);
    idx.nHeight  = 1234;
    idx.nStatus  = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    idx.nFile    = 1;
    idx.nDataPos = 77;
    uint256 blockHash = h.GetHash();
    idx.phashBlock = &blockHash;

    CDataStream ssBefore(SER_DISK, CLIENT_VERSION);
    ssBefore << CDiskBlockIndex(&idx);

    idx.FreeHeaderData();                 // the buried-entry prune
    ASSERT_FALSE(idx.HasHeaderData());
    idx.RestoreHeaderData(h);             // flush-side restore from disk read
    ASSERT_TRUE(idx.HasHeaderData());

    CDataStream ssAfter(SER_DISK, CLIENT_VERSION);
    ssAfter << CDiskBlockIndex(&idx);

    EXPECT_EQ(std::vector<unsigned char>(ssBefore.begin(), ssBefore.end()),
              std::vector<unsigned char>(ssAfter.begin(), ssAfter.end()));
}

// ---- on-disk format (no reindex) -------------------------------------------

TEST(BlockIndex, DiskBlockIndexSerializationRoundTrip)
{
    CBlockHeader h = MakePopulatedHeader();
    // No predecessor in this fixture (idx.pprev stays null), and CBlockIndex
    // carries the prev via pprev rather than storing hashPrevBlock — so keep
    // the header's prev null to match, otherwise the reconstructed hash differs.
    h.hashPrevBlock = uint256();
    CBlockIndex idx(h);
    idx.nHeight   = 2654321;
    idx.nFile     = 4;
    idx.nDataPos  = 1234;
    idx.nUndoPos  = 5678;
    idx.nTx       = 9;
    idx.nStatus   = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO |
                    BLOCK_ACTIVATES_UPGRADE;   // forces nCachedBranchId to serialize
    idx.nCachedBranchId = (uint32_t)0x76b809bb;
    idx.hashSproutAnchor = uint256S("aa");
    idx.nSproutValue  = 111;               // serialized when client ver >= SPROUT_VALUE_VERSION
    idx.nSaplingValue = 333;

    // CBlockIndex::GetBlockHash() returns *phashBlock; real code points this at
    // the arena hash array / map key. Give the hand-built index a valid hash so
    // the CDiskBlockIndex ctor (which reads pindex->GetBlockHash()) is safe.
    uint256 blockHash = h.GetHash();
    idx.phashBlock = &blockHash;

    CDiskBlockIndex disk(&idx);
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << disk;

    CDiskBlockIndex disk2;
    ss >> disk2;

    // Skeleton / resident fields
    EXPECT_EQ(disk2.nHeight, idx.nHeight);
    EXPECT_EQ(disk2.nStatus, idx.nStatus);
    EXPECT_EQ(disk2.nFile, idx.nFile);
    EXPECT_EQ(disk2.nDataPos, idx.nDataPos);
    EXPECT_EQ(disk2.nUndoPos, idx.nUndoPos);
    EXPECT_EQ(disk2.nTx, idx.nTx);
    EXPECT_EQ(disk2.nCachedBranchId, std::optional<uint32_t>(0x76b809bb));
    EXPECT_EQ(disk2.hashSproutAnchor, uint256S("aa"));
    EXPECT_EQ(disk2.nSproutValue, std::optional<CAmount>(111));
    EXPECT_EQ(disk2.nSaplingValue, (CAmount)333);

    // Prunable block-file fields (deserialized into a fresh HeaderData)
    ASSERT_TRUE(disk2.HasHeaderData());
    EXPECT_EQ(disk2.pHeaderData->hashMerkleRoot, h.hashMerkleRoot);
    EXPECT_EQ(disk2.pHeaderData->hashFinalSaplingRoot, h.hashFinalSaplingRoot);
    EXPECT_EQ(disk2.pHeaderData->nNonce, h.nNonce);
    EXPECT_EQ(disk2.pHeaderData->nSolution, h.nSolution);
    EXPECT_EQ(disk2.pHeaderData->nodesCollateral, h.nodesCollateral);
    EXPECT_EQ(disk2.pHeaderData->vchBlockSig, h.vchBlockSig);

    // The hash reconstructed from the round-tripped header matches the original.
    EXPECT_EQ(disk2.GetBlockHash(), h.GetHash());
}

// ShouldFreeAgedHeaderData is the decision behind the runtime HeaderData prune
// (PruneAgedHeaderData): once a connected block ages past the window, free its
// rebuildable header data. The guards matter — a header-only entry (no block on
// disk) cannot be rebuilt and must NOT be pruned, and only fluxnodes prune.
TEST(BlockIndex, RuntimeHeaderDataPruneDecision)
{
    const int W = 1000;
    // At/past the window, fluxnode, block data on disk, header data resident -> free it.
    EXPECT_TRUE(ShouldFreeAgedHeaderData(/*fluxnode=*/true, /*belowTip=*/W, W, /*hasBlockData=*/true, /*hasHeaderData=*/true));
    EXPECT_TRUE(ShouldFreeAgedHeaderData(true, W + 500, W, true, true));

    // Inside the window -> keep (boundary / off-by-one guard).
    EXPECT_FALSE(ShouldFreeAgedHeaderData(true, W - 1, W, true, true));

    // Non-fluxnode -> never prune (master behaviour).
    EXPECT_FALSE(ShouldFreeAgedHeaderData(false, W, W, true, true));

    // Header-only entry (no block data on disk) -> must stay resident; it cannot
    // be rebuilt from disk. This is the essential guard.
    EXPECT_FALSE(ShouldFreeAgedHeaderData(true, W, W, /*hasBlockData=*/false, true));

    // Already pruned (no resident header data) -> nothing to free.
    EXPECT_FALSE(ShouldFreeAgedHeaderData(true, W, W, true, /*hasHeaderData=*/false));
}

// A tip is announced with its whole header whether or not its entry still holds header
// data. A fluxnode frees an entry's header data when the entry leaves the active chain,
// and the entry then says its header is not whole; the announcement takes the block in
// hand, else the block file's header, else announces no header.
TEST(BlockIndex, AnnouncementHeaderIsWholeAfterHeaderDataIsFreed)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus();

    const std::filesystem::path dir = std::filesystem::temp_directory_path() /
        strprintf("flux-gtest-announce-%d", (int)getpid());
    std::filesystem::create_directories(dir);
    mapArgs["-datadir"] = dir.string();
    ClearDatadirCache();

    CBlock block;
    static_cast<CBlockHeader&>(block) = MakePopulatedHeader();
    const uint256 hash = block.GetHash();

    // A block on disk whose entry has lost its header data, as a block just taken off
    // the active chain has.
    CBlockIndex entry(block.GetBlockHeader());
    entry.phashBlock = &hash;
    CDiskBlockPos pos(0, 0);
    ASSERT_TRUE(WriteBlockToDisk(block, pos, Params().MessageStart()));
    entry.nFile = pos.nFile;
    entry.nDataPos = pos.nPos;
    entry.nStatus |= BLOCK_HAVE_DATA;
    entry.FreeHeaderData();

    CBlockHeader resident;
    EXPECT_FALSE(entry.ResidentHeader(resident));
    EXPECT_TRUE(resident.nodesCollateral.IsNull());
    EXPECT_TRUE(resident.vchBlockSig.empty());

    const auto expectWhole = [&](const CBlockHeader& header) {
        EXPECT_EQ(header.GetHash(), hash);
        EXPECT_EQ(header.nodesCollateral, block.nodesCollateral);
        EXPECT_EQ(header.vchBlockSig, block.vchBlockSig);
    };

    CBlockHeader fromBlock;
    ASSERT_TRUE(GetAnnouncementHeader(fromBlock, &entry, &block, params));
    expectWhole(fromBlock);

    CBlockHeader fromDisk;
    ASSERT_TRUE(GetAnnouncementHeader(fromDisk, &entry, nullptr, params));
    expectWhole(fromDisk);

    // An entry with header data in memory needs neither.
    CBlockIndex live(block.GetBlockHeader());
    live.phashBlock = &hash;
    CBlockHeader fromMemory;
    ASSERT_TRUE(GetAnnouncementHeader(fromMemory, &live, nullptr, params));
    EXPECT_EQ(fromMemory.nodesCollateral, block.nodesCollateral);
    EXPECT_EQ(fromMemory.vchBlockSig, block.vchBlockSig);

    // No header data and no block to read: no header is announced.
    live.FreeHeaderData();
    CBlockHeader none;
    EXPECT_FALSE(GetAnnouncementHeader(none, &live, nullptr, params));

    mapArgs.erase("-datadir");
    ClearDatadirCache();
    std::filesystem::remove_all(dir);
}
