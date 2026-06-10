// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// Tests for the fluxnode block-index memory work:
//  - CBlockIndexPool (the sparse, O_TMPFILE-backed arena) incl. the
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
#include "clientversion.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "streams.h"
#include "uint256.h"

#include <optional>

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

TEST(BlockIndexPool, AllocateContainsExhaustDestroy)
{
    CBlockIndexPool pool;
    // Tiny capacity so we can hit exhaustion deterministically.
    ASSERT_TRUE(pool.Initialize(sizeof(CBlockIndex), sizeof(uint256), 3, "/tmp"));
    EXPECT_EQ(pool.Capacity(), (size_t)3);
    EXPECT_EQ(pool.Size(), (size_t)0);

    void* a = pool.AllocateEntry();
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(pool.Size(), (size_t)1);
    EXPECT_TRUE(pool.Contains(a));
    EXPECT_NE(pool.HashAt(0), nullptr);

    int onStack = 0;
    EXPECT_FALSE(pool.Contains(&onStack));   // heap/stack pointers are not "in" the pool
    EXPECT_FALSE(pool.Contains(nullptr));

    ASSERT_NE(pool.AllocateEntry(), nullptr);
    ASSERT_NE(pool.AllocateEntry(), nullptr);
    EXPECT_EQ(pool.Size(), (size_t)3);

    // Exhausted: returns nullptr, which is what makes InsertBlockIndex fall
    // back to heap allocation instead of aborting.
    EXPECT_EQ(pool.AllocateEntry(), nullptr);

    pool.DestroyAll([](void*) {});           // no objects constructed; just reset
    EXPECT_EQ(pool.Size(), (size_t)0);
}

TEST(BlockIndexPool, InitializeFailsGracefullyOnBadDir)
{
    CBlockIndexPool pool;
    // O_TMPFILE on a nonexistent directory fails -> Initialize returns false
    // -> caller uses plain heap allocation (master behavior).
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

    ASSERT_TRUE(idx.HasHeaderData());
    EXPECT_EQ(idx.GetBlockHeader().hashMerkleRoot, h.hashMerkleRoot);

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
}

TEST(BlockIndex, GetBlockHeaderZeroedAfterPrune)
{
    CBlockHeader h = MakePopulatedHeader();
    CBlockIndex idx(h);

    CBlockHeader before = idx.GetBlockHeader();
    EXPECT_EQ(before.hashMerkleRoot, h.hashMerkleRoot);
    EXPECT_EQ(before.nNonce, h.nNonce);
    EXPECT_EQ(before.nSolution, h.nSolution);

    idx.FreeHeaderData();
    CBlockHeader after = idx.GetBlockHeader();

    // Contract: once pruned, GetBlockHeader returns zeroed block-file fields —
    // callers serving headers must rehydrate from disk (GetFullBlockHeader).
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
    EXPECT_EQ(b.GetBlockHeader().hashMerkleRoot, h.hashMerkleRoot);
}

// ---- on-disk format (no reindex) -------------------------------------------

TEST(BlockIndex, DiskBlockIndexSerializationRoundTrip)
{
    CBlockHeader h = MakePopulatedHeader();
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

    // The reconstructed block hash must match the original block.
    EXPECT_EQ(disk2.GetBlockHash(), idx.GetBlockHash());
}
