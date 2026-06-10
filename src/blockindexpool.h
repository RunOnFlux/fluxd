// Copyright (c) 2018-2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKINDEXPOOL_H
#define BITCOIN_BLOCKINDEXPOOL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <sys/mman.h>
#include <unistd.h>

class CBlockIndex;
class uint256;

/**
 * Pool allocator for CBlockIndex objects, backed by a single growable scratch
 * file on the datadir's filesystem (blockindex.arena). Each slot holds a
 * CBlockIndex immediately followed by its 32-byte block hash, so one file
 * carries both (the hash shares a page with its index — hot/cold together).
 * Benefit over individual heap allocation:
 *
 * - Cold (old-block) pages evict to the backing file, not to swap, so a node
 *   with little RAM (and no swap) keeps resident memory bounded to the working
 *   set; disk used grows only with the amount actually written.
 *
 * Storage is *segmented*: the file is grown in fixed-size steps (ftruncate)
 * and mapped as a series of fixed mmap windows at increasing offsets. A new
 * window is mapped on demand when the current one fills, so:
 *
 * - There is no fixed up-front reservation and no hard ceiling: file size and
 *   virtual size track actual chain size, growing one chunk at a time.
 * - Existing windows are never moved or remapped, so the millions of raw
 *   CBlockIndex* pointers into them (pprev/pskip/mapBlockIndex/chainActive)
 *   stay valid forever.
 *
 * The file is scratch — the in-memory index is always rebuilt from the leveldb
 * block index at startup. Cleanup: opened O_TRUNC at startup (discarding any
 * content left by a previous crash) and unlinked on clean shutdown. If it
 * can't be created/grown/mapped (unsupported FS, disk full), the call fails
 * and the caller falls back to heap allocation — no abort.
 */
class CBlockIndexPool {
private:
    std::vector<void*> chunks; // mmap windows, each nSlotSize*nEntriesPerChunk bytes
    size_t nEntrySize;         // sizeof(CBlockIndex)
    size_t nHashSize;          // sizeof(uint256)
    size_t nSlotSize;          // nEntrySize + nHashSize (8-aligned)
    size_t nEntriesPerChunk;
    size_t nAllocated;         // total live entries across all chunks
    size_t nChunkBytes;        // page-aligned per-chunk byte size
    std::string arenaPath;
    int arenaFd;

    bool AddChunk();           // grow file + map one more window; false on failure

    CBlockIndexPool(const CBlockIndexPool&) = delete;
    CBlockIndexPool& operator=(const CBlockIndexPool&) = delete;

public:
    CBlockIndexPool();
    ~CBlockIndexPool();

    // Set up the segmented arena: each chunk holds `entriesPerChunk` slots
    // (a CBlockIndex + its hash), backed by blockindex.arena under `backingDir`
    // (opened O_TRUNC). Maps the first chunk; returns false on any failure
    // (caller falls back to heap allocation).
    bool Initialize(size_t entrySize, size_t hashSize, size_t entriesPerChunk,
                    const std::string& backingDir);

    // Allocate the next CBlockIndex slot (adding a chunk if needed). Returns
    // raw memory to placement-new into, or nullptr if a needed chunk could not
    // be mapped (caller then uses heap allocation for this entry).
    void* AllocateEntry();

    // Get the hash storage for the entry at the given global index.
    void* HashAt(size_t index);

    // Check if a pointer falls within any chunk's entry region.
    bool Contains(const void* p) const;

    size_t Size() const { return nAllocated; }
    size_t Capacity() const { return chunks.size() * nEntriesPerChunk; }

    // Tell the OS that pages for old entries are cold. Call after chain
    // is fully loaded and activated.
    void AdviseOldBlocksCold(size_t nKeepRecent);

    // Destruct all allocated entries (caller passes destructor function)
    void DestroyAll(void (*destructor)(void*));
};

#endif // BITCOIN_BLOCKINDEXPOOL_H
