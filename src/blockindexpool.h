// Copyright (c) 2018-2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKINDEXPOOL_H
#define BITCOIN_BLOCKINDEXPOOL_H

#include <cstddef>
#include <cstdint>
#include <string>

#include <sys/mman.h>
#include <unistd.h>

class CBlockIndex;
class uint256;

/**
 * Pool allocator for CBlockIndex objects backed by anonymous mmap.
 *
 * All CBlockIndex objects and their associated hashes are allocated from
 * contiguous mmap regions. Benefits over individual heap allocation:
 *
 * - Zero per-element malloc overhead (~40 bytes saved per entry)
 * - Contiguous layout: old blocks cluster at low addresses, recent at high
 * - The OS can page out cold (old block) pages under memory pressure
 * - MADV_COLD hint proactively tells the kernel which pages are cold
 * - No heap fragmentation from 2.5M+ allocations
 *
 * The arena is backed by sparse, nameless disk inodes (O_TMPFILE + MAP_SHARED)
 * on the datadir's filesystem rather than anonymous memory. Consequences:
 *
 * - The capacity reservation is a sparse ftruncate: it costs no disk and no
 *   RAM until pages are actually touched, so we reserve far more than the
 *   chain will need in our lifetime and never hit a hard ceiling.
 * - Cold pages are evicted to the backing inode, not to swap. A node with
 *   little RAM (and no swap) keeps resident memory bounded to the working
 *   set; disk used grows only with the amount actually evicted.
 * - The inodes have no directory entry (O_TMPFILE), so they are invisible to
 *   ls/du/backup tooling and the kernel reclaims their disk blocks
 *   automatically when the process exits, clean or crashed. Nothing to clean
 *   up, nothing to exclude from backups. Durability is irrelevant: the bytes
 *   hold process-lifetime pointers and are never reused across runs.
 *
 * If O_TMPFILE is unsupported (old kernel/exotic FS), Initialize() returns
 * false and the caller falls back to plain heap allocation.
 */
class CBlockIndexPool {
private:
    void* pPoolMem;
    void* pHashMem;
    size_t nEntrySize;
    size_t nHashSize;
    size_t nCapacity;
    size_t nAllocated;

    CBlockIndexPool(const CBlockIndexPool&) = delete;
    CBlockIndexPool& operator=(const CBlockIndexPool&) = delete;

public:
    CBlockIndexPool();
    ~CBlockIndexPool();

    // Reserve a sparse file-backed arena for `capacity` entries under
    // `backingDir` (typically the datadir). Returns false on any failure;
    // the caller must then fall back to heap allocation.
    bool Initialize(size_t entrySize, size_t hashSize, size_t capacity,
                    const std::string& backingDir);

    // Allocate the next CBlockIndex slot. Returns raw memory; caller
    // must placement-new the CBlockIndex.
    void* AllocateEntry();

    // Get the hash storage for entry at the given index.
    void* HashAt(size_t index);

    // Check if a pointer falls within the pool
    bool Contains(const void* p) const;

    size_t Size() const { return nAllocated; }
    size_t Capacity() const { return nCapacity; }

    // Tell the OS that pages for old entries are cold. Call after chain
    // is fully loaded and activated.
    void AdviseOldBlocksCold(size_t nKeepRecent);

    // Destruct all allocated entries (caller passes destructor function)
    void DestroyAll(void (*destructor)(void*));
};

#endif // BITCOIN_BLOCKINDEXPOOL_H
