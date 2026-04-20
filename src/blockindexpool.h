// Copyright (c) 2018-2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKINDEXPOOL_H
#define BITCOIN_BLOCKINDEXPOOL_H

#include <cstddef>
#include <cstdint>

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
 * Uses MAP_NORESERVE so virtual address space is reserved upfront but
 * physical pages are only allocated on first touch (demand paging).
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

    bool Initialize(size_t entrySize, size_t hashSize, size_t capacity);

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
