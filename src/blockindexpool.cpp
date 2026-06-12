// Copyright (c) 2018-2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "blockindexpool.h"

#ifdef WIN32

// The arena is built on POSIX mmap/ftruncate, which Windows lacks. On Windows
// the pool is inert: Initialize() reports failure, so every caller takes its
// heap-fallback path and the node behaves like a stock build. (The pool is
// only ever engaged on fluxnodes, which are Linux.)

CBlockIndexPool::CBlockIndexPool()
    : nEntrySize(0), nHashSize(0), nSlotSize(0), nEntriesPerChunk(0),
      nAllocated(0), nChunkBytes(0), arenaFd(-1)
{
}

CBlockIndexPool::~CBlockIndexPool() = default;

bool CBlockIndexPool::AddChunk() { return false; }

bool CBlockIndexPool::Initialize(size_t, size_t, size_t, const std::string&) { return false; }

void* CBlockIndexPool::AllocateEntry() { return nullptr; }

void* CBlockIndexPool::HashAt(size_t) { return nullptr; }

bool CBlockIndexPool::Contains(const void*) const { return false; }

void CBlockIndexPool::AdviseOldBlocksCold(size_t) {}

void CBlockIndexPool::DestroyAll(void (*)(void*)) {}

#else

#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MADV_COLD
#define MADV_COLD 20
#endif

namespace {
size_t PageAlignUp(size_t n)
{
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    size_t p = (size_t)ps;
    return ((n + p - 1) / p) * p;
}
} // namespace

CBlockIndexPool::CBlockIndexPool()
    : nEntrySize(0), nHashSize(0), nSlotSize(0), nEntriesPerChunk(0),
      nAllocated(0), nChunkBytes(0), arenaFd(-1)
{
}

CBlockIndexPool::~CBlockIndexPool()
{
    for (void* w : chunks)
        if (w) munmap(w, nChunkBytes);
    chunks.clear();
    if (arenaFd >= 0) close(arenaFd);
    // Scratch file: drop it on clean shutdown. (A crash leaves it; the next
    // startup opens O_TRUNC, discarding the stale content.)
    if (!arenaPath.empty()) unlink(arenaPath.c_str());
}

bool CBlockIndexPool::AddChunk()
{
    const size_t n = chunks.size();
    // Grow the file to cover the new window, then map it at its offset.
    // ftruncate only extends the logical size (sparse); blocks are allocated
    // lazily as pages are written.
    if (ftruncate(arenaFd, (off_t)((n + 1) * nChunkBytes)) != 0)
        return false;
    void* w = mmap(nullptr, nChunkBytes, PROT_READ | PROT_WRITE,
                   MAP_SHARED, arenaFd, (off_t)(n * nChunkBytes));
    if (w == MAP_FAILED)
        return false;
    chunks.push_back(w);
    return true;
}

bool CBlockIndexPool::Initialize(size_t entrySize, size_t hashSize,
                                 size_t entriesPerChunk, const std::string& backingDir)
{
    nEntrySize = entrySize;
    nHashSize = hashSize;
    // Each slot is a CBlockIndex followed by its hash. Round the slot up to
    // 8 bytes so successive CBlockIndex objects stay aligned.
    nSlotSize = ((entrySize + hashSize + 7) / 8) * 8;
    nEntriesPerChunk = entriesPerChunk;
    nAllocated = 0;
    nChunkBytes = PageAlignUp(entriesPerChunk * nSlotSize);
    arenaPath = backingDir + "/blockindex.arena";

    if (nEntriesPerChunk == 0)
        return false;

    // O_TRUNC discards any file left by a previous crash. The arena is scratch
    // (always rebuilt from leveldb at startup), so this is always safe.
    arenaFd = open(arenaPath.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (arenaFd < 0)
        return false;

    // Map the first chunk now so an unsupported/full FS fails here and the
    // caller can fall back to heap allocation.
    return AddChunk();
}

void* CBlockIndexPool::AllocateEntry()
{
    const size_t chunkIdx = nAllocated / nEntriesPerChunk;
    if (chunkIdx >= chunks.size()) {
        if (!AddChunk())
            return nullptr;   // couldn't grow (disk/mmap) -> caller uses heap
    }
    const size_t off = nAllocated % nEntriesPerChunk;
    void* p = static_cast<char*>(chunks[chunkIdx]) + (off * nSlotSize);
    nAllocated++;
    return p;
}

void* CBlockIndexPool::HashAt(size_t index)
{
    if (index >= nAllocated)
        return nullptr;
    const size_t chunkIdx = index / nEntriesPerChunk;
    const size_t off = index % nEntriesPerChunk;
    // The hash lives immediately after the CBlockIndex within the slot.
    return static_cast<char*>(chunks[chunkIdx]) + (off * nSlotSize) + nEntrySize;
}

bool CBlockIndexPool::Contains(const void* p) const
{
    if (!p)
        return false;
    const size_t usedBytes = nEntriesPerChunk * nSlotSize;
    for (void* w : chunks) {
        if (p >= w && p < static_cast<const char*>(w) + usedBytes)
            return true;
    }
    return false;
}

void CBlockIndexPool::AdviseOldBlocksCold(size_t nKeepRecent)
{
    if (nAllocated == 0)
        return;

    // Recent entries live in the last chunk(s); advise every chunk that holds
    // only buried entries (below nAllocated - nKeepRecent) as cold, leaving the
    // chunk(s) covering the recent tail resident.
    const size_t coldBelow = (nAllocated > nKeepRecent) ? (nAllocated - nKeepRecent) : 0;
    if (coldBelow == 0)
        return;
    const size_t lastColdChunk = coldBelow / nEntriesPerChunk; // [0, lastColdChunk) fully cold

    for (size_t i = 0; i < lastColdChunk && i < chunks.size(); i++) {
        if (madvise(chunks[i], nChunkBytes, MADV_COLD) != 0)
            madvise(chunks[i], nChunkBytes, MADV_DONTNEED);
    }
}

void CBlockIndexPool::DestroyAll(void (*destructor)(void*))
{
    for (size_t i = 0; i < nAllocated; i++) {
        const size_t chunkIdx = i / nEntriesPerChunk;
        const size_t off = i % nEntriesPerChunk;
        destructor(static_cast<char*>(chunks[chunkIdx]) + (off * nSlotSize));
    }
    nAllocated = 0;
}

#endif // WIN32
