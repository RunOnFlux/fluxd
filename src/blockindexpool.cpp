// Copyright (c) 2018-2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE   // expose O_TMPFILE
#endif

#include "blockindexpool.h"

#include <cstring>
#include <fcntl.h>

#ifndef O_TMPFILE
// Fallback for libc headers that don't expose the constant (Linux value).
#define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

// Map a sparse, anonymous (nameless) disk-backed region of `bytes` under
// directory `dir`, or return MAP_FAILED. We use O_TMPFILE: the backing inode
// has no directory entry, so it is invisible to ls/du/backup tooling and is
// reclaimed automatically by the kernel when the process exits (clean OR
// crashed) — no scratch file to manage and nothing to exclude from backups.
// ftruncate sparse-sizes it (untouched pages cost no disk), and MAP_SHARED
// lets the kernel evict dirty cold pages back to this inode instead of swap.
// If O_TMPFILE is unsupported (old kernel/exotic FS), open() fails and the
// caller falls through to plain heap allocation.
static void* MapBackingFile(const std::string& dir, size_t bytes)
{
    int fd = open(dir.c_str(), O_TMPFILE | O_RDWR, 0600);
    if (fd < 0)
        return MAP_FAILED;

    if (ftruncate(fd, (off_t)bytes) != 0) {
        close(fd);
        return MAP_FAILED;
    }

    void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd); // mapping keeps the unnamed inode alive; reclaimed on munmap/exit
    return p;
}

CBlockIndexPool::CBlockIndexPool()
    : pPoolMem(nullptr), pHashMem(nullptr),
      nEntrySize(0), nHashSize(0), nCapacity(0), nAllocated(0)
{
}

CBlockIndexPool::~CBlockIndexPool()
{
    // The backing inodes are nameless (O_TMPFILE); munmap drops the last
    // reference and the kernel reclaims their disk blocks. Nothing to unlink.
    if (pPoolMem)
        munmap(pPoolMem, nCapacity * nEntrySize);
    if (pHashMem)
        munmap(pHashMem, nCapacity * nHashSize);
}

bool CBlockIndexPool::Initialize(size_t entrySize, size_t hashSize, size_t capacity,
                                 const std::string& backingDir)
{
    nEntrySize = entrySize;
    nHashSize = hashSize;
    nCapacity = capacity;
    nAllocated = 0;

    // Two separate nameless inodes under the datadir's filesystem.
    pPoolMem = MapBackingFile(backingDir, nCapacity * nEntrySize);
    if (pPoolMem == MAP_FAILED) {
        pPoolMem = nullptr;
        return false;
    }

    pHashMem = MapBackingFile(backingDir, nCapacity * nHashSize);
    if (pHashMem == MAP_FAILED) {
        munmap(pPoolMem, nCapacity * nEntrySize);
        pPoolMem = nullptr;
        pHashMem = nullptr;
        return false;
    }

    return true;
}

void* CBlockIndexPool::AllocateEntry()
{
    if (nAllocated >= nCapacity)
        return nullptr;

    void* p = static_cast<char*>(pPoolMem) + (nAllocated * nEntrySize);
    nAllocated++;
    return p;
}

void* CBlockIndexPool::HashAt(size_t index)
{
    if (index >= nAllocated)
        return nullptr;
    return static_cast<char*>(pHashMem) + (index * nHashSize);
}

bool CBlockIndexPool::Contains(const void* p) const
{
    if (!pPoolMem || !p)
        return false;
    return p >= pPoolMem &&
           p < static_cast<const char*>(pPoolMem) + (nAllocated * nEntrySize);
}

void CBlockIndexPool::AdviseOldBlocksCold(size_t nKeepRecent)
{
    if (!pPoolMem || nAllocated == 0)
        return;

    size_t nColdCount = (nAllocated > nKeepRecent) ? nAllocated - nKeepRecent : 0;
    if (nColdCount == 0)
        return;

    long pageSize = sysconf(_SC_PAGESIZE);

    size_t coldPoolBytes = nColdCount * nEntrySize;
    coldPoolBytes = (coldPoolBytes / pageSize) * pageSize;

    size_t coldHashBytes = nColdCount * nHashSize;
    coldHashBytes = (coldHashBytes / pageSize) * pageSize;

    // MADV_COLD (Linux 5.4+) tells the kernel these pages are cold.
    // Fall back to MADV_DONTNEED on older kernels (discards pages entirely).
#ifndef MADV_COLD
#define MADV_COLD 20
#endif
    int advice = MADV_COLD;
    if (coldPoolBytes > 0) {
        if (madvise(pPoolMem, coldPoolBytes, advice) != 0)
            madvise(pPoolMem, coldPoolBytes, MADV_DONTNEED);
    }
    if (coldHashBytes > 0) {
        if (madvise(pHashMem, coldHashBytes, advice) != 0)
            madvise(pHashMem, coldHashBytes, MADV_DONTNEED);
    }
}

void CBlockIndexPool::DestroyAll(void (*destructor)(void*))
{
    if (!pPoolMem)
        return;

    for (size_t i = 0; i < nAllocated; i++) {
        void* p = static_cast<char*>(pPoolMem) + (i * nEntrySize);
        destructor(p);
    }
    nAllocated = 0;
}
