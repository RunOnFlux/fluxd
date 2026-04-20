// Copyright (c) 2018-2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "blockindexpool.h"

#include <cstring>

CBlockIndexPool::CBlockIndexPool()
    : pPoolMem(nullptr), pHashMem(nullptr),
      nEntrySize(0), nHashSize(0), nCapacity(0), nAllocated(0)
{
}

CBlockIndexPool::~CBlockIndexPool()
{
    if (pPoolMem)
        munmap(pPoolMem, nCapacity * nEntrySize);
    if (pHashMem)
        munmap(pHashMem, nCapacity * nHashSize);
}

bool CBlockIndexPool::Initialize(size_t entrySize, size_t hashSize, size_t capacity)
{
    nEntrySize = entrySize;
    nHashSize = hashSize;
    nCapacity = capacity;
    nAllocated = 0;

    pPoolMem = mmap(nullptr, nCapacity * nEntrySize,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                    -1, 0);
    if (pPoolMem == MAP_FAILED) {
        pPoolMem = nullptr;
        return false;
    }

    pHashMem = mmap(nullptr, nCapacity * nHashSize,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
                    -1, 0);
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
