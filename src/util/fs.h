// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_FS_H
#define BITCOIN_UTIL_FS_H

#include <filesystem>
#include <string>

/**
 * Simple file locking mechanism (replaces boost::interprocess::file_lock)
 * Uses native OS file locking: fcntl on POSIX, LockFileEx on Windows
 *
 * Implementation follows Bitcoin Core's approach for cross-platform file locking.
 */
class FileLock
{
public:
    FileLock() = delete;
    FileLock(const FileLock&) = delete;
    FileLock(FileLock&&) = delete;
    explicit FileLock(const std::filesystem::path& file);
    ~FileLock();
    bool TryLock();
    std::string GetReason() { return m_reason; }

private:
    std::string m_reason;
#ifndef WIN32
    int m_fd = -1;
#else
    void* m_hFile = (void*)-1; // INVALID_HANDLE_VALUE
#endif
};

#endif // BITCOIN_UTIL_FS_H
