// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "fs.h"

#include <cerrno>
#include <cstring>
#include <limits>

#ifndef WIN32
#include <fcntl.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

// FileLock implementation (replaces boost::interprocess::file_lock)
// Matches Bitcoin Core's implementation for cross-platform file locking

#ifndef WIN32
// POSIX implementation using fcntl
static std::string GetErrorReason()
{
    return std::strerror(errno);
}

FileLock::FileLock(const std::filesystem::path& file)
{
    m_fd = open(file.c_str(), O_RDWR);
    if (m_fd == -1) {
        m_reason = GetErrorReason();
    }
}

FileLock::~FileLock()
{
    if (m_fd != -1) {
        close(m_fd);
    }
}

bool FileLock::TryLock()
{
    if (m_fd == -1) {
        return false;
    }

    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if (fcntl(m_fd, F_SETLK, &lock) == -1) {
        m_reason = GetErrorReason();
        return false;
    }

    return true;
}

#else
// Windows implementation using LockFileEx
static std::string GetErrorReason()
{
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError();
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf,
        0, NULL);
    std::string ret((char*)lpMsgBuf);
    LocalFree(lpMsgBuf);
    return ret;
}

FileLock::FileLock(const std::filesystem::path& file)
{
    m_hFile = CreateFileW(file.wstring().c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_hFile == INVALID_HANDLE_VALUE) {
        m_reason = GetErrorReason();
    }
}

FileLock::~FileLock()
{
    if (m_hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hFile);
    }
}

bool FileLock::TryLock()
{
    if (m_hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    _OVERLAPPED overlapped = {};
    if (!LockFileEx(m_hFile, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
        std::numeric_limits<DWORD>::max(), std::numeric_limits<DWORD>::max(), &overlapped)) {
        m_reason = GetErrorReason();
        return false;
    }
    return true;
}
#endif
