// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "sdnotify.h"

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <string>

#ifndef WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

static std::string NotifySocketPath()
{
    const char* path = std::getenv("NOTIFY_SOCKET");
    return path ? std::string(path) : std::string();
}

bool SystemdNotifyEnabled()
{
    return !NotifySocketPath().empty();
}

bool SystemdNotifyTo(const std::string& socketPath, const std::string& state)
{
#ifdef WIN32
    return false;
#else
    if (socketPath.empty() || state.empty()) return false;
    // sun_path holds the name and, for a filesystem socket, its terminator.
    sockaddr_un addr;
    if (socketPath.size() >= sizeof(addr.sun_path)) return false;
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, socketPath.data(), socketPath.size());
    socklen_t addrLen = offsetof(sockaddr_un, sun_path) + socketPath.size();
    if (socketPath[0] == '@') {
        // Abstract namespace: a leading NUL and no terminator.
        addr.sun_path[0] = '\0';
    } else {
        addrLen += 1;
    }

    const int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return false;
    const ssize_t sent = sendto(fd, state.data(), state.size(), MSG_NOSIGNAL,
                                reinterpret_cast<const sockaddr*>(&addr), addrLen);
    close(fd);
    return sent == static_cast<ssize_t>(state.size());
#endif
}

bool SystemdNotify(const std::string& state)
{
    const std::string path = NotifySocketPath();
    if (path.empty()) return false;
    return SystemdNotifyTo(path, state);
}

void SystemdNotifyStatus(const std::string& status)
{
    SystemdNotify("STATUS=" + status);
}
