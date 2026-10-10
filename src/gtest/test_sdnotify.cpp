// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "sdnotify.h"

#ifndef WIN32

#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

// A datagram socket standing in for systemd's notification socket.
class NotifySink {
public:
    explicit NotifySink(const std::string& path) : path_(path)
    {
        fd_ = socket(AF_UNIX, SOCK_DGRAM, 0);
        sockaddr_un addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        std::memcpy(addr.sun_path, path.data(), path.size());
        socklen_t len = offsetof(sockaddr_un, sun_path) + path.size();
        if (path[0] == '@') {
            addr.sun_path[0] = '\0';
        } else {
            len += 1;
        }
        bound_ = bind(fd_, reinterpret_cast<const sockaddr*>(&addr), len) == 0;
        timeval tv{1, 0};
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    ~NotifySink()
    {
        close(fd_);
        if (path_[0] != '@') unlink(path_.c_str());
    }
    bool bound() const { return bound_; }
    std::string receive()
    {
        char buf[256];
        const ssize_t n = recv(fd_, buf, sizeof(buf), 0);
        return n > 0 ? std::string(buf, n) : std::string();
    }

private:
    std::string path_;
    int fd_ = -1;
    bool bound_ = false;
};

std::string TempSocketPath()
{
    return (std::filesystem::temp_directory_path() / ("fluxd-notify-" + std::to_string(getpid()) + ".sock")).string();
}

} // namespace

TEST(SystemdNotify, DisabledWithoutNotifySocket)
{
    unsetenv("NOTIFY_SOCKET");
    EXPECT_FALSE(SystemdNotifyEnabled());
    EXPECT_FALSE(SystemdNotify("READY=1"));
}

TEST(SystemdNotify, DeliversStateToFilesystemSocket)
{
    const std::string path = TempSocketPath();
    NotifySink sink(path);
    ASSERT_TRUE(sink.bound());

    EXPECT_TRUE(SystemdNotifyTo(path, "READY=1"));
    EXPECT_EQ(sink.receive(), "READY=1");
}

TEST(SystemdNotify, DeliversStateToAbstractSocket)
{
    const std::string path = "@fluxd-notify-test-" + std::to_string(getpid());
    NotifySink sink(path);
    ASSERT_TRUE(sink.bound());

    EXPECT_TRUE(SystemdNotifyTo(path, "STOPPING=1"));
    EXPECT_EQ(sink.receive(), "STOPPING=1");
}

TEST(SystemdNotify, ReadsSocketFromEnvironmentAndFormatsStatus)
{
    const std::string path = TempSocketPath();
    NotifySink sink(path);
    ASSERT_TRUE(sink.bound());

    setenv("NOTIFY_SOCKET", path.c_str(), 1);
    EXPECT_TRUE(SystemdNotifyEnabled());
    SystemdNotifyStatus("Loading block index...");
    EXPECT_EQ(sink.receive(), "STATUS=Loading block index...");
    unsetenv("NOTIFY_SOCKET");
}

TEST(SystemdNotify, FailsWhenNothingListens)
{
    const std::string path = TempSocketPath() + ".absent";
    EXPECT_FALSE(SystemdNotifyTo(path, "READY=1"));
    EXPECT_FALSE(SystemdNotifyTo("", "READY=1"));
    EXPECT_FALSE(SystemdNotifyTo(path, ""));
}

#endif // WIN32
