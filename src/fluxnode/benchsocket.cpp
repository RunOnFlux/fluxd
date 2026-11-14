// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "fluxnode/benchsocket.h"

#ifdef WIN32

std::string BenchSocketCall(const std::string&, const std::string&, const UniValue&)
{
    return "";
}

#else

#include <cstring>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include "tinyformat.h"
#include "util.h"

namespace {

const int TIMEOUT_S = 30;

class Socket
{
public:
    explicit Socket(int fd) : fd_(fd) {}
    ~Socket() { if (fd_ >= 0) close(fd_); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    int fd() const { return fd_; }

private:
    int fd_;
};

bool SendAll(int fd, const std::string& data)
{
    size_t sent = 0;
    while (sent < data.size()) {
        const ssize_t n = send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

std::string ReceiveAll(int fd)
{
    std::string reply;
    char buffer[4096];
    ssize_t n;
    while ((n = recv(fd, buffer, sizeof(buffer), 0)) > 0)
        reply.append(buffer, n);
    return reply;
}

} // namespace

std::string BenchSocketCall(const std::string& socketPath, const std::string& method, const UniValue& params)
{
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    if (socketPath.size() >= sizeof(address.sun_path)) return "";
    std::memcpy(address.sun_path, socketPath.c_str(), socketPath.size() + 1);

    const Socket socket_(socket(AF_UNIX, SOCK_STREAM, 0));
    if (socket_.fd() < 0) return "";
    const timeval timeout{TIMEOUT_S, 0};
    setsockopt(socket_.fd(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(socket_.fd(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    if (connect(socket_.fd(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        LogPrintf("fluxbench socket %s: %s\n", socketPath, strerror(errno));
        return "";
    }

    UniValue request(UniValue::VOBJ);
    request.push_back(Pair("method", method));
    request.push_back(Pair("params", params));
    request.push_back(Pair("id", 1));
    const std::string body = request.write();
    const std::string http = strprintf("POST / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                                       "Content-Type: application/json\r\nContent-Length: %u\r\n\r\n%s",
                                       body.size(), body);
    if (!SendAll(socket_.fd(), http)) return "";

    const std::string reply = ReceiveAll(socket_.fd());
    const size_t bodyAt = reply.find("\r\n\r\n");
    if (bodyAt == std::string::npos) return "";

    UniValue response;
    if (!response.read(reply.substr(bodyAt + 4)) || !response.isObject()) {
        LogPrintf("fluxbench socket %s: no JSON-RPC reply to %s\n", socketPath, method);
        return "";
    }
    const UniValue& error = find_value(response, "error");
    if (!error.isNull()) {
        const UniValue& message = find_value(error, "message");
        return message.isStr() ? message.get_str() : error.write();
    }
    const UniValue& result = find_value(response, "result");
    return result.isStr() ? result.get_str() : result.write(2);
}

#endif // WIN32
