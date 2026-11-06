// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>

#include "fluxnode/benchsocket.h"

namespace {

// A stand-in for fluxbench's RPC server: one connection, one canned HTTP reply.
class FakeBench
{
public:
    explicit FakeBench(const std::string& body, const std::string& status = "200 OK")
    {
        char dir[] = "/tmp/fbXXXXXX";
        path_ = std::string(mkdtemp(dir)) + "/s.sock";
        listen_ = socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un address{};
        address.sun_family = AF_UNIX;
        std::strcpy(address.sun_path, path_.c_str());
        EXPECT_EQ(0, bind(listen_, reinterpret_cast<sockaddr*>(&address), sizeof(address)));
        EXPECT_EQ(0, listen(listen_, 1));
        server_ = std::thread([this, body, status]() {
            const int client = accept(listen_, nullptr, nullptr);
            char buffer[4096];
            while (request_.find("\r\n\r\n") == std::string::npos || !Whole()) {
                const ssize_t n = recv(client, buffer, sizeof(buffer), 0);
                if (n <= 0) break;
                request_.append(buffer, n);
            }
            const std::string reply = "HTTP/1.1 " + status + "\r\nContent-Length: " +
                                      std::to_string(body.size()) + "\r\n\r\n" + body;
            send(client, reply.data(), reply.size(), MSG_NOSIGNAL);
            close(client);
        });
    }

    ~FakeBench()
    {
        if (server_.joinable()) server_.join();
        close(listen_);
        std::filesystem::remove_all(std::filesystem::path(path_).parent_path());
    }

    const std::string& path() const { return path_; }

    std::string Request()
    {
        server_.join();
        return request_;
    }

private:
    bool Whole() const
    {
        const size_t at = request_.find("Content-Length: ");
        const size_t bodyAt = request_.find("\r\n\r\n");
        if (at == std::string::npos || bodyAt == std::string::npos) return false;
        return request_.size() >= bodyAt + 4 + std::stoul(request_.substr(at + 16));
    }

    std::string path_;
    std::string request_;
    int listen_;
    std::thread server_;
};

UniValue NoParams() { return UniValue(UniValue::VARR); }

} // namespace

TEST(benchsocket, a_call_is_one_json_rpc_post)
{
    FakeBench bench("{\"result\":\"ok\",\"error\":null,\"id\":1}");
    UniValue params(UniValue::VARR);
    params.push_back(UniValue(true));
    EXPECT_EQ("ok", BenchSocketCall(bench.path(), "getstatus", params));
    const std::string request = bench.Request();
    EXPECT_EQ(0u, request.find("POST / HTTP/1.1\r\n"));
    EXPECT_NE(std::string::npos, request.find("\"method\":\"getstatus\""));
    EXPECT_NE(std::string::npos, request.find("\"params\":[true]"));
}

TEST(benchsocket, an_object_result_reads_as_the_cli_prints_it)
{
    FakeBench bench("{\"result\":{\"status\":\"online\"},\"error\":null,\"id\":1}");
    const std::string answer = BenchSocketCall(bench.path(), "getstatus", NoParams());
    UniValue parsed;
    ASSERT_TRUE(parsed.read(answer));
    EXPECT_EQ("online", find_value(parsed, "status").get_str());
    EXPECT_NE(std::string::npos, answer.find('\n'));
}

TEST(benchsocket, a_refused_call_answers_with_the_message)
{
    FakeBench bench("{\"result\":null,\"error\":{\"code\":-8,\"message\":\"not signing\"},\"id\":1}");
    EXPECT_EQ("not signing", BenchSocketCall(bench.path(), "signfluxnodetransaction", NoParams()));
}

TEST(benchsocket, a_grant_refusal_is_no_answer)
{
    FakeBench bench("", "403 Forbidden");
    EXPECT_EQ("", BenchSocketCall(bench.path(), "stop", NoParams()));
}

TEST(benchsocket, a_missing_socket_is_no_answer)
{
    EXPECT_EQ("", BenchSocketCall("/tmp/no-such-fluxbench.sock", "getstatus", NoParams()));
}

TEST(benchsocket, a_path_too_long_for_a_socket_is_no_answer)
{
    EXPECT_EQ("", BenchSocketCall("/tmp/" + std::string(200, 'x'), "getstatus", NoParams()));
}
