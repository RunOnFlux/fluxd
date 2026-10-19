// Copyright (c) 2026 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <gtest/gtest.h>

#include "rpc/protocol.h"
#include "util.h"

#include <filesystem>
#include <sys/stat.h>

namespace fs = std::filesystem;

class RPCCookie : public ::testing::Test {
protected:
    fs::path dir;
    fs::path cookie;
    mode_t saved_umask;

    void SetUp() override {
        dir = fs::temp_directory_path() / fs::path("flux-gtest-cookie-" + std::to_string(getpid()));
        fs::create_directories(dir);
        cookie = dir / "rpc.cookie";
        mapArgs["-rpccookiefile"] = cookie.string();
        // A permissive umask, so only an explicit mode can give 0600.
        saved_umask = umask(022);
    }

    void TearDown() override {
        umask(saved_umask);
        mapArgs.erase("-rpccookiefile");
        fs::remove_all(dir);
    }

    mode_t Mode() {
        struct stat st;
        EXPECT_EQ(stat(cookie.c_str(), &st), 0);
        return st.st_mode & 0777;
    }
};

TEST_F(RPCCookie, ParsesPerms) {
    EXPECT_EQ(ParseCookiePerms("owner"), fs::perms::owner_read | fs::perms::owner_write);
    EXPECT_EQ(ParseCookiePerms("group"), fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read);
    EXPECT_EQ(ParseCookiePerms("all"), fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read);
    EXPECT_FALSE(ParseCookiePerms(""));
    EXPECT_FALSE(ParseCookiePerms("0640"));
    EXPECT_FALSE(ParseCookiePerms("Group"));
}

TEST_F(RPCCookie, WritesTheModeAsked) {
    for (const auto& [name, mode] : {std::pair{"owner", 0600}, {"group", 0640}, {"all", 0644}}) {
        std::string written;
        ASSERT_TRUE(GenerateAuthCookie(&written, ParseCookiePerms(name))) << name;
        EXPECT_EQ(Mode(), (mode_t)mode) << name;
        std::string read;
        ASSERT_TRUE(GetAuthCookie(&read));
        EXPECT_EQ(read, written);
        EXPECT_EQ(written.rfind("__cookie__:", 0), 0u);
        EXPECT_FALSE(fs::exists(dir / "rpc.cookie.tmp"));
    }
}

TEST_F(RPCCookie, WithoutPermsTheUmaskDecides) {
    std::string written;
    ASSERT_TRUE(GenerateAuthCookie(&written));
    EXPECT_EQ(Mode(), (mode_t)0644);
}

TEST_F(RPCCookie, ReplacesTheModeOfAnEarlierCookie) {
    std::string written;
    ASSERT_TRUE(GenerateAuthCookie(&written, ParseCookiePerms("all")));
    ASSERT_TRUE(GenerateAuthCookie(&written, ParseCookiePerms("owner")));
    EXPECT_EQ(Mode(), (mode_t)0600);
}

TEST_F(RPCCookie, AnUnwritableDirectoryFails) {
    mapArgs["-rpccookiefile"] = (dir / "missing" / "rpc.cookie").string();
    std::string written;
    EXPECT_FALSE(GenerateAuthCookie(&written, ParseCookiePerms("group")));
}
