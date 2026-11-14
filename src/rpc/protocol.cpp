// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "rpc/protocol.h"

#include "random.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "version.h"

#include <stdint.h>
#include <fstream>

using namespace std;

/**
 * JSON-RPC protocol.  Bitcoin speaks version 1.0 for maximum compatibility,
 * but uses JSON-RPC 1.1/2.0 standards for parts of the 1.0 standard that were
 * unspecified (HTTP errors and contents of 'error').
 *
 * 1.0 spec: http://json-rpc.org/wiki/specification
 * 1.2 spec: http://jsonrpc.org/historical/json-rpc-over-http.html
 */

string JSONRPCRequest(const string& strMethod, const UniValue& params, const UniValue& id)
{
    UniValue request(UniValue::VOBJ);
    request.pushKV("method", strMethod);
    request.pushKV("params", params);
    request.pushKV("id", id);
    return request.write() + "\n";
}

UniValue JSONRPCReplyObj(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply(UniValue::VOBJ);
    if (!error.isNull())
        reply.pushKV("result", NullUniValue);
    else
        reply.pushKV("result", result);
    reply.pushKV("error", error);
    reply.pushKV("id", id);
    return reply;
}

string JSONRPCReply(const UniValue& result, const UniValue& error, const UniValue& id)
{
    UniValue reply = JSONRPCReplyObj(result, error, id);
    return reply.write() + "\n";
}

UniValue JSONRPCError(int code, const string& message)
{
    UniValue error(UniValue::VOBJ);
    error.pushKV("code", code);
    error.pushKV("message", message);
    return error;
}

/** Username used when cookie authentication is in use (arbitrary, only for
 * recognizability in debugging/logging purposes)
 */
static const std::string COOKIEAUTH_USER = "__cookie__";
/** Default name for auth cookie file */
static const std::string COOKIEAUTH_FILE = ".cookie";

std::filesystem::path GetAuthCookieFile()
{
    std::filesystem::path path(GetArg("-rpccookiefile", COOKIEAUTH_FILE));
    if (!path.is_absolute()) path = GetDataDir() / path;
    return path;
}

std::optional<std::filesystem::perms> ParseCookiePerms(const std::string& value)
{
    using std::filesystem::perms;
    const perms owner = perms::owner_read | perms::owner_write;
    if (value == "owner") return owner;
    if (value == "group") return owner | perms::group_read;
    if (value == "all") return owner | perms::group_read | perms::others_read;
    return std::nullopt;
}

bool GenerateAuthCookie(std::string *cookie_out, std::optional<std::filesystem::perms> perms)
{
    unsigned char rand_pwd[32];
    GetRandBytes(rand_pwd, 32);
    std::string cookie = COOKIEAUTH_USER + ":" + EncodeBase64(&rand_pwd[0],32);

    /** the umask determines what permissions are used to create this file -
     * these are set to 077 in init.cpp unless overridden with -sysperms.
     */
    /* Written beside the cookie and renamed over it, so a reader never sees a
     * partial cookie or one with the wrong mode. */
    std::ofstream file;
    std::filesystem::path filepath = GetAuthCookieFile();
    std::filesystem::path filepath_tmp = filepath;
    filepath_tmp += ".tmp";
    file.open(filepath_tmp.string().c_str());
    if (!file.is_open()) {
        LogPrintf("Unable to open cookie authentication file %s for writing\n", filepath_tmp.string());
        return false;
    }
    file << cookie;
    file.close();
    if (!file) {
        LogPrintf("Unable to write cookie authentication file %s\n", filepath_tmp.string());
        return false;
    }

    std::error_code ec;
    if (perms) {
        std::filesystem::permissions(filepath_tmp, *perms, std::filesystem::perm_options::replace, ec);
        if (ec) {
            LogPrintf("Unable to set permissions on cookie authentication file %s: %s\n", filepath_tmp.string(), ec.message());
            std::filesystem::remove(filepath_tmp, ec);
            return false;
        }
    }
    std::filesystem::rename(filepath_tmp, filepath, ec);
    if (ec) {
        LogPrintf("Unable to rename cookie authentication file %s to %s: %s\n", filepath_tmp.string(), filepath.string(), ec.message());
        std::filesystem::remove(filepath_tmp, ec);
        return false;
    }
    LogPrintf("Generated RPC authentication cookie %s\n", filepath.string());

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

bool GetAuthCookie(std::string *cookie_out)
{
    std::ifstream file;
    std::string cookie;
    std::filesystem::path filepath = GetAuthCookieFile();
    file.open(filepath.string().c_str());
    if (!file.is_open())
        return false;
    std::getline(file, cookie);
    file.close();

    if (cookie_out)
        *cookie_out = cookie;
    return true;
}

void DeleteAuthCookie()
{
    try {
        std::filesystem::remove(GetAuthCookieFile());
    } catch (const std::filesystem::filesystem_error& e) {
        LogPrintf("%s: Unable to remove random auth cookie file: %s\n", __func__, e.what());
    }
}

