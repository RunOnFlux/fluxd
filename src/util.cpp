// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "util.h"

#include "chainparamsbase.h"
#include "random.h"
#include "serialize.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <thread>
#include <mutex>
#include <sstream>
#include <algorithm>
#include <string_view>
#include "clientversion.h"

#include <stdarg.h>
#include <mutex>
#include <stdio.h>
#include <mutex>

#if (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
#include <pthread.h>
#include <mutex>
#include <pthread_np.h>
#include <mutex>
#endif

#ifndef WIN32
// for posix_fallocate
#ifdef __linux__

#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif

#define _POSIX_C_SOURCE 200112L

#endif // __linux__

#include <algorithm>
#include <mutex>
#include <fcntl.h>
#include <mutex>
#include <sys/resource.h>
#include <mutex>
#include <sys/stat.h>
#include <mutex>

#else

#ifdef _MSC_VER
#pragma warning(disable:4786)
#pragma warning(disable:4804)
#pragma warning(disable:4805)
#pragma warning(disable:4717)
#endif

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0501

#ifdef _WIN32_IE
#undef _WIN32_IE
#endif
#define _WIN32_IE 0x0501

#define WIN32_LEAN_AND_MEAN 1
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <io.h> /* for _commit */
#include <mutex>
#include <shlobj.h>
#include <mutex>
#endif

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#include <mutex>
#endif

#include <boost/algorithm/string/case_conv.hpp> // for to_lower()
#include <mutex>
#include <boost/algorithm/string/join.hpp>
#include <mutex>
#include <boost/algorithm/string/predicate.hpp> // for startswith() and endswith()
#include <mutex>
#include <filesystem>
#include <mutex>
#include <fstream>
#include <mutex>
#include <boost/program_options/detail/config_file.hpp>
#include <mutex>
#include <boost/program_options/parsers.hpp>
#include <mutex>
#include <openssl/crypto.h>
#include <mutex>
#include <openssl/conf.h>
#include <mutex>

// Work around clang compilation problem in Boost 1.46:
// /usr/include/boost/program_options/detail/config_file.hpp:163:17: error: call to function 'to_internal' that is neither visible in the template definition nor found by argument-dependent lookup
// See also: http://stackoverflow.com/questions/10020179/compilation-fail-in-boost-librairies-program-options
//           http://clang.debian.net/status.php?version=3.0&key=CANNOT_FIND_FUNCTION
namespace boost {

    namespace program_options {
        std::string to_internal(const std::string&);
    }

} // namespace boost

using namespace std;

string strFluxnodeAddr = "";
string strFluxnodePrivKey = "";
bool fFluxnode = false;
bool fArcane = false;

CCriticalSection cs_args;
map<string, string> mapArgs;
map<string, vector<string> > mapMultiArgs;
bool fDebug = false;
bool fPrintToConsole = false;
bool fPrintToDebugLog = true;
bool fDaemon = false;
bool fServer = false;
string strMiscWarning;
bool fLogTimestamps = DEFAULT_LOGTIMESTAMPS;
bool fLogTimeMicros = DEFAULT_LOGTIMEMICROS;
bool fLogIPs = DEFAULT_LOGIPS;
std::atomic<bool> fReopenDebugLog(false);
CTranslationInterface translationInterface;

/** Init OpenSSL library multithreading support */
static CCriticalSection** ppmutexOpenSSL;
void locking_callback(int mode, int i, const char* file, int line) NO_THREAD_SAFETY_ANALYSIS
{
    if (mode & CRYPTO_LOCK) {
        ENTER_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    } else {
        LEAVE_CRITICAL_SECTION(*ppmutexOpenSSL[i]);
    }
}

// Init
static class CInit
{
public:
    CInit()
    {
        // Init OpenSSL library multithreading support
        ppmutexOpenSSL = (CCriticalSection**)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(CCriticalSection*));
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            ppmutexOpenSSL[i] = new CCriticalSection();
        CRYPTO_set_locking_callback(locking_callback);

        // OpenSSL can optionally load a config file which lists optional loadable modules and engines.
        // We don't use them so we don't require the config. However some of our libs may call functions
        // which attempt to load the config file, possibly resulting in an exit() or crash if it is missing
        // or corrupt. Explicitly tell OpenSSL not to try to load the file. The result for our libs will be
        // that the config appears to have been loaded and there are no modules/engines available.
        OPENSSL_no_config();
    }
    ~CInit()
    {
        // Shutdown OpenSSL library multithreading support
        CRYPTO_set_locking_callback(NULL);
        for (int i = 0; i < CRYPTO_num_locks(); i++)
            delete ppmutexOpenSSL[i];
        OPENSSL_free(ppmutexOpenSSL);
    }
}
instance_of_cinit;

/**
 * LogPrintf() has been broken a couple of times now
 * by well-meaning people adding mutexes in the most straightforward way.
 * It breaks because it may be called by global destructors during shutdown.
 * Since the order of destruction of static/global objects is undefined,
 * defining a mutex as a global object doesn't work (the mutex gets
 * destroyed, and then some later destructor calls OutputDebugStringF,
 * maybe indirectly, and you get a core dump at shutdown trying to lock
 * the mutex).
 */

static std::once_flag debugPrintInitFlag;

/**
 * We use std::call_once() to make sure mutexDebugLog and
 * vMsgsBeforeOpenLog are initialized in a thread-safe manner.
 *
 * NOTE: fileout, mutexDebugLog and sometimes vMsgsBeforeOpenLog
 * are leaked on exit. This is ugly, but will be cleaned up by
 * the OS/libc. When the shutdown sequence is fully audited and
 * tested, explicit destruction of these objects can be implemented.
 */
static FILE* fileout = NULL;
static std::mutex* mutexDebugLog = NULL;
static list<string> *vMsgsBeforeOpenLog;

[[noreturn]] void new_handler_terminate()
{
    // Rather than throwing std::bad-alloc if allocation fails, terminate
    // immediately to (try to) avoid chain corruption.
    // Since LogPrintf may itself allocate memory, set the handler directly
    // to terminate first.
    std::set_new_handler(std::terminate);
    fputs("Error: Out of memory. Terminating.\n", stderr);
    LogPrintf("Error: Out of memory. Terminating.\n");

    // The log was successful, terminate now.
    std::terminate();
};

static int FileWriteStr(const std::string &str, FILE *fp)
{
    return fwrite(str.data(), 1, str.size(), fp);
}

static void DebugPrintInit()
{
    assert(mutexDebugLog == NULL);
    mutexDebugLog = new std::mutex();
    vMsgsBeforeOpenLog = new list<string>;
}

void OpenDebugLog()
{
    std::call_once(debugPrintInitFlag, &DebugPrintInit);
    std::lock_guard<std::mutex> scoped_lock(*mutexDebugLog);

    assert(fileout == NULL);
    assert(vMsgsBeforeOpenLog);
    std::filesystem::path pathDebug = GetDataDir() / "debug.log";
    fileout = fopen(pathDebug.string().c_str(), "a");
    if (fileout) setbuf(fileout, NULL); // unbuffered

    // dump buffered messages from before we opened the log
    while (!vMsgsBeforeOpenLog->empty()) {
        FileWriteStr(vMsgsBeforeOpenLog->front(), fileout);
        vMsgsBeforeOpenLog->pop_front();
    }

    delete vMsgsBeforeOpenLog;
    vMsgsBeforeOpenLog = NULL;
}

bool LogAcceptCategory(const char* category)
{
    if (category != NULL)
    {
        if (!fDebug)
            return false;

        // Give each thread quick access to -debug settings.
        // This helps prevent issues debugging global destructors,
        // where mapMultiArgs might be deleted before another
        // global destructor calls LogPrint()
        thread_local std::unique_ptr<set<string>> ptrCategory;
        if (ptrCategory.get() == NULL)
        {
            const vector<string>& categories = mapMultiArgs["-debug"];
            ptrCategory.reset(new set<string>(categories.begin(), categories.end()));
            // thread_specific_ptr automatically deletes the set when the thread ends.
        }
        const set<string>& setCategories = *ptrCategory.get();

        // if not debugging everything and not debugging specific category, LogPrint does nothing.
        if (setCategories.count(string("")) == 0 &&
            setCategories.count(string("1")) == 0 &&
            setCategories.count(string(category)) == 0)
            return false;
    }
    return true;
}

/**
 * fStartedNewLine is a state variable held by the calling context that will
 * suppress printing of the timestamp when multiple calls are made that don't
 * end in a newline. Initialize it to true, and hold it, in the calling context.
 */
static std::string LogTimestampStr(const std::string &str, bool *fStartedNewLine)
{
    string strStamped;

    if (!fLogTimestamps)
        return str;

    if (*fStartedNewLine)
        strStamped =  DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()) + ' ' + str;
    else
        strStamped = str;

    if (!str.empty() && str[str.size()-1] == '\n')
        *fStartedNewLine = true;
    else
        *fStartedNewLine = false;

    return strStamped;
}

int LogPrintStr(const std::string &str)
{
    int ret = 0; // Returns total number of characters written
    static bool fStartedNewLine = true;
    if (fPrintToConsole)
    {
        // print to console
        ret = fwrite(str.data(), 1, str.size(), stdout);
        fflush(stdout);
    }
    else if (fPrintToDebugLog)
    {
        std::call_once(debugPrintInitFlag, &DebugPrintInit);
        std::lock_guard<std::mutex> scoped_lock(*mutexDebugLog);

        string strTimestamped = LogTimestampStr(str, &fStartedNewLine);

        // buffer if we haven't opened the log yet
        if (fileout == NULL) {
            assert(vMsgsBeforeOpenLog);
            ret = strTimestamped.length();
            vMsgsBeforeOpenLog->push_back(strTimestamped);
        }
        else
        {
            // reopen the log file, if requested
            if (fReopenDebugLog) {
                fReopenDebugLog = false;
                std::filesystem::path pathDebug = GetDataDir() / "debug.log";
                if (freopen(pathDebug.string().c_str(),"a",fileout) != NULL)
                    setbuf(fileout, NULL); // unbuffered
            }

            ret = FileWriteStr(strTimestamped, fileout);
        }
    }
    return ret;
}

static void InterpretNegativeSetting(string name, map<string, string>& mapSettingsRet)
{
    // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
    if (name.find("-no") == 0)
    {
        std::string positive("-");
        positive.append(name.begin()+3, name.end());
        if (mapSettingsRet.count(positive) == 0)
        {
            bool value = !GetBoolArg(name, false);
            mapSettingsRet[positive] = (value ? "1" : "0");
        }
    }
}

void ParseParameters(int argc, const char* const argv[])
{
    LOCK(cs_args);
    mapArgs.clear();
    mapMultiArgs.clear();

    for (int i = 1; i < argc; i++)
    {
        std::string str(argv[i]);
        std::string strValue;
        size_t is_index = str.find('=');
        if (is_index != std::string::npos)
        {
            strValue = str.substr(is_index+1);
            str = str.substr(0, is_index);
        }
#ifdef WIN32
        str = ToLower(str);
        if (StartsWith(str, "/"))
            str = "-" + str.substr(1);
#endif

        if (str[0] != '-')
            break;

        // Interpret --foo as -foo.
        // If both --foo and -foo are set, the last takes effect.
        if (str.length() > 1 && str[1] == '-')
            str = str.substr(1);

        mapArgs[str] = strValue;
        mapMultiArgs[str].push_back(strValue);
    }

    // New 0.6 features:
    for (const PAIRTYPE(string,string)& entry : mapArgs)
    {
        // interpret -nofoo as -foo=0 (and -nofoo=0 as -foo=1) as long as -foo not set
        InterpretNegativeSetting(entry.first, mapArgs);
    }
}

bool IsArgSet(const std::string& strArg)
{
    LOCK(cs_args);
    return mapArgs.count(strArg);
}


std::string GetArg(const std::string& strArg, const std::string& strDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return mapArgs[strArg];
    return strDefault;
}

int64_t GetArg(const std::string& strArg, int64_t nDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return atoi64(mapArgs[strArg]);
    return nDefault;
}

bool GetBoolArg(const std::string& strArg, bool fDefault)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
    {
        if (mapArgs[strArg].empty())
            return true;
        return (atoi(mapArgs[strArg]) != 0);
    }
    return fDefault;
}

bool SoftSetArg(const std::string& strArg, const std::string& strValue)
{
    LOCK(cs_args);
    if (mapArgs.count(strArg))
        return false;
    mapArgs[strArg] = strValue;
    return true;
}

bool SoftSetBoolArg(const std::string& strArg, bool fValue)
{
    if (fValue)
        return SoftSetArg(strArg, std::string("1"));
    else
        return SoftSetArg(strArg, std::string("0"));
}

static const int screenWidth = 79;
static const int optIndent = 2;
static const int msgIndent = 7;

std::string HelpMessageGroup(const std::string &message) {
    return std::string(message) + std::string("\n\n");
}

std::string HelpMessageOpt(const std::string &option, const std::string &message) {
    return std::string(optIndent,' ') + std::string(option) +
           std::string("\n") + std::string(msgIndent,' ') +
           FormatParagraph(message, screenWidth - msgIndent, msgIndent) +
           std::string("\n\n");
}

static std::string FormatException(const std::exception* pex, const char* pszThread)
{
#ifdef WIN32
    char pszModule[MAX_PATH] = "";
    GetModuleFileNameA(NULL, pszModule, sizeof(pszModule));
#else
    const char* pszModule = "Zelcash"; // "Zelcash" is now known as "Flux"
#endif
    if (pex)
        return strprintf(
            "EXCEPTION: %s       \n%s       \n%s in %s       \n", typeid(*pex).name(), pex->what(), pszModule, pszThread);
    else
        return strprintf(
            "UNKNOWN EXCEPTION       \n%s in %s       \n", pszModule, pszThread);
}

void PrintExceptionContinue(const std::exception* pex, const char* pszThread)
{
    std::string message = FormatException(pex, pszThread);
    LogPrintf("\n\n************************\n%s\n", message);
    fprintf(stderr, "\n\n************************\n%s\n", message.c_str());
    strMiscWarning = message;
}

std::filesystem::path GetDefaultDataDirForCoinName(const std::string &coinName)
{
    namespace fs = std::filesystem;
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\Flux
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\Flux
    // Mac: ~/Library/Application Support/Flux
    // Unix: ~/.flux
#ifdef WIN32
    // Windows

    return GetSpecialFolderPath(CSIDL_APPDATA) / coinName;
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    return pathRet / "Library/Application Support" / coinName;
#else
    std::string flux_lowercase = "flux";
    std::string zelcash_lowercase = "zelcash";
    // Unix
    if (coinName == "Flux")
        return pathRet / ("." + flux_lowercase);

    return pathRet / ("." + zelcash_lowercase);
#endif
#endif
}


std::filesystem::path GetDefaultDataDir()
{
    namespace fs = std::filesystem;

    fs::path fluxDefaultDir = GetDefaultDataDirForCoinName("Flux");
    if (!fs::is_directory(fluxDefaultDir)) {
        // try "zelcash" in case we're upgrading from pre-firo version
        fs::path zelcashDefaultDir = GetDefaultDataDirForCoinName("Zelcash");
        if (fs::is_directory(zelcashDefaultDir))
            return zelcashDefaultDir;
    }

    return fluxDefaultDir;
}

static std::filesystem::path pathCached;
static std::filesystem::path pathCachedNetSpecific;
static std::filesystem::path zc_paramsPathCached;
static CCriticalSection csPathCached;

static std::filesystem::path ZC_GetBaseParamsDir()
{
    // Copied from GetDefaultDataDir and adapter for zcash params.

    namespace fs = std::filesystem;
    // Windows < Vista: C:\Documents and Settings\Username\Application Data\ZcashParams
    // Windows >= Vista: C:\Users\Username\AppData\Roaming\ZcashParams
    // Mac: ~/Library/Application Support/ZcashParams
    // Unix: ~/.zcash-params
#ifdef WIN32
    // Windows
    return GetSpecialFolderPath(CSIDL_APPDATA) / "ZcashParams";
#else
    fs::path pathRet;
    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        pathRet = fs::path("/");
    else
        pathRet = fs::path(pszHome);
#ifdef MAC_OSX
    // Mac
    pathRet /= "Library/Application Support";
    TryCreateDirectory(pathRet);
    return pathRet / "ZcashParams";
#else
    // Unix
    return pathRet / ".zcash-params";
#endif
#endif
}

const std::filesystem::path &ZC_GetParamsDir()
{
    namespace fs = std::filesystem;

    LOCK(csPathCached); // Reuse the same lock as upstream.

    fs::path &path = zc_paramsPathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

    path = ZC_GetBaseParamsDir();

    return path;
}

// Return the user specified export directory.  Create directory if it doesn't exist.
// If user did not set option, return an empty path.
// If there is a filesystem problem, throw an exception.
const std::filesystem::path GetExportDir()
{
    namespace fs = std::filesystem;
    fs::path path;
    if (mapArgs.count("-exportdir")) {
        path = fs::absolute(mapArgs["-exportdir"]);
        if (fs::exists(path) && !fs::is_directory(path)) {
            throw std::runtime_error(strprintf("The -exportdir '%s' already exists and is not a directory", path.string()));
        }
        if (!fs::exists(path) && !fs::create_directories(path)) {
            throw std::runtime_error(strprintf("Failed to create directory at -exportdir '%s'", path.string()));
        }
    }
    return path;
}


const std::filesystem::path &GetDataDir(bool fNetSpecific)
{
    namespace fs = std::filesystem;

    LOCK(csPathCached);

    fs::path &path = fNetSpecific ? pathCachedNetSpecific : pathCached;

    // This can be called during exceptions by LogPrintf(), so we cache the
    // value so we don't have to do memory allocations after that.
    if (!path.empty())
        return path;

    if (mapArgs.count("-datadir")) {
        path = fs::absolute(mapArgs["-datadir"]);
        if (!fs::is_directory(path)) {
            path = "";
            return path;
        }
    } else {
        path = GetDefaultDataDir();
    }
    if (fNetSpecific)
        path /= BaseParams().DataDir();

    fs::create_directories(path);

    return path;
}

bool RenameDirectoriesFromZelcashToFlux()
{
    namespace fs = std::filesystem;

    fs::path zelcashPath = GetDefaultDataDirForCoinName("Zelcash");
    fs::path fluxPath = GetDefaultDataDirForCoinName("Flux");

    // rename is possible only if zcoin directory exists and firo doesn't
    if (fs::exists(fluxPath) || !fs::is_directory(zelcashPath))
        return false;

    fs::path zelcashConfFileName = zelcashPath / "zelcash.conf";
    fs::path fluxConfFileName = zelcashPath / "flux.conf";
    if (fs::exists(fluxConfFileName))
        return false;

    try {
        if (fs::is_regular_file(zelcashConfFileName))
            fs::rename(zelcashConfFileName, fluxConfFileName);

        try {
            fs::rename(zelcashPath, fluxPath);
        }
        catch (const fs::filesystem_error &) {
            // rename config file back
            fs::rename(fluxConfFileName, zelcashConfFileName);
            throw;
        }
    }
    catch (const fs::filesystem_error &) {
        return false;
    }

    ClearDatadirCache();
    return true;
}

void ClearDatadirCache()
{
    pathCached = std::filesystem::path();
    pathCachedNetSpecific = std::filesystem::path();
}

std::filesystem::path GetConfigFile()
{
    std::filesystem::path pathFluxConfigFile(GetArg("-conf", "flux.conf"));
    std::filesystem::path dataDir = GetDataDir(false);
    if (!pathFluxConfigFile.is_absolute()) {
        pathFluxConfigFile = dataDir / pathFluxConfigFile;
    }

    std::ifstream streamConfig(pathFluxConfigFile);
    if (streamConfig.good()) {
        return pathFluxConfigFile;
    }

    std::filesystem::path pathZelcashConfigFile(GetArg("-conf", "zelcash.conf"));
    if (!pathZelcashConfigFile.is_absolute()) {
        pathZelcashConfigFile = dataDir / pathZelcashConfigFile;
    }

    return pathZelcashConfigFile;
}

std::filesystem::path GetFluxnodeConfigFile()
{
    namespace fs = std::filesystem;

    // If zelnode.conf exists use this file instead of fluxnode.conf
    std::filesystem::path pathZelnodeConfigFile(GetArg("-znconf", "zelnode.conf"));
    if (!pathZelnodeConfigFile.is_absolute()) {
        pathZelnodeConfigFile = GetDataDir() / pathZelnodeConfigFile;
        if (fs::exists(pathZelnodeConfigFile)) {
            LogPrintf("Using zelnode.conf Config File\n");
            return pathZelnodeConfigFile;
        }
    }

    // Use fluxnode.conf as the next option
    std::filesystem::path pathFluxnodeConfigFile(GetArg("-znconf", "fluxnode.conf"));
    if (!pathFluxnodeConfigFile.is_absolute()) {
        pathFluxnodeConfigFile = GetDataDir() / pathFluxnodeConfigFile;
        if (fs::exists(pathFluxnodeConfigFile)) {
            LogPrintf("Using fluxnode.conf Config File\n");
            return pathFluxnodeConfigFile;
        }
    }

    // If no file exists yet. It needs to be created. Returning the location and filename so it can be created
    // Newly created files should be in the format of fluxnode.conf
    return pathFluxnodeConfigFile;
}

void ReadConfigFile(map<string, string>& mapSettingsRet,
                    map<string, vector<string> >& mapMultiSettingsRet)
{
    std::ifstream streamConfig(GetConfigFile());
    if (!streamConfig.good())
        throw missing_zelcash_conf();

    set<string> setOptions;
    setOptions.insert("*");

    for (boost::program_options::detail::config_file_iterator it(streamConfig, setOptions), end; it != end; ++it)
    {
        // Don't overwrite existing settings so command line settings override flux.conf
        string strKey = string("-") + it->string_key;
        if (mapSettingsRet.count(strKey) == 0)
        {
            mapSettingsRet[strKey] = it->value[0];
            // interpret nofoo=1 as foo=0 (and nofoo=0 as foo=1) as long as foo not set)
            InterpretNegativeSetting(strKey, mapSettingsRet);
        }
        mapMultiSettingsRet[strKey].push_back(it->value[0]);
    }
    // If datadir is changed in .conf file:
    ClearDatadirCache();
}

#ifndef WIN32
std::filesystem::path GetPidFile()
{
    std::filesystem::path pathPidFile(GetArg("-pid", "zelcashd.pid"));
    if (!pathPidFile.is_absolute()) pathPidFile = GetDataDir() / pathPidFile;
    return pathPidFile;
}

void CreatePidFile(const std::filesystem::path &path, pid_t pid)
{
    FILE* file = fopen(path.string().c_str(), "w");
    if (file)
    {
        fprintf(file, "%d\n", pid);
        fclose(file);
    }
}
#endif

bool RenameOver(std::filesystem::path src, std::filesystem::path dest)
{
#ifdef WIN32
    return MoveFileExA(src.string().c_str(), dest.string().c_str(),
                       MOVEFILE_REPLACE_EXISTING) != 0;
#else
    int rc = std::rename(src.string().c_str(), dest.string().c_str());
    return (rc == 0);
#endif /* WIN32 */
}

/**
 * Ignores exceptions thrown by Boost's create_directory if the requested directory exists.
 * Specifically handles case where path p exists, but it wasn't possible for the user to
 * write to the parent directory.
 */
bool TryCreateDirectory(const std::filesystem::path& p)
{
    try
    {
        return std::filesystem::create_directory(p);
    } catch (const std::filesystem::filesystem_error&) {
        if (!std::filesystem::exists(p) || !std::filesystem::is_directory(p))
            throw;
    }

    // create_directory didn't create the directory, it had to have existed already
    return false;
}

void FileCommit(FILE *fileout)
{
    fflush(fileout); // harmless if redundantly called
#ifdef WIN32
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(fileout));
    FlushFileBuffers(hFile);
#else
    #if defined(__linux__) || defined(__NetBSD__)
    fdatasync(fileno(fileout));
    #elif defined(__APPLE__) && defined(F_FULLFSYNC)
    fcntl(fileno(fileout), F_FULLFSYNC, 0);
    #else
    fsync(fileno(fileout));
    #endif
#endif
}

bool TruncateFile(FILE *file, unsigned int length) {
#if defined(WIN32)
    return _chsize(_fileno(file), length) == 0;
#else
    return ftruncate(fileno(file), length) == 0;
#endif
}

/**
 * this function tries to raise the file descriptor limit to the requested number.
 * It returns the actual file descriptor limit (which may be more or less than nMinFD)
 */
int RaiseFileDescriptorLimit(int nMinFD) {
#if defined(WIN32)
    return 2048;
#else
    struct rlimit limitFD;
    if (getrlimit(RLIMIT_NOFILE, &limitFD) != -1) {
        if (limitFD.rlim_cur < (rlim_t)nMinFD) {
            limitFD.rlim_cur = nMinFD;
            if (limitFD.rlim_cur > limitFD.rlim_max)
                limitFD.rlim_cur = limitFD.rlim_max;
            setrlimit(RLIMIT_NOFILE, &limitFD);
            getrlimit(RLIMIT_NOFILE, &limitFD);
        }
        return limitFD.rlim_cur;
    }
    return nMinFD; // getrlimit failed, assume it's fine
#endif
}

/**
 * this function tries to make a particular range of a file allocated (corresponding to disk space)
 * it is advisory, and the range specified in the arguments will never contain live data
 */
void AllocateFileRange(FILE *file, unsigned int offset, unsigned int length) {
#if defined(WIN32)
    // Windows-specific version
    HANDLE hFile = (HANDLE)_get_osfhandle(_fileno(file));
    LARGE_INTEGER nFileSize;
    int64_t nEndPos = (int64_t)offset + length;
    nFileSize.u.LowPart = nEndPos & 0xFFFFFFFF;
    nFileSize.u.HighPart = nEndPos >> 32;
    SetFilePointerEx(hFile, nFileSize, 0, FILE_BEGIN);
    SetEndOfFile(hFile);
#elif defined(MAC_OSX)
    // OSX specific version
    fstore_t fst;
    fst.fst_flags = F_ALLOCATECONTIG;
    fst.fst_posmode = F_PEOFPOSMODE;
    fst.fst_offset = 0;
    fst.fst_length = (off_t)offset + length;
    fst.fst_bytesalloc = 0;
    if (fcntl(fileno(file), F_PREALLOCATE, &fst) == -1) {
        fst.fst_flags = F_ALLOCATEALL;
        fcntl(fileno(file), F_PREALLOCATE, &fst);
    }
    ftruncate(fileno(file), fst.fst_length);
#elif defined(__linux__)
    // Version using posix_fallocate
    off_t nEndPos = (off_t)offset + length;
    posix_fallocate(fileno(file), 0, nEndPos);
#else
    // Fallback version
    // TODO: just write one byte per block
    static const char buf[65536] = {};
    fseek(file, offset, SEEK_SET);
    while (length > 0) {
        unsigned int now = 65536;
        if (length < now)
            now = length;
        fwrite(buf, 1, now, file); // allowed to fail; this function is advisory anyway
        length -= now;
    }
#endif
}

void ShrinkDebugFile()
{
    // Scroll debug.log if it's getting too big
    std::filesystem::path pathLog = GetDataDir() / "debug.log";
    FILE* file = fopen(pathLog.string().c_str(), "r");

    // Get configurable size threshold (default 500MB, min 10MB, max 10GB)
    int64_t nMaxLogSizeMB = GetArg("-maxdebugfilesize", 500); // Default 500MB
    if (nMaxLogSizeMB < 10) nMaxLogSizeMB = 10;       // Minimum 10MB
    if (nMaxLogSizeMB > 2048) nMaxLogSizeMB = 2048; // Maximum 2GB
    int64_t nMaxLogSize = nMaxLogSizeMB * 1000000;

    if (file && std::filesystem::file_size(pathLog) > nMaxLogSize)
    {
        LogPrintf("ShrinkDebugFile: debug.log size is %.1f MB, shrinking to last 50 MB...\n",
                  std::filesystem::file_size(pathLog) / 1000000.0);

        // Keep last 50MB when shrinking (reasonable amount for debugging)
        std::vector <char> vch(50000000,0);
        fseek(file, -((long)vch.size()), SEEK_END);
        int nBytes = fread(begin_ptr(vch), 1, vch.size(), file);
        fclose(file);

        file = fopen(pathLog.string().c_str(), "w");
        if (file)
        {
            fwrite(begin_ptr(vch), 1, nBytes, file);
            fclose(file);
            LogPrintf("ShrinkDebugFile: Shrinking complete, kept %.1f MB\n", nBytes / 1000000.0);
        }
    }
    else if (file != NULL)
        fclose(file);
}

#ifdef WIN32
std::filesystem::path GetSpecialFolderPath(int nFolder, bool fCreate)
{
    namespace fs = std::filesystem;

    char pszPath[MAX_PATH] = "";

    if(SHGetSpecialFolderPathA(NULL, pszPath, nFolder, fCreate))
    {
        return fs::path(pszPath);
    }

    LogPrintf("SHGetSpecialFolderPathA() failed, could not obtain requested path.\n");
    return fs::path("");
}
#endif

std::filesystem::path GetTempPath() {
#if BOOST_FILESYSTEM_VERSION == 3
    return std::filesystem::temp_directory_path();
#else
    // TODO: remove when we don't support filesystem v2 anymore
    std::filesystem::path path;
#ifdef WIN32
    char pszPath[MAX_PATH] = "";

    if (GetTempPathA(MAX_PATH, pszPath))
        path = std::filesystem::path(pszPath);
#else
    path = std::filesystem::path("/tmp");
#endif
    if (path.empty() || !std::filesystem::is_directory(path)) {
        LogPrintf("GetTempPath(): failed to find temp path\n");
        return std::filesystem::path("");
    }
    return path;
#endif
}

void runCommand(const std::string& strCommand)
{
    int nErr = ::system(strCommand.c_str());
    if (nErr)
        LogPrintf("runCommand error: system(%s) returned %d\n", strCommand, nErr);
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    ::prctl(PR_SET_NAME, name, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__))
    pthread_set_name_np(pthread_self(), name);

#elif defined(MAC_OSX)
    pthread_setname_np(name);
#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}

void SetupEnvironment()
{
    // On most POSIX systems (e.g. Linux, but not BSD) the environment's locale
    // may be invalid, in which case the "C" locale is used as fallback.
#if !defined(WIN32) && !defined(MAC_OSX) && !defined(__FreeBSD__) && !defined(__OpenBSD__)
    try {
        std::locale(""); // Raises a runtime error if current locale is invalid
    } catch (const std::runtime_error&) {
        setenv("LC_ALL", "C", 1);
    }
#endif
    // Note: std::filesystem (unlike boost::filesystem) does not require explicit
    // locale initialization as it handles locales internally in a thread-safe manner.
}

bool SetupNetworking()
{
#ifdef WIN32
    // Initialize Windows Sockets
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2,2), &wsadata);
    if (ret != NO_ERROR || LOBYTE(wsadata.wVersion ) != 2 || HIBYTE(wsadata.wVersion) != 2)
        return false;
#endif
    return true;
}

void SetThreadPriority(int nPriority)
{
#ifdef WIN32
    SetThreadPriority(GetCurrentThread(), nPriority);
#else // WIN32
#ifdef PRIO_THREAD
    setpriority(PRIO_THREAD, 0, nPriority);
#else // PRIO_THREAD
    setpriority(PRIO_PROCESS, 0, nPriority);
#endif // PRIO_THREAD
#endif // WIN32
}

std::string PrivacyInfo()
{
    return "\n" +
           FormatParagraph(strprintf(_("In order to ensure you are adequately protecting your privacy when using Flux, please see <%s>."),
                                     "https://github.com/RunOnFlux/fluxd/")) + "\n";
}

std::string VersionInfo()
{
    return "\n" + _("Software Version") + " v" + FormatVersion(CLIENT_VERSION) + "\n";
}

std::string LicenseInfo()
{
    return "\n" +
           FormatParagraph(strprintf(_("Copyright (C) 2009-%i The Bitcoin Core Developers"), COPYRIGHT_YEAR)) + "\n" +
           FormatParagraph(strprintf(_("Copyright (C) 2015-%i The Zcash Developers"), COPYRIGHT_YEAR)) + "\n" +
	   FormatParagraph(strprintf(_("Copyright (C) 2018-%i The Flux Developers"), COPYRIGHT_YEAR)) + "\n" +
           "\n" +
           FormatParagraph(_("This is experimental software.")) + "\n" +
           "\n" +
           FormatParagraph(_("Distributed under the MIT software license, see the accompanying file COPYING or <https://www.opensource.org/licenses/mit-license.php>.")) + "\n" +
           "\n" +
           FormatParagraph(_("This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit <https://www.openssl.org/> and cryptographic software written by Eric Young.")) +
           "\n";
}

int GetNumCores()
{
    return std::thread::hardware_concurrency();
}

// String utility functions to replace boost::algorithm
void ReplaceAll(std::string& str, const std::string& from, const std::string& to)
{
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
}

void ReplaceFirst(std::string& str, const std::string& from, const std::string& to)
{
    if (from.empty()) return;
    size_t pos = str.find(from);
    if (pos != std::string::npos) {
        str.replace(pos, from.length(), to);
    }
}

std::vector<std::string> SplitString(const std::string& str, char delimiter)
{
    std::vector<std::string> result;
    std::string token;
    std::istringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        result.push_back(token);
    }
    return result;
}

std::vector<std::string> SplitStringMulti(const std::string& str, const std::string& delimiters)
{
    std::vector<std::string> result;
    size_t start = 0;
    size_t end = str.find_first_of(delimiters);

    while (end != std::string::npos) {
        // Add token (even if empty, matching Bitcoin Core behavior)
        result.push_back(str.substr(start, end - start));
        start = end + 1;
        end = str.find_first_of(delimiters, start);
    }

    // Add remaining token
    result.push_back(str.substr(start));

    return result;
}

void Trim(std::string& str)
{
    // Trim from start
    size_t start = str.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) {
        str.clear();
        return;
    }

    // Trim from end
    size_t end = str.find_last_not_of(" \t\n\r\f\v");
    str = str.substr(start, end - start + 1);
}

void TrimRight(std::string& str)
{
    size_t end = str.find_last_not_of(" \t\n\r\f\v");
    if (end == std::string::npos) {
        str.clear();
        return;
    }
    str.erase(end + 1);
}

std::string ToLower(const std::string& str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return result;
}

std::string ToUpper(const std::string& str)
{
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c){ return std::toupper(c); });
    return result;
}

std::string GenerateUUID()
{
    // Generate a random UUID v4 (replaces boost::uuids::random_generator)
    // Format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
    // where x is any hexadecimal digit and y is one of 8, 9, A, or B

    static const char* hex_chars = "0123456789abcdef";
    std::string uuid;
    uuid.reserve(36);

    // Use GetRandBytes from random.h for cryptographically secure randomness
    unsigned char random_bytes[16];
    GetRandBytes(random_bytes, 16);

    // Set version (4) and variant bits as per RFC 4122
    random_bytes[6] = (random_bytes[6] & 0x0f) | 0x40;  // Version 4
    random_bytes[8] = (random_bytes[8] & 0x3f) | 0x80;  // Variant is 10

    // Format as UUID string
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            uuid += '-';
        }
        uuid += hex_chars[(random_bytes[i] >> 4) & 0x0f];
        uuid += hex_chars[random_bytes[i] & 0x0f];
    }

    return uuid;
}

bool StartsWith(const std::string& str, const std::string& prefix)
{
    // C++20: Use std::string_view::starts_with() (matching Bitcoin Core)
    return std::string_view(str).starts_with(std::string_view(prefix));
}

bool EndsWith(const std::string& str, const std::string& suffix)
{
    // C++20: Use std::string_view::ends_with() (matching Bitcoin Core)
    return std::string_view(str).ends_with(std::string_view(suffix));
}

bool IStartsWith(const std::string& str, const std::string& prefix)
{
    if (str.size() < prefix.size()) return false;
    return std::equal(prefix.begin(), prefix.end(), str.begin(),
                      [](char a, char b) {
                          return std::tolower(static_cast<unsigned char>(a)) ==
                                 std::tolower(static_cast<unsigned char>(b));
                      });
}

