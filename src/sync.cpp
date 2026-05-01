// Copyright (c) 2011-2012 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "sync.h"

#include "util.h"
#include "utilstrencodings.h"

#include <stdio.h>
#include <mutex>


#ifdef DEBUG_LOCKCONTENTION
void PrintLockContention(const char* pszName, const char* pszFile, int nLine)
{
    LogPrintf("LOCKCONTENTION: %s\n", pszName);
    LogPrintf("Locker: %s:%d\n", pszFile, nLine);
}
#endif /* DEBUG_LOCKCONTENTION */

#ifdef DEBUG_LOCKORDER
//
// Early deadlock detection.
// Problem being solved:
//    Thread 1 locks  A, then B, then C
//    Thread 2 locks  D, then C, then A
//     --> may result in deadlock between the two threads, depending on when they run.
// Solution implemented here:
// Keep track of pairs of locks: (A before B), (A before C), etc.
// Complain if any thread tries to lock in a different order.
//

struct CLockLocation {
    CLockLocation(const char* pszName, const char* pszFile, int nLine, bool fTryIn)
    {
        mutexName = pszName;
        sourceFile = pszFile;
        sourceLine = nLine;
        fTry = fTryIn;
    }

    std::string ToString() const
    {
        return mutexName + "  " + sourceFile + ":" + itostr(sourceLine) + (fTry ? " (TRY)" : "");
    }

    std::string MutexName() const { return mutexName; }

    bool fTry;
private:
    std::string mutexName;
    std::string sourceFile;
    int sourceLine;
};

typedef std::vector<std::pair<void*, CLockLocation> > LockStack;

static std::mutex dd_mutex;
static std::map<std::pair<void*, void*>, LockStack> lockorders;
thread_local std::unique_ptr<LockStack> lockstack;


static void potential_deadlock_detected(const std::pair<void*, void*>& mismatch, const LockStack& s1, const LockStack& s2)
{
    // We attempt to not assert on probably-not deadlocks by assuming that
    // a try lock will immediately have otherwise bailed if it had
    // failed to get the lock
    // We do this by, for the locks which triggered the potential deadlock,
    // in either lockorder, checking that the second of the two which is locked
    // is only a TRY_LOCK, ignoring locks if they are reentrant.
    bool firstLocked = false;
    bool secondLocked = false;
    bool onlyMaybeDeadlock = false;

    LogPrintf("POTENTIAL DEADLOCK DETECTED\n");
    LogPrintf("Previous lock order was:\n");
    for (const auto& [lockPtr, lockLoc] :s2) {
        if (lockPtr == mismatch.first) {
            LogPrintf(" (1)");
            if (!firstLocked && secondLocked && lockLoc.fTry)
                onlyMaybeDeadlock = true;
            firstLocked = true;
        }
        if (lockPtr == mismatch.second) {
            LogPrintf(" (2)");
            if (!secondLocked && firstLocked && lockLoc.fTry)
                onlyMaybeDeadlock = true;
            secondLocked = true;
        }
        LogPrintf(" %s\n", lockLoc.ToString());
    }
    firstLocked = false;
    secondLocked = false;
    LogPrintf("Current lock order is:\n");
    for (const auto& [lockPtr, lockLoc] :s1) {
        if (lockPtr == mismatch.first) {
            LogPrintf(" (1)");
            if (!firstLocked && secondLocked && lockLoc.fTry)
                onlyMaybeDeadlock = true;
            firstLocked = true;
        }
        if (lockPtr == mismatch.second) {
            LogPrintf(" (2)");
            if (!secondLocked && firstLocked && lockLoc.fTry)
                onlyMaybeDeadlock = true;
            secondLocked = true;
        }
        LogPrintf(" %s\n", lockLoc.ToString());
    }
    assert(onlyMaybeDeadlock);
}

static void push_lock(void* c, const CLockLocation& locklocation, bool fTry)
{
    if (lockstack.get() == NULL)
        lockstack.reset(new LockStack);

    dd_mutex.lock();

    (*lockstack).push_back(std::make_pair(c, locklocation));

    if (!fTry) {
        for (const auto& [lockPtr, lockLoc] :(*lockstack)) {
            if (lockPtr == c)
                break;

            std::pair<void*, void*> p1 = std::make_pair(lockPtr, c);
            if (lockorders.count(p1))
                continue;
            lockorders[p1] = (*lockstack);

            std::pair<void*, void*> p2 = std::make_pair(c, lockPtr);
            if (lockorders.count(p2))
                potential_deadlock_detected(p1, lockorders[p2], lockorders[p1]);
        }
    }
    dd_mutex.unlock();
}

static void pop_lock()
{
    dd_mutex.lock();
    (*lockstack).pop_back();
    dd_mutex.unlock();
}

void EnterCritical(const char* pszName, const char* pszFile, int nLine, void* cs, bool fTry)
{
    push_lock(cs, CLockLocation(pszName, pszFile, nLine, fTry), fTry);
}

void LeaveCritical()
{
    pop_lock();
}

std::string LocksHeld()
{
    std::string result;
    for (const auto& [lockPtr, lockLoc] :*lockstack)
        result += lockLoc.ToString() + std::string("\n");
    return result;
}

void AssertLockHeldInternal(const char* pszName, const char* pszFile, int nLine, void* cs)
{
    for (const auto& [lockPtr, lockLoc] :*lockstack)
        if (lockPtr == cs)
            return;
    fprintf(stderr, "Assertion failed: lock %s not held in %s:%i; locks held:\n%s", pszName, pszFile, nLine, LocksHeld().c_str());
    abort();
}

#endif /* DEBUG_LOCKORDER */
