// Copyright (c) 2016-present The Bitcoin Core developers
// Copyright (c) 2025 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FLUX_UTIL_THREADINTERRUPT_H
#define FLUX_UTIL_THREADINTERRUPT_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>

/**
 * A helper class for interruptible sleeps. Calling operator() will interrupt
 * any current sleep, and after that point operator bool() will return true
 * until reset.
 */
class CThreadInterrupt
{
public:
    using Clock = std::chrono::steady_clock;

    CThreadInterrupt();
    virtual ~CThreadInterrupt() = default;

    /// Return true if operator()() has been called.
    bool interrupted() const;

    /// An alias for interrupted().
    explicit operator bool() const;

    /// Interrupt any sleeps. After this interrupted() will return true.
    void operator()();

    /// Reset to a non-interrupted state.
    void reset();

    /// Sleep for the given duration.
    /// @retval true The time passed.
    /// @retval false The sleep was interrupted.
    bool sleep_for(Clock::duration rel_time);

private:
    std::condition_variable cond;
    std::mutex mut;
    std::atomic<bool> flag;
};

#endif // FLUX_UTIL_THREADINTERRUPT_H
