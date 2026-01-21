// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UTIL_TASK_RUNNER_H
#define BITCOIN_UTIL_TASK_RUNNER_H

#include <functional>
#include <cstddef>

namespace util {

/**
 * @brief Abstract base class for executing callbacks asynchronously.
 *
 * Subclasses implement different execution strategies (immediate, queued, etc.)
 */
class TaskRunnerInterface
{
public:
    virtual ~TaskRunnerInterface() = default;

    /**
     * Insert a callback to be executed.
     * @param func The callback function to execute
     */
    virtual void insert(std::function<void()> func) = 0;

    /**
     * Process all pending callbacks.
     */
    virtual void flush() = 0;

    /**
     * Get the number of pending callbacks.
     * @return Number of callbacks waiting to execute
     */
    virtual size_t size() = 0;
};

/**
 * @brief TaskRunner that executes callbacks immediately (synchronously).
 *
 * Useful for testing or situations where async execution is not needed.
 */
class ImmediateTaskRunner : public TaskRunnerInterface
{
public:
    void insert(std::function<void()> func) override { func(); }
    void flush() override {}
    size_t size() override { return 0; }
};

} // namespace util

#endif // BITCOIN_UTIL_TASK_RUNNER_H
