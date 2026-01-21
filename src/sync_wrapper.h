// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SYNC_WRAPPER_H
#define BITCOIN_SYNC_WRAPPER_H

#include <mutex>
#include <utility>

/**
 * Simple thread-safe value wrapper to replace boost::synchronized_value
 * Provides synchronized access to a value using std::mutex
 */
template<typename T>
class synchronized_value {
private:
    mutable std::mutex mtx;
    T value;

public:
    // Helper class for synchronized access (replaces boost::strict_lock_ptr)
    class lock_ptr {
    private:
        std::unique_lock<std::mutex> lock;
        T* ptr;

    public:
        lock_ptr(std::mutex& m, T& v) : lock(m), ptr(&v) {}

        T* operator->() { return ptr; }
        T& operator*() { return *ptr; }
        const T* operator->() const { return ptr; }
        const T& operator*() const { return *ptr; }
    };

    synchronized_value() = default;
    synchronized_value(const T& val) : value(val) {}
    synchronized_value(T&& val) : value(std::move(val)) {}

    // Get synchronized access
    lock_ptr synchronize() {
        return lock_ptr(mtx, value);
    }

    // Assignment operator for simple types
    synchronized_value& operator=(const T& val) {
        std::lock_guard<std::mutex> lock(mtx);
        value = val;
        return *this;
    }

    // Get value (creates copy under lock)
    T get() const {
        std::lock_guard<std::mutex> lock(mtx);
        return value;
    }
};

#endif // BITCOIN_SYNC_WRAPPER_H
