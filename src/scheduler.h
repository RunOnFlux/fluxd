// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCHEDULER_H
#define BITCOIN_SCHEDULER_H

//
// NOTE:
// Using C++17 - std::thread and boost::chrono migrated to std equivalents
//
#include <functional>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <map>

//
// Simple class for background tasks that should be run
// periodically or once "after a while"
//
// Usage:
//
// CScheduler* s = new CScheduler();
// s->scheduleFromNow(doSomething, 11); // Assuming a: void doSomething() { }
// s->scheduleFromNow([&]() { this->func(argument); }, 3);
// std::thread t([&]() { s->serviceQueue(); });
//
// ... then at program shutdown, clean up the thread running serviceQueue:
// s->stop();
// t.join();
// delete s; // Must be done after thread is stopped/joined.
//

class CScheduler
{
public:
    CScheduler();
    ~CScheduler();

    typedef std::function<void(void)> Function;

    // Call func at/after time t
    void schedule(Function f, std::chrono::system_clock::time_point t);

    // Convenience method: call f once deltaSeconds from now
    void scheduleFromNow(Function f, int64_t deltaSeconds);

    // Another convenience method: call f approximately
    // every deltaSeconds forever, starting deltaSeconds from now.
    // To be more precise: every time f is finished, it
    // is rescheduled to run deltaSeconds later. If you
    // need more accurate scheduling, don't use this method.
    void scheduleEvery(Function f, int64_t deltaSeconds);

    // To keep things as simple as possible, there is no unschedule.

    // Services the queue 'forever'. Should be run in a thread,
    // and stopped using stop()
    void serviceQueue();

    // Tell any threads running serviceQueue to stop as soon as they're
    // done servicing whatever task they're currently servicing (drain=false)
    // or when there is no work left to be done (drain=true)
    void stop(bool drain=false);

    // Returns number of tasks waiting to be serviced,
    // and first and last task times
    size_t getQueueInfo(std::chrono::system_clock::time_point &first,
                        std::chrono::system_clock::time_point &last) const;

private:
    std::multimap<std::chrono::system_clock::time_point, Function> taskQueue;
    std::condition_variable newTaskScheduled;
    mutable std::mutex newTaskMutex;
    int nThreadsServicingQueue;
    bool stopRequested;
    bool stopWhenEmpty;
    bool shouldStop() { return stopRequested || (stopWhenEmpty && taskQueue.empty()); }
};

#endif
