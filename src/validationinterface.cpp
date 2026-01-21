// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "validationinterface.h"
#include "sync.h"
#include "util/task_runner.h"
#include "primitives/transaction.h"
#include "primitives/block.h"
#include "chain.h"
#include "consensus/validation.h"

#include <list>
#include <unordered_map>
#include <memory>
#include <functional>

/**
 * ValidationSignalsImpl manages callback registration and execution.
 * Uses reference counting to safely handle callbacks being unregistered during execution.
 */
class ValidationSignalsImpl
{
private:
    CCriticalSection m_mutex;

    //! List entry with reference counting
    //! count = 1 (registered only) + N (number of active executions)
    struct ListEntry {
        std::shared_ptr<CValidationInterface> callbacks;
        int count = 1;
    };

    std::list<ListEntry> m_list;  // Preserves order
    std::unordered_map<CValidationInterface*, std::list<ListEntry>::iterator> m_map;  // Fast lookup

public:
    std::unique_ptr<util::TaskRunnerInterface> m_task_runner;

    explicit ValidationSignalsImpl(std::unique_ptr<util::TaskRunnerInterface> task_runner)
        : m_task_runner(std::move(task_runner)) {}

    /**
     * Register a new callback.
     */
    void Register(std::shared_ptr<CValidationInterface> callbacks)
    {
        LOCK(m_mutex);
        auto inserted = m_map.emplace(callbacks.get(), m_list.end());
        if (inserted.second) {
            // First time registering, add to list
            inserted.first->second = m_list.emplace(m_list.end());
        }
        inserted.first->second->callbacks = std::move(callbacks);
    }

    /**
     * Unregister a callback.
     * If the callback is currently executing, it will be removed after execution completes.
     */
    void Unregister(CValidationInterface* callbacks)
    {
        LOCK(m_mutex);
        auto it = m_map.find(callbacks);
        if (it != m_map.end()) {
            // Decrement count and erase from list only if not executing
            if (!--it->second->count) {
                m_list.erase(it->second);
            }
            m_map.erase(it);
        }
    }

    /**
     * Unregister all callbacks.
     */
    void Clear()
    {
        LOCK(m_mutex);
        for (const auto& entry : m_map) {
            // Decrement count and erase from list only if not executing
            if (!--entry.second->count) {
                m_list.erase(entry.second);
            }
        }
        m_map.clear();
    }

    /**
     * Iterate over all callbacks, safely handling unregistration during iteration.
     *
     * @param f Function to execute on each callback
     */
    template<typename F>
    void Iterate(F&& f)
    {
        LOCK(m_mutex);
        for (auto it = m_list.begin(); it != m_list.end();) {
            ++it->count;  // Mark as executing
            {
                // Release lock during callback execution
                LEAVE_CRITICAL_SECTION(m_mutex);
                f(*it->callbacks);
                ENTER_CRITICAL_SECTION(m_mutex);
            }
            // After execution, decrement and cleanup if unregistered
            it = --it->count ? std::next(it) : m_list.erase(it);
        }
    }
};

//! Global validation signals instance
static CMainSignals* g_signals = nullptr;

CMainSignals::CMainSignals(std::unique_ptr<util::TaskRunnerInterface> task_runner)
    : m_internals(std::make_unique<ValidationSignalsImpl>(std::move(task_runner)))
{
}

CMainSignals::~CMainSignals() = default;

void CMainSignals::RegisterCallbacks(std::shared_ptr<CValidationInterface> callbacks)
{
    m_internals->Register(std::move(callbacks));
}

void CMainSignals::UnregisterCallbacks(CValidationInterface* callbacks)
{
    m_internals->Unregister(callbacks);
}

void CMainSignals::UnregisterAllCallbacks()
{
    m_internals->Clear();
}

void CMainSignals::CallFunctionInValidationInterfaceQueue(std::function<void()> func)
{
    m_internals->m_task_runner->insert(std::move(func));
}

void CMainSignals::UpdatedBlockTip(const CBlockIndex *pindex)
{
    auto event = [this, pindex] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.UpdatedBlockTip(pindex);
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::SyncTransaction(const CTransaction &tx, const CBlock *pblock)
{
    // Make shared_ptr copies to extend lifetime
    auto ptx = std::make_shared<CTransaction>(tx);
    auto pblockCopy = pblock ? std::make_shared<CBlock>(*pblock) : nullptr;

    auto event = [this, ptx, pblockCopy] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.SyncTransaction(*ptx, pblockCopy.get());
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::EraseTransaction(const uint256 &hash)
{
    auto event = [this, hash] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.EraseFromWallet(hash);
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::UpdatedTransaction(const uint256 &hash)
{
    auto event = [this, hash] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.UpdatedTransaction(hash);
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::ChainTip(const CBlockIndex *pindex, const CBlock *pblock,
                             SproutMerkleTree sproutTree, SaplingMerkleTree saplingTree, bool added)
{
    auto event = [this, pindex, pblock, sproutTree, saplingTree, added] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.ChainTip(pindex, pblock, sproutTree, saplingTree, added);
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::SetBestChain(const CBlockLocator &locator)
{
    // Make copy to extend lifetime
    auto locatorCopy = std::make_shared<CBlockLocator>(locator);

    auto event = [this, locatorCopy] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.SetBestChain(*locatorCopy);
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::Inventory(const uint256 &hash)
{
    auto event = [this, hash] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.Inventory(hash);
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::Broadcast(int64_t nBestBlockTime)
{
    auto event = [this, nBestBlockTime] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.ResendWalletTransactions(nBestBlockTime);
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::BlockChecked(const CBlock& block, const CValidationState& state)
{
    // Make copies to extend lifetime
    auto pblock = std::make_shared<CBlock>(block);
    auto pstate = std::make_shared<CValidationState>(state);

    auto event = [this, pblock, pstate] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.BlockChecked(*pblock, *pstate);
        });
    };
    m_internals->m_task_runner->insert(event);
}

void CMainSignals::ScriptForMining(std::shared_ptr<CReserveScript>& script)
{
    // This one is synchronous - we need the result immediately
    m_internals->Iterate([&](CValidationInterface& callbacks) {
        callbacks.GetScriptForMining(script);
    });
}

void CMainSignals::BlockFound(const uint256 &hash)
{
    auto event = [this, hash] {
        m_internals->Iterate([&](CValidationInterface& callbacks) {
            callbacks.ResetRequestCount(hash);
        });
    };
    m_internals->m_task_runner->insert(event);
}

CMainSignals& GetMainSignals()
{
    // Initialize on first use with immediate task runner
    if (!g_signals) {
        g_signals = new CMainSignals(std::make_unique<util::ImmediateTaskRunner>());
    }
    return *g_signals;
}

void RegisterValidationInterface(CValidationInterface* pwalletIn)
{
    // Wrap raw pointer in shared_ptr with no-op deleter since we don't own it
    auto shared = std::shared_ptr<CValidationInterface>(pwalletIn, [](CValidationInterface*){});
    GetMainSignals().RegisterCallbacks(std::move(shared));
}

void UnregisterValidationInterface(CValidationInterface* pwalletIn)
{
    GetMainSignals().UnregisterCallbacks(pwalletIn);
}

void UnregisterAllValidationInterfaces()
{
    GetMainSignals().UnregisterAllCallbacks();
}

void SyncWithWallets(const CTransaction& tx, const CBlock* pblock)
{
    GetMainSignals().SyncTransaction(tx, pblock);
}
