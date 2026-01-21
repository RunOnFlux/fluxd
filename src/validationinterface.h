// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATIONINTERFACE_H
#define BITCOIN_VALIDATIONINTERFACE_H

#include <memory>

#include "flux/IncrementalMerkleTree.hpp"

class CBlock;
class CBlockIndex;
struct CBlockLocator;
class CReserveScript;
class CTransaction;
class CValidationInterface;
class CValidationState;
class uint256;

namespace util {
class TaskRunnerInterface;
}

// These functions dispatch to one or all registered wallets

/** Register a wallet to receive updates from core */
void RegisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister a wallet from core */
void UnregisterValidationInterface(CValidationInterface* pwalletIn);
/** Unregister all wallets from core */
void UnregisterAllValidationInterfaces();
/** Push an updated transaction to all registered wallets */
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL);

class CValidationInterface {
public:
    virtual ~CValidationInterface() = default;

    // NOTE: These methods were protected in the boost::signals2 version,
    // but need to be public now since CMainSignals calls them directly
    virtual void UpdatedBlockTip(const CBlockIndex *pindex) {}
    virtual void SyncTransaction(const CTransaction &tx, const CBlock *pblock) {}
    virtual void EraseFromWallet(const uint256 &hash) {}
    virtual void ChainTip(const CBlockIndex *pindex, const CBlock *pblock, SproutMerkleTree sproutTree, SaplingMerkleTree saplingTree, bool added) {}
    virtual void SetBestChain(const CBlockLocator &locator) {}
    virtual void UpdatedTransaction(const uint256 &hash) {}
    virtual void Inventory(const uint256 &hash) {}
    virtual void ResendWalletTransactions(int64_t nBestBlockTime) {}
    virtual void BlockChecked(const CBlock&, const CValidationState&) {}
    virtual void GetScriptForMining(std::shared_ptr<CReserveScript>&) {}
    virtual void ResetRequestCount(const uint256 &hash) {}
    virtual void ChainReorg(const CBlockIndex *pindexOldTip, const CBlockIndex *pindexNewTip, const CBlockIndex *pindexFork) {}

    friend void ::RegisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterValidationInterface(CValidationInterface*);
    friend void ::UnregisterAllValidationInterfaces();
};

class ValidationSignalsImpl;

/**
 * Main validation signals dispatcher.
 * Manages callback registration and execution without boost::signals2.
 */
class CMainSignals {
private:
    std::unique_ptr<ValidationSignalsImpl> m_internals;

public:
    /** Initialize with a task runner for async callback execution */
    explicit CMainSignals(std::unique_ptr<util::TaskRunnerInterface> task_runner);
    ~CMainSignals();

    // Delete copy/move to prevent accidental copying
    CMainSignals(const CMainSignals&) = delete;
    CMainSignals& operator=(const CMainSignals&) = delete;

    /** Register callbacks */
    void RegisterCallbacks(std::shared_ptr<CValidationInterface> callbacks);
    /** Unregister callbacks */
    void UnregisterCallbacks(CValidationInterface* callbacks);
    /** Unregister all callbacks */
    void UnregisterAllCallbacks();

    /** Execute a function in the validation interface queue */
    void CallFunctionInValidationInterfaceQueue(std::function<void()> func);

    // Event notification methods
    void UpdatedBlockTip(const CBlockIndex *pindex);
    void SyncTransaction(const CTransaction &tx, const CBlock *pblock);
    void EraseTransaction(const uint256 &hash);
    void UpdatedTransaction(const uint256 &hash);
    void ChainTip(const CBlockIndex *pindex, const CBlock *pblock, SproutMerkleTree sproutTree, SaplingMerkleTree saplingTree, bool added);
    void SetBestChain(const CBlockLocator &locator);
    void Inventory(const uint256 &hash);
    void Broadcast(int64_t nBestBlockTime);
    void BlockChecked(const CBlock& block, const CValidationState& state);
    void ScriptForMining(std::shared_ptr<CReserveScript>& script);
    void BlockFound(const uint256 &hash);
    void ChainReorg(const CBlockIndex *pindexOldTip, const CBlockIndex *pindexNewTip, const CBlockIndex *pindexFork);
};

CMainSignals& GetMainSignals();

#endif // BITCOIN_VALIDATIONINTERFACE_H
