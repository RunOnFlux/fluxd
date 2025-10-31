// Copyright (c) 2016-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCKENCODINGS_H
#define BITCOIN_BLOCKENCODINGS_H

#include "primitives/block.h"
#include "serialize.h"
#include "uint256.h"

#include <vector>

class CTxMemPool;
class CBlockIndex;

// Dumb helper to handle CTransaction compression at serialize-time
struct TransactionCompressor {
private:
    CTransaction& tx;
public:
    TransactionCompressor(CTransaction& txIn) : tx(txIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(tx);
    }
};

// Prefilled transactions in compact blocks
struct PrefilledTransaction {
    // Index offset from last prefilled tx
    uint16_t index;
    CTransaction tx;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint64_t idx = index;
        READWRITE(COMPACTSIZE(idx));
        if (idx > std::numeric_limits<uint16_t>::max())
            throw std::ios_base::failure("index overflowed 16-bit bounds");
        index = (uint16_t)idx;
        READWRITE(REF(TransactionCompressor(tx)));
    }
};

typedef enum ReadStatus_t
{
    READ_STATUS_OK,
    READ_STATUS_INVALID,   // Invalid object, peer is sending bogus data
    READ_STATUS_FAILED,    // Failed to reconstruct block (request full block)
    READ_STATUS_CHECKBLOCK_FAILED // Reconstructed block failed checks
} ReadStatus;

// Main compact block structure (BIP 152)
class CBlockHeaderAndShortTxIDs {
private:
    mutable uint64_t shorttxidk0, shorttxidk1;
    uint64_t nonce;

    void FillShortTxIDSelector() const;

    friend class PartiallyDownloadedBlock;

protected:
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

public:
    static constexpr int SHORTTXIDS_LENGTH = 6;

    CBlockHeader header;

    // Default constructor for deserialization
    CBlockHeaderAndShortTxIDs() : nonce(0), shorttxidk0(0), shorttxidk1(0) {}

    // Construct from a full block
    CBlockHeaderAndShortTxIDs(const CBlock& block, bool fUseWTXID);

    uint64_t GetShortID(const uint256& txhash) const;

    size_t BlockTxCount() const { return shorttxids.size() + prefilledtxn.size(); }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(header);
        READWRITE(nonce);

        uint64_t shorttxids_size = (uint64_t)shorttxids.size();
        READWRITE(COMPACTSIZE(shorttxids_size));
        if (ser_action.ForRead()) {
            size_t shorttxids_size_real = (size_t)shorttxids_size;
            if (shorttxids_size_real > std::numeric_limits<uint16_t>::max())
                throw std::ios_base::failure("indexes overflowed 16 bits");
            shorttxids.resize(shorttxids_size_real);
        }

        for (size_t i = 0; i < shorttxids.size(); i++) {
            uint64_t lsb = shorttxids[i] & 0xffffffffL;
            uint16_t msb = (shorttxids[i] >> 32) & 0xffffL;
            READWRITE(lsb);
            READWRITE(msb);
            shorttxids[i] = (uint64_t(msb) << 32) | uint64_t(lsb);
        }

        READWRITE(prefilledtxn);

        if (ser_action.ForRead())
            FillShortTxIDSelector();
    }
};

// Request for missing transactions
class BlockTransactionsRequest {
public:
    uint256 blockhash;
    std::vector<uint16_t> indexes;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockhash);
        uint64_t indexes_size = (uint64_t)indexes.size();
        READWRITE(COMPACTSIZE(indexes_size));
        if (ser_action.ForRead()) {
            size_t indexes_size_real = (size_t)indexes_size;
            if (indexes_size_real > std::numeric_limits<uint16_t>::max())
                throw std::ios_base::failure("indexes size too large");
            indexes.resize(indexes_size_real);
        }
        for (size_t i = 0; i < indexes.size(); i++) {
            uint64_t index = indexes[i];
            READWRITE(COMPACTSIZE(index));
            if (index > std::numeric_limits<uint16_t>::max())
                throw std::ios_base::failure("index overflowed 16-bit bounds");
            indexes[i] = (uint16_t)index;
        }
    }
};

// Response with missing transactions
class BlockTransactions {
public:
    uint256 blockhash;
    std::vector<CTransaction> txn;

    BlockTransactions() {}
    BlockTransactions(const BlockTransactionsRequest& req) :
        blockhash(req.blockhash), txn(req.indexes.size()) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(blockhash);
        uint64_t txn_size = (uint64_t)txn.size();
        READWRITE(COMPACTSIZE(txn_size));
        if (ser_action.ForRead()) {
            size_t txn_size_real = (size_t)txn_size;
            txn.resize(txn_size_real);
        }
        for (size_t i = 0; i < txn.size(); i++)
            READWRITE(REF(TransactionCompressor(txn[i])));
    }
};

// Helper for reconstructing blocks from compact blocks + mempool
class PartiallyDownloadedBlock {
protected:
    std::vector<CTransaction> txn_available;
    size_t prefilled_count;
    size_t mempool_count;
    CTxMemPool* pool;

public:
    CBlockHeader header;

    explicit PartiallyDownloadedBlock(CTxMemPool* poolIn) :
        prefilled_count(0), mempool_count(0), pool(poolIn) {}

    ReadStatus InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<uint256, CTransaction>>& extra_txn = std::vector<std::pair<uint256, CTransaction>>());
    bool IsTxAvailable(size_t index) const;
    ReadStatus FillBlock(CBlock& block, const std::vector<CTransaction>& vtx_missing);
};

#endif // BITCOIN_BLOCKENCODINGS_H
