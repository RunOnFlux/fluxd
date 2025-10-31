// Copyright (c) 2016-2022 The Bitcoin Core developers
// Copyright (c) 2024 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "blockencodings.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "crypto/sha256.h"
#include "crypto/siphash.h"
#include "main.h"
#include "random.h"
#include "streams.h"
#include "txmempool.h"
#include "util.h"

#include <unordered_map>

CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock& block, bool fUseWTXID) :
        nonce(GetRand(std::numeric_limits<uint64_t>::max())),
        shorttxids(block.vtx.size() - 1), prefilledtxn(1), header(block) {
    FillShortTxIDSelector();

    // Coinbase is always prefilled (index 0)
    prefilledtxn[0] = {0, block.vtx[0]};

    // Create short IDs for remaining transactions
    for (size_t i = 1; i < block.vtx.size(); i++) {
        const CTransaction& tx = block.vtx[i];
        // Flux doesn't have SegWit, so we always use regular TXID
        shorttxids[i - 1] = GetShortID(tx.GetHash());
    }
}

void CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() const {
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << header << nonce;
    CSHA256 hasher;
    hasher.Write((unsigned char*)&stream[0], stream.size());
    uint256 shorttxidhash;
    hasher.Finalize((unsigned char*)&shorttxidhash);
    shorttxidk0 = shorttxidhash.GetUint64(0);
    shorttxidk1 = shorttxidhash.GetUint64(1);
}

uint64_t CBlockHeaderAndShortTxIDs::GetShortID(const uint256& txhash) const {
    static_assert(SHORTTXIDS_LENGTH == 6, "shorttxids calculation assumes 6-byte shorttxids");
    return SipHashUint256(shorttxidk0, shorttxidk1, txhash) & 0xffffffffffffL;
}

ReadStatus PartiallyDownloadedBlock::InitData(const CBlockHeaderAndShortTxIDs& cmpctblock, const std::vector<std::pair<uint256, CTransaction>>& extra_txn)
{
    if (cmpctblock.header.IsNull() || (cmpctblock.shorttxids.empty() && cmpctblock.prefilledtxn.empty()))
        return READ_STATUS_INVALID;

    // Sanity check on transaction count
    if (cmpctblock.shorttxids.size() + cmpctblock.prefilledtxn.size() > MAX_BLOCK_SIZE / 100)
        return READ_STATUS_INVALID;

    if (!header.IsNull() || !txn_available.empty())
        return READ_STATUS_INVALID;

    header = cmpctblock.header;
    txn_available.resize(cmpctblock.BlockTxCount());

    // Fill in prefilled transactions
    int32_t lastprefilledindex = -1;
    for (size_t i = 0; i < cmpctblock.prefilledtxn.size(); i++) {
        if (cmpctblock.prefilledtxn[i].tx.IsNull())
            return READ_STATUS_INVALID;

        lastprefilledindex += cmpctblock.prefilledtxn[i].index + 1;
        if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
            return READ_STATUS_INVALID;
        if ((uint32_t)lastprefilledindex > cmpctblock.shorttxids.size() + i)
            return READ_STATUS_INVALID;

        txn_available[lastprefilledindex] = cmpctblock.prefilledtxn[i].tx;
    }
    prefilled_count = cmpctblock.prefilledtxn.size();

    // Build map of short IDs to indexes
    std::unordered_map<uint64_t, uint16_t> shorttxids(cmpctblock.shorttxids.size());
    uint16_t index_offset = 0;
    for (size_t i = 0; i < cmpctblock.shorttxids.size(); i++) {
        while (txn_available[i + index_offset].IsNull() == false)
            index_offset++;
        shorttxids[cmpctblock.shorttxids[i]] = i + index_offset;

        // Detect hash collision attacks
        if (shorttxids.bucket_size(shorttxids.bucket(cmpctblock.shorttxids[i])) > 12)
            return READ_STATUS_FAILED;
    }

    // Check for short ID collision
    if (shorttxids.size() != cmpctblock.shorttxids.size())
        return READ_STATUS_FAILED;

    std::vector<bool> have_txn(txn_available.size());

    // Try to fill transactions from mempool
    // Flux uses indexed_transaction_set (boost::multi_index) instead of std::map
    {
        LOCK(pool->cs);
        // Iterate through Flux's mempool structure
        for (CTxMemPool::indexed_transaction_set::iterator it = pool->mapTx.begin();
             it != pool->mapTx.end(); ++it) {
            const CTransaction& tx = it->GetTx();
            uint64_t shortid = cmpctblock.GetShortID(tx.GetHash());
            std::unordered_map<uint64_t, uint16_t>::iterator idit = shorttxids.find(shortid);
            if (idit != shorttxids.end()) {
                if (!have_txn[idit->second]) {
                    txn_available[idit->second] = tx;
                    have_txn[idit->second] = true;
                    mempool_count++;
                } else {
                    // Collision - clear the transaction (request it instead)
                    txn_available[idit->second] = CTransaction();
                    mempool_count--;
                }
            }

            // Early exit optimization
            if (mempool_count == shorttxids.size())
                break;
        }
    }

    // Try to fill transactions from extra transaction pool
    size_t extra_count = 0;
    for (size_t i = 0; i < extra_txn.size(); i++) {
        const CTransaction& tx = extra_txn[i].second;
        if (tx.IsNull()) continue; // Skip empty entries in ring buffer

        uint64_t shortid = cmpctblock.GetShortID(tx.GetHash());
        std::unordered_map<uint64_t, uint16_t>::iterator idit = shorttxids.find(shortid);
        if (idit != shorttxids.end()) {
            if (!have_txn[idit->second]) {
                txn_available[idit->second] = tx;
                have_txn[idit->second] = true;
                extra_count++;
            }
            // Note: we don't handle collisions here since mempool already checked
        }

        // Early exit if we've found everything
        if (mempool_count + extra_count == shorttxids.size())
            break;
    }

    LogPrint("cmpctblock", "Initialized PartiallyDownloadedBlock for %s using cmpctblock: %u prefilled, %u from mempool, %u from extra pool, %u missing\n",
             cmpctblock.header.GetHash().ToString(), prefilled_count, mempool_count, extra_count, shorttxids.size() - mempool_count - extra_count);

    return READ_STATUS_OK;
}

bool PartiallyDownloadedBlock::IsTxAvailable(size_t index) const {
    assert(!header.IsNull());
    if (index >= txn_available.size())
        return false;
    return !txn_available[index].IsNull();
}

ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock& block, const std::vector<CTransaction>& vtx_missing) {
    assert(!header.IsNull());
    block = CBlock(header);

    size_t tx_missing_offset = 0;
    for (size_t i = 0; i < txn_available.size(); i++) {
        if (!txn_available[i].IsNull()) {
            block.vtx.push_back(txn_available[i]);
        } else {
            if (vtx_missing.size() <= tx_missing_offset)
                return READ_STATUS_FAILED;
            block.vtx.push_back(vtx_missing[tx_missing_offset++]);
        }
    }

    // Check we used all provided missing transactions
    if (vtx_missing.size() != tx_missing_offset)
        return READ_STATUS_FAILED;

    // Verify block hash matches
    if (block.GetHash() != header.GetHash())
        return READ_STATUS_FAILED;

    LogPrint("cmpctblock", "Successfully reconstructed block %s (%u transactions: %u prefilled, %u from mempool, %u requested)\n",
             block.GetHash().ToString(), block.vtx.size(), prefilled_count, mempool_count, vtx_missing.size());

    return READ_STATUS_OK;
}
