// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "zmqpublishnotifier.h"
#include "main.h"
#include "util.h"
#include "fluxnode/fluxnode.h"
#include "streams.h"

static std::multimap<std::string, CZMQAbstractPublishNotifier*> mapPublishNotifiers;

static const char *MSG_HASHBLOCK = "hashblock";
static const char *MSG_HASHTX    = "hashtx";
static const char *MSG_RAWBLOCK  = "rawblock";
static const char *MSG_RAWTX     = "rawtx";
static const char *MSG_CHECKEDBLOCK = "checkedblock";
static const char *MSG_HASHBLOCKHEIGHT = "hashblockheight";
static const char *MSG_CHAINREORG = "chainreorg";
static const char *MSG_FLUXNODELISTDELTA = "fluxnodelistdelta";

// Internal function to send multipart message
static int zmq_send_multipart(void *sock, const void* data, size_t size, ...)
{
    va_list args;
    va_start(args, size);

    while (1)
    {
        zmq_msg_t msg;

        int rc = zmq_msg_init_size(&msg, size);
        if (rc != 0)
        {
            zmqError("Unable to initialize ZMQ msg");
            return -1;
        }

        void *buf = zmq_msg_data(&msg);
        memcpy(buf, data, size);

        data = va_arg(args, const void*);

        rc = zmq_msg_send(&msg, sock, data ? ZMQ_SNDMORE : 0);
        if (rc == -1)
        {
            zmqError("Unable to send ZMQ msg");
            zmq_msg_close(&msg);
            return -1;
        }

        zmq_msg_close(&msg);

        if (!data)
            break;

        size = va_arg(args, size_t);
    }
    return 0;
}

bool CZMQAbstractPublishNotifier::Initialize(void *pcontext)
{
    assert(!psocket);

    // check if address is being used by other publish notifier
    std::multimap<std::string, CZMQAbstractPublishNotifier*>::iterator i = mapPublishNotifiers.find(address);

    if (i==mapPublishNotifiers.end())
    {
        psocket = zmq_socket(pcontext, ZMQ_PUB);
        if (!psocket)
        {
            zmqError("Failed to create socket");
            return false;
        }

        int rc = zmq_bind(psocket, address.c_str());
        if (rc!=0)
        {
            zmqError("Failed to bind address");
            zmq_close(psocket);
            return false;
        }

        // register this notifier for the address, so it can be reused for other publish notifier
        mapPublishNotifiers.insert(std::make_pair(address, this));
        return true;
    }
    else
    {
        LogPrint("zmq", "zmq: Reusing socket for address %s\n", address);

        psocket = i->second->psocket;
        mapPublishNotifiers.insert(std::make_pair(address, this));

        return true;
    }
}

void CZMQAbstractPublishNotifier::Shutdown()
{
    assert(psocket);

    int count = mapPublishNotifiers.count(address);

    // remove this notifier from the list of publishers using this address
    typedef std::multimap<std::string, CZMQAbstractPublishNotifier*>::iterator iterator;
    std::pair<iterator, iterator> iterpair = mapPublishNotifiers.equal_range(address);

    for (iterator it = iterpair.first; it != iterpair.second; ++it)
    {
        if (it->second==this)
        {
            mapPublishNotifiers.erase(it);
            break;
        }
    }

    if (count == 1)
    {
        LogPrint("zmq", "Close socket at address %s\n", address);
        int linger = 0;
        zmq_setsockopt(psocket, ZMQ_LINGER, &linger, sizeof(linger));
        zmq_close(psocket);
    }

    psocket = 0;
}

bool CZMQAbstractPublishNotifier::SendMessage(const char *command, const void* data, size_t size)
{
    assert(psocket);

    /* send three parts, command & data & a LE 4byte sequence number */
    unsigned char msgseq[sizeof(uint32_t)];
    WriteLE32(&msgseq[0], nSequence);
    int rc = zmq_send_multipart(psocket, command, strlen(command), data, size, msgseq, (size_t)sizeof(uint32_t), (void*)0);
    if (rc == -1)
        return false;

    /* increment memory only sequence number after sending */
    nSequence++;

    return true;
}

bool CZMQPublishHashBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    uint256 hash = pindex->GetBlockHash();
    LogPrint("zmq", "zmq: Publish hashblock %s\n", hash.GetHex());
    char data[32];
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hash.begin()[i];
    return SendMessage(MSG_HASHBLOCK, data, 32);
}

bool CZMQPublishHashTransactionNotifier::NotifyTransaction(const CTransaction &transaction)
{
    uint256 hash = transaction.GetHash();
    LogPrint("zmq", "zmq: Publish hashtx %s\n", hash.GetHex());
    char data[32];
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hash.begin()[i];
    return SendMessage(MSG_HASHTX, data, 32);
}

bool CZMQPublishRawBlockNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    LogPrint("zmq", "zmq: Publish rawblock %s\n", pindex->GetBlockHash().GetHex());

    const Consensus::Params& consensusParams = Params().GetConsensus();
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    {
        LOCK(cs_main);
        CBlock block;
        if(!ReadBlockFromDisk(block, pindex, consensusParams))
        {
            zmqError("Can't read block from disk");
            return false;
        }

        ss << block;
    }

    return SendMessage(MSG_RAWBLOCK, &(*ss.begin()), ss.size());
}

bool CZMQPublishCheckedBlockNotifier::NotifyBlock(const CBlock& block)
{
    LogPrint("zmq", "zmq: Publish checkedblock %s\n", block.GetHash().GetHex());

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    {
        LOCK(cs_main);
        ss << block;
    }

    return SendMessage(MSG_CHECKEDBLOCK, &(*ss.begin()), ss.size());
}

bool CZMQPublishRawTransactionNotifier::NotifyTransaction(const CTransaction &transaction)
{
    uint256 hash = transaction.GetHash();
    LogPrint("zmq", "zmq: Publish rawtx %s\n", hash.GetHex());
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << transaction;
    return SendMessage(MSG_RAWTX, &(*ss.begin()), ss.size());
}

bool CZMQPublishHashBlockHeightNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    uint256 hash = pindex->GetBlockHash();
    LogPrint("zmq", "zmq: Publish hashblockheight %s height %d\n", hash.GetHex(), pindex->nHeight);
    unsigned char data[36];

    // Hash (reversed for display)
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hash.begin()[i];

    // Height (little-endian)
    WriteLE32(&data[32], (uint32_t)pindex->nHeight);

    return SendMessage(MSG_HASHBLOCKHEIGHT, data, 36);
}

bool CZMQPublishChainReorgNotifier::NotifyChainReorg(const CBlockIndex *pindexOldTip, const CBlockIndex *pindexNewTip, const CBlockIndex *pindexFork)
{
    if (!pindexOldTip || !pindexNewTip || !pindexFork) {
        LogPrint("zmq", "zmq: ChainReorg notification skipped (null pointer)\n");
        return true;
    }

    uint256 hashOldTip = pindexOldTip->GetBlockHash();
    uint256 hashNewTip = pindexNewTip->GetBlockHash();
    uint256 hashFork = pindexFork->GetBlockHash();

    LogPrint("zmq", "zmq: Publish chainreorg old_height=%d new_height=%d fork_height=%d\n",
             pindexOldTip->nHeight, pindexNewTip->nHeight, pindexFork->nHeight);

    unsigned char data[108];

    // Old tip hash (reversed for display byte order)
    for (unsigned int i = 0; i < 32; i++)
        data[31 - i] = hashOldTip.begin()[i];

    // Old tip height (little-endian)
    WriteLE32(&data[32], (uint32_t)pindexOldTip->nHeight);

    // New tip hash (reversed for display byte order)
    for (unsigned int i = 0; i < 32; i++)
        data[67 - i] = hashNewTip.begin()[i];

    // New tip height (little-endian)
    WriteLE32(&data[68], (uint32_t)pindexNewTip->nHeight);

    // Fork hash (reversed for display byte order)
    for (unsigned int i = 0; i < 32; i++)
        data[103 - i] = hashFork.begin()[i];

    // Fork point height (little-endian)
    WriteLE32(&data[104], (uint32_t)pindexFork->nHeight);

    return SendMessage(MSG_CHAINREORG, data, 108);
}

bool CZMQPublishFluxNodeListNotifier::NotifyBlock(const CBlockIndex *pindex)
{
    if (!fInitialized) {
        // First block after daemon start - skip delta
        // (Client uses RPC for initial state, not first delta)
        g_fluxnodeDelta.Clear();
        nLastDeltaHeight = pindex->nHeight;
        fInitialized = true;
        LogPrint("zmq", "zmq: FluxNode delta initialized at height %d (skipping first delta)\n", pindex->nHeight);
        return true;
    }

    return SendDelta(nLastDeltaHeight, pindex->nHeight, pindex);
}

bool CZMQPublishFluxNodeListNotifier::SendDelta(int nFromHeight, int nToHeight, const CBlockIndex *pindexTo)
{
    // Get block indices for from and to heights
    CBlockIndex *pindexFrom = chainActive[nFromHeight];
    if (!pindexFrom || !pindexTo) {
        LogPrint("zmq", "zmq: FluxNode delta skipped (null block index)\n");
        return false;
    }

    uint256 hashFrom = pindexFrom->GetBlockHash();
    uint256 hashTo = pindexTo->GetBlockHash();

    // Build delta message from tracked changes
    // Format: from_height (4) + to_height (4) + from_hash (32) + to_hash (32) + node data
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << (uint32_t)nFromHeight;
    ss << (uint32_t)nToHeight;

    // From block hash (reversed for display byte order)
    unsigned char from_hash_bytes[32];
    for (unsigned int i = 0; i < 32; i++)
        from_hash_bytes[31 - i] = hashFrom.begin()[i];
    ss.write((const char*)from_hash_bytes, 32);

    // To block hash (reversed for display byte order)
    unsigned char to_hash_bytes[32];
    for (unsigned int i = 0; i < 32; i++)
        to_hash_bytes[31 - i] = hashTo.begin()[i];
    ss.write((const char*)to_hash_bytes, 32);

    {
        LOCK(g_fluxnodeDelta.cs);

        // Serialize added nodes (full data)
        WriteCompactSize(ss, g_fluxnodeDelta.mapAdded.size());
        for (const auto& item : g_fluxnodeDelta.mapAdded) {
            const COutPoint& outpoint = item.first;
            const FluxnodeCacheData& data = item.second;
            ss << outpoint << data.collateralPubkey << data.pubKey
               << (uint32_t)data.nConfirmedBlockHeight
               << (uint32_t)data.nLastPaidHeight
               << data.nTier << data.nStatus << data.ip;
        }

        // Serialize removed nodes (outpoint only - saves bandwidth!)
        WriteCompactSize(ss, g_fluxnodeDelta.setRemoved.size());
        for (const auto& outpoint : g_fluxnodeDelta.setRemoved) {
            ss << outpoint;  // Only 36 bytes vs ~200 for full data
        }

        // Serialize updated nodes (full data)
        WriteCompactSize(ss, g_fluxnodeDelta.mapUpdated.size());
        for (const auto& item : g_fluxnodeDelta.mapUpdated) {
            const COutPoint& outpoint = item.first;
            const FluxnodeCacheData& data = item.second;
            ss << outpoint << data.collateralPubkey << data.pubKey
               << (uint32_t)data.nConfirmedBlockHeight
               << (uint32_t)data.nLastPaidHeight
               << data.nTier << data.nStatus << data.ip;
        }

        LogPrint("zmq", "zmq: FluxNode delta %d->%d: added=%d removed=%d updated=%d size=%d\n",
                 nFromHeight, nToHeight,
                 g_fluxnodeDelta.mapAdded.size(),
                 g_fluxnodeDelta.setRemoved.size(),
                 g_fluxnodeDelta.mapUpdated.size(),
                 ss.size());

        // Clear for next block
        g_fluxnodeDelta.Clear();
    }

    nLastDeltaHeight = nToHeight;

    return SendMessage(MSG_FLUXNODELISTDELTA, &(*ss.begin()), ss.size());
}
