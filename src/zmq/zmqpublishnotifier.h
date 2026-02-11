// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H
#define BITCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H

#include "zmqabstractnotifier.h"

class CBlockIndex;

class CZMQAbstractPublishNotifier : public CZMQAbstractNotifier
{
private:
    uint32_t nSequence; //! upcounting per message sequence number

public:

    /* send zmq multipart message
       parts:
          * command
          * data
          * message sequence number
    */
    bool SendMessage(const char *command, const void* data, size_t size);

    bool Initialize(void *pcontext);
    void Shutdown();
};

class CZMQPublishHashBlockNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyBlock(const CBlockIndex *pindex);
};

class CZMQPublishHashTransactionNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyTransaction(const CTransaction &transaction);
};

class CZMQPublishRawBlockNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyBlock(const CBlockIndex *pindex);
};

class CZMQPublishRawTransactionNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyTransaction(const CTransaction &transaction);
};

class CZMQPublishCheckedBlockNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyBlock(const CBlock &block);
};

class CZMQPublishHashBlockHeightNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyBlock(const CBlockIndex *pindex);
};

class CZMQPublishChainReorgNotifier : public CZMQAbstractPublishNotifier
{
public:
    bool NotifyChainReorg(const CBlockIndex *pindexOldTip, const CBlockIndex *pindexNewTip, const CBlockIndex *pindexFork);
};

class CZMQPublishFluxNodeListNotifier : public CZMQAbstractPublishNotifier
{
private:
    int nLastDeltaHeight;
    bool fInitialized;

    bool SendDelta(int nFromHeight, int nToHeight, const CBlockIndex *pindexTo);

public:
    CZMQPublishFluxNodeListNotifier() : nLastDeltaHeight(0), fInitialized(false) {}
    bool NotifyBlock(const CBlockIndex *pindex);
};

#endif // BITCOIN_ZMQ_ZMQPUBLISHNOTIFIER_H
