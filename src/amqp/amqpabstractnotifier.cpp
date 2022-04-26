// Copyright (c) 2017-2019 The Zcash developers
// Copyright (C) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "amqpabstractnotifier.h"
#include "util.h"


AMQPAbstractNotifier::~AMQPAbstractNotifier()
{
}

bool AMQPAbstractNotifier::NotifyBlock(const CBlockIndex * /*CBlockIndex*/)
{
    return true;
}

bool AMQPAbstractNotifier::NotifyTransaction(const CTransaction &/*transaction*/)
{
    return true;
}
