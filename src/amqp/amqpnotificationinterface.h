// Copyright (c) 2017 The Zelcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASH_AMQP_AMQPNOTIFICATIONINTERFACE_H
#define ZELCASH_AMQP_AMQPNOTIFICATIONINTERFACE_H

#include "validationinterface.h"
#include <string>
#include <map>

class CBlockIndex;
class AMQPAbstractNotifier;

class AMQPNotificationInterface : public CValidationInterface
{
public:
    virtual ~AMQPNotificationInterface();

    static AMQPNotificationInterface* CreateWithArguments(const std::map<std::string, std::string> &args);

protected:
    bool Initialize();
    void Shutdown();

    // CValidationInterface
    void SyncTransaction(const CTransaction &tx, const CBlock *pblock);
    void UpdatedBlockTip(const CBlockIndex *pindex);

private:
    AMQPNotificationInterface();

    std::list<AMQPAbstractNotifier*> notifiers;
};

#endif // ZELCASH_AMQP_AMQPNOTIFICATIONINTERFACE_H
