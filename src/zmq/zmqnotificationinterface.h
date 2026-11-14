// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
#define BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H

#include "validationinterface.h"
#include "consensus/validation.h"
#include "sync.h"
#include <list>
#include <string>
#include <map>
#include <utility>
#include <vector>

class CBlockIndex;
class CZMQAbstractNotifier;

class CZMQNotificationInterface : public CValidationInterface
{
public:
    virtual ~CZMQNotificationInterface();

    static CZMQNotificationInterface* CreateWithArguments(const std::map<std::string, std::string> &args);

    /** The notifiers publishing now, as (type, address). One that fails to
     * publish is shut down and drops out of the list. */
    std::vector<std::pair<std::string, std::string>> GetActiveNotifiers() const;

protected:
    bool Initialize();
    void Shutdown();

    // CValidationInterface
    void SyncTransaction(const CTransaction &tx, const CBlock *pblock);
    void UpdatedBlockTip(const CBlockIndex *pindex);
    void BlockChecked(const CBlock& block, const CValidationState& state);
    void ChainReorg(const CBlockIndex *pindexOldTip, const CBlockIndex *pindexNewTip, const CBlockIndex *pindexFork);

private:
    CZMQNotificationInterface();

    void *pcontext;
    /** Guards notifiers: the validation callbacks drop failed notifiers while
     * RPC threads read the list. */
    mutable CCriticalSection cs_notifiers;
    std::list<CZMQAbstractNotifier*> notifiers;
};

/** The node's ZMQ notification interface; NULL when no notifier is configured
 * or one failed to start. */
extern CZMQNotificationInterface* g_zmq_notification_interface;

#endif // BITCOIN_ZMQ_ZMQNOTIFICATIONINTERFACE_H
