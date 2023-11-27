// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "asyncrpcoperation.h"
#include "univalue.h"
#include "flux/Address.hpp"
#include "flux/zip32.h"

class AsyncRPCOperation_saplingmigration : public AsyncRPCOperation
{
public:
    AsyncRPCOperation_saplingmigration(int targetHeight);
    virtual ~AsyncRPCOperation_saplingmigration();

    // We don't want to be copied or moved around
    AsyncRPCOperation_saplingmigration(AsyncRPCOperation_saplingmigration const&) = delete;            // Copy construct
    AsyncRPCOperation_saplingmigration(AsyncRPCOperation_saplingmigration&&) = delete;                 // Move construct
    AsyncRPCOperation_saplingmigration& operator=(AsyncRPCOperation_saplingmigration const&) = delete; // Copy assign
    AsyncRPCOperation_saplingmigration& operator=(AsyncRPCOperation_saplingmigration&&) = delete;      // Move assign

    static libflux::SaplingPaymentAddress getMigrationDestAddress(const HDSeed& seed, bool& fFailed);

    virtual void main();

    virtual void cancel();

    virtual UniValue getStatus() const;

private:
    int targetHeight_;

    bool main_impl();

    void setMigrationResult(int numTxCreated, const CAmount& amountMigrated, const std::vector<std::string>& migrationTxIds);

    CAmount chooseAmount(const CAmount& availableFunds);
};
