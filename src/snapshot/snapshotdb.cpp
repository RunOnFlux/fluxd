// Copyright (c) 2022 The Flux Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "snapshotdb.h"
#include <boost/filesystem.hpp>
#include "univalue.h"
#include "rpc/server.h"
#include "main.h"

static const char DB_SNAPSHOT = 's';

CSnapshotDB::CSnapshotDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "snapshots", nCacheSize, fMemory, fWipe) {}


bool CSnapshotDB::WriteFluxSnapshot(const CSnapshot &snapshot)
{
    LogPrint("snapshot", "Wrote snapshot to database at height %d\n", snapshot.nActualSnapshotHeight);
    return Write(std::make_pair(DB_SNAPSHOT, snapshot.nSnapshotTimeOrHeight), snapshot);
}

bool CSnapshotDB::ReadFluxSnapshot(const int64_t& nTimeOrHeight, CSnapshot &snapshot)
{
    LogPrint("snapshot", "Reading snapshot from database at height/time = %d\n", nTimeOrHeight);
    return Read(std::make_pair(DB_SNAPSHOT, nTimeOrHeight), snapshot);
}

UniValue PrettyPrintSnapshot(const int64_t& nTimeOrHeight)
{
    CSnapshot snapshot;
    snapshot.nSnapshotTimeOrHeight = nTimeOrHeight;

    if (pSnapshotDB && pSnapshotDB->ReadFluxSnapshot(nTimeOrHeight, snapshot)) {
        UniValue data(UniValue::VOBJ);

        data.pushKV("timeorheightgiven", nTimeOrHeight);
        data.pushKV("actualheight", snapshot.nActualSnapshotHeight);

        UniValue balances(UniValue::VOBJ);
        for (const auto& pair: snapshot.mapBalances) {
            balances.pushKV(pair.first, ValueFromAmount(pair.second));
        }

        data.pushKV("balances", balances);

        return data;
    }

    return NullUniValue;
}

void CheckForSnapshot(CCoinsViewCache* coinsview)
{
    if (!pSnapshotDB) {
        return;
    }

    // Check if snapshot timestamp was set
    int64_t nSnapshotArg = GetArg("-snapshot", 0);
    if (nSnapshotArg <= 0) {
        return;
    }

    // Check if snapshot at this timestamp is already completed
    if (pSnapshotDB->Exists(std::make_pair(DB_SNAPSHOT, nSnapshotArg))) {
        return;
    }

    {
        // Locking as we are accessing chainActive
        LOCK(cs_main);

        // nSnapshotTime could be a block height or a timestamp
        if (nSnapshotArg < 1000000000) {
            // We are looking at block heights only
            int64_t nCurrentHeight = chainActive.Height();
            if (nCurrentHeight != nSnapshotArg) {
                return;
            }
        } else {
            // We are looking at timestamps only
            if (!chainActive.Tip() || chainActive.Height() < 1) {
                return;
            }
            int64_t tipTime = chainActive.Tip()->nTime;
            int64_t nPrevTime = chainActive[chainActive.Height() - 1]->nTime;

            // The snap shot time must be greater than the block two blocks ago but less that the current tip
            if (nSnapshotArg < nPrevTime) {
                return;
            }

            if (nSnapshotArg > tipTime) {
                return;
            }
        }
    }

    // If you made it this far, create the snapshot
    CreateSnapshot(nSnapshotArg, coinsview);
}

void CreateSnapshot(const int64_t& nTimeOrHeight, CCoinsViewCache* coinsview)
{

    CSnapshot snapshot;
    snapshot.nSnapshotTimeOrHeight = nTimeOrHeight;

    // Set the block height
    {
        LOCK(cs_main);
        snapshot.nActualSnapshotHeight = chainActive.Height();
    }

    // Flush the state to before accessing the coins database.
    // This will ensure all data is as valid as it can be
    FlushStateToDisk();

    {
        LOCK(cs_main);
        coinsview->GetAllBalances(snapshot.mapBalances);
    }

    if(pSnapshotDB->WriteFluxSnapshot(snapshot)) {
        LogPrintf("Wrote snapshot to db");
    } else {
        LogPrintf("Failed to write snapshot to db");
    }
}
