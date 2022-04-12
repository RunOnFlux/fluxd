// Copyright (c) 2022 The Flux Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASH_CSNAPSHOTDB_H
#define ZELCASH_CSNAPSHOTDB_H

#include "dbwrapper.h"
#include <boost/filesystem/path.hpp>
#include <amount.h>

class UniValue;
class CCoinsViewCache;

// A Snapshot will be created after the first block that is mined after the given timestamp.
class CSnapshot
{

public:
    CSnapshot()
    {
        SetNull();
    }

    void SetNull()
    {
        nSnapshotTime = 0;
        nActualSnapshotHeight = 0;
        mapBalances.clear();
    }

    int64_t nSnapshotTime;
    int32_t nActualSnapshotHeight;
    std::map<std::string,CAmount> mapBalances;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSnapshotTime);
        READWRITE(nActualSnapshotHeight);
        READWRITE(mapBalances);
    }
};

UniValue PrettyPrintSnapshot(const int64_t& nTime);
void CheckForSnapshot(CCoinsViewCache *);
void CreateSnapshot(const int64_t& nTime, CCoinsViewCache *);

class CSnapshotDB : public CDBWrapper
{

public:
    CSnapshotDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

private:
    CSnapshotDB(const CSnapshotDB&);
    void operator=(const CSnapshotDB&);

public:
    bool WriteFluxSnapshot(const CSnapshot& snapshot);
    bool ReadFluxSnapshot(const int64_t& nTime, CSnapshot &snapshot);
};


#endif //ZELCASH_CSNAPSHOTDB_H
