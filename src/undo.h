// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UNDO_H
#define BITCOIN_UNDO_H

#include "compressor.h" 
#include "primitives/transaction.h"
#include "serialize.h"
#include "fluxnode/fluxnode.h"

/** Undo information for a CTxIn
 *
 *  Contains the prevout's CTxOut being spent, and if this was the
 *  last output of the affected transaction, its metadata as well
 *  (coinbase or not, height, transaction version)
 */
class CTxInUndo
{
public:
    CTxOut txout;         // the txout data before being spent
    bool fCoinBase;       // if the outpoint was the last unspent: whether it belonged to a coinbase
    unsigned int nHeight; // if the outpoint was the last unspent: its height
    int nVersion;         // if the outpoint was the last unspent: its version

    CTxInUndo() : txout(), fCoinBase(false), nHeight(0), nVersion(0) {}
    CTxInUndo(const CTxOut &txoutIn, bool fCoinBaseIn = false, unsigned int nHeightIn = 0, int nVersionIn = 0) : txout(txoutIn), fCoinBase(fCoinBaseIn), nHeight(nHeightIn), nVersion(nVersionIn) { }

    template<typename Stream>
    void Serialize(Stream &s) const {
        ::Serialize(s, VARINT(nHeight*2+(fCoinBase ? 1 : 0)));
        if (nHeight > 0)
            ::Serialize(s, VARINT(this->nVersion));
        ::Serialize(s, CTxOutCompressor(REF(txout)));
    }

    template<typename Stream>
    void Unserialize(Stream &s) {
        unsigned int nCode = 0;
        ::Unserialize(s, VARINT(nCode));
        nHeight = nCode / 2;
        fCoinBase = nCode & 1;
        if (nHeight > 0)
            ::Unserialize(s, VARINT(this->nVersion));
        ::Unserialize(s, REF(CTxOutCompressor(REF(txout))));
    }
};

/** Undo information for a CTransaction */
class CTxUndo
{
public:
    // undo information for all txins
    std::vector<CTxInUndo> vprevout;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vprevout);
    }
};

/** Undo information for a CBlock */
class CBlockUndo
{
public:
    std::vector<CTxUndo> vtxundo; // for all but the coinbase
    uint256 old_sprout_tree_root;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vtxundo);
        READWRITE(old_sprout_tree_root);
    }
};

template <typename Stream, typename Operation, typename T>
void ReadWriteExtraFluxnodeUndoBlockData(Stream &s, Operation ser_action, T &data)
{
    if (ser_action.ForRead())
    {
        if (!s.empty()) {
            READWRITE(data);
        }
    }
    else
    {
        READWRITE(data);
    }
}


class CFluxnodeTxBlockUndo
{
public:
    std::vector<FluxnodeCacheData> vecExpiredDosData;
    std::vector<FluxnodeCacheData> vecExpiredConfirmedData;
    std::map<COutPoint, int> mapUpdateLastConfirmHeight;
    std::map<COutPoint, int> mapLastPaidHeights;
    std::map<COutPoint, std::string> mapLastIpAddress;
    std::map<COutPoint, CFluxnodeDelegates> mapOldDelegates;

    void SetNull() {
        vecExpiredDosData.clear();
        vecExpiredConfirmedData.clear();
        mapUpdateLastConfirmHeight.clear();
        mapLastPaidHeights.clear();
        mapLastIpAddress.clear();
        mapOldDelegates.clear();
    }

    CFluxnodeTxBlockUndo(){
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vecExpiredDosData);
        READWRITE(vecExpiredConfirmedData);
        READWRITE(mapUpdateLastConfirmHeight);
        READWRITE(mapLastPaidHeights);
        ReadWriteExtraFluxnodeUndoBlockData(s, ser_action, mapLastIpAddress);
        ReadWriteExtraFluxnodeUndoBlockData(s, ser_action, mapOldDelegates);
    }
};

#endif // BITCOIN_UNDO_H
