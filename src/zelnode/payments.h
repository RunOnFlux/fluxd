// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2019 The Zel developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef ZELCASHNODES_PAYMENTS_H
#define ZELCASHNODES_PAYMENTS_H

#include "key.h"
#include "main.h"
#include "zelnode/zelnode.h"

using namespace std;

extern CCriticalSection cs_vecPayments;
extern CCriticalSection cs_mapZelnodeBlocks;
extern CCriticalSection cs_mapZelnodePayeeVotes;


class Payments;
class PaymentWinner;
class BlockPayees;

extern Payments zelnodePayments;

#define ZNPAYMENTS_SIGNATURES_REQUIRED 16 // TODO Remove after Zelnode Upgrade
#define ZNPAYMENTS_SIGNATURES_TOTAL 10

#define ZNPAYMENTS_SIGNATURES_REQUIRED_AFTER_UPGRADE 6

void ProcessMessageZelnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
bool IsBlockPayeeValid(const CBlock& block, int nBlockHeight);
std::string GetRequiredPaymentsString(int nBlockHeight);
bool IsBlockValueValid(const CBlock& block, CAmount nExpectedValue, CAmount nMinted);
void FillBlockPayee(CMutableTransaction& txNew, CAmount nFees, std::map<int, std::pair<CScript, CAmount>>* payments = nullptr);

void DumpZelnodePayments();


/** Save Zelnode payment Data (zelnodepayments.dat)
 */
class PaymentDB
{
private:
    boost::filesystem::path pathDB;
    std::string strMagicMessage;

public:
    enum ReadResult
    {
        Ok,
        FileError,
        HashReadError,
        IncorrectHash,
        IncorrectMagicMessage,
        IncorrectMagicNumber,
        IncorrectFormat
    };

    PaymentDB();
    bool Write(const Payments& objToSave);
    ReadResult Read(Payments& objToLoad, bool fDryRun = false);
};

class ZelnodePayee
{
public:
    CScript scriptPubKey;
    int nVotes;

    ZelnodePayee()
    {
        scriptPubKey = CScript();
        nVotes = 0;
    }

    ZelnodePayee(CScript payee, int nVotesIn)
    {
        scriptPubKey = payee;
        nVotes = nVotesIn;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(nVotes);
    }
};

// Keep track of votes for payees from zelnodes
class ZelnodeBlockPayees
{
public:
    int nBlockHeight;
    std::vector<ZelnodePayee> vecCUMULUSPayments;
    std::vector<ZelnodePayee> vecNIMBUSPayments;
    std::vector<ZelnodePayee> vecSTRATUSPayments;

    ZelnodeBlockPayees()
    {
        nBlockHeight = 0;
        vecCUMULUSPayments.clear();
        vecNIMBUSPayments.clear();
        vecSTRATUSPayments.clear();
    }
    ZelnodeBlockPayees(int nBlockHeightIn)
    {
        nBlockHeight = nBlockHeightIn;
        vecCUMULUSPayments.clear();
        vecNIMBUSPayments.clear();
        vecSTRATUSPayments.clear();
    }

    void AddPayee(CScript payeeIn, int nIncrement, int nNodeTier)
    {
        LOCK(cs_vecPayments);

        if (nNodeTier == Zelnode::CUMULUS) {
            for (ZelnodePayee& payee : vecCUMULUSPayments) {
                if (payee.scriptPubKey == payeeIn) {
                    payee.nVotes += nIncrement;
                    return;
                }
            }
        }

        else if (nNodeTier == Zelnode::NIMBUS) {
            for (ZelnodePayee& payee : vecNIMBUSPayments) {
                if (payee.scriptPubKey == payeeIn) {
                    payee.nVotes += nIncrement;
                    return;
                }
            }
        }

        else if (nNodeTier == Zelnode::STRATUS) {
            for (ZelnodePayee& payee : vecSTRATUSPayments) {
                if (payee.scriptPubKey == payeeIn) {
                    payee.nVotes += nIncrement;
                    return;
                }
            }
        }

        ZelnodePayee c(payeeIn, nIncrement);
        if (nNodeTier == Zelnode::CUMULUS) vecCUMULUSPayments.push_back(c);
        else if (nNodeTier == Zelnode::NIMBUS) vecNIMBUSPayments.push_back(c);
        else if (nNodeTier == Zelnode::STRATUS) vecSTRATUSPayments.push_back(c);
    }

    bool getCUMULUSPayee(CScript& CUMULUSPayee)
    {
        LOCK(cs_vecPayments);

        int nVotes = -1;
        for (ZelnodePayee& p : vecCUMULUSPayments) {
            if (p.nVotes > nVotes) {
                CUMULUSPayee = p.scriptPubKey;
                nVotes = p.nVotes;
            }
        }

        return (nVotes > -1);
    }

    bool getNIMBUSPayee(CScript& NIMBUSPayee)
    {
        LOCK(cs_vecPayments);

        int nVotes = -1;
        for (ZelnodePayee& p : vecNIMBUSPayments) {
            if (p.nVotes > nVotes) {
                NIMBUSPayee = p.scriptPubKey;
                nVotes = p.nVotes;
            }
        }

        return (nVotes > -1);
    }

    bool GetSTRATUSPayee(CScript& STRATUSPayee)
    {
        LOCK(cs_vecPayments);

        int nVotes = -1;
        for (ZelnodePayee& p : vecSTRATUSPayments) {
            if (p.nVotes > nVotes) {
                STRATUSPayee = p.scriptPubKey;
                nVotes = p.nVotes;
            }
        }

        return (nVotes > -1);
    }

    bool HasPayeeWithVotes(CScript payee, int nVotesReq)
    {
        LOCK(cs_vecPayments);

        for (ZelnodePayee& p : vecCUMULUSPayments) {
            if (p.nVotes >= nVotesReq && p.scriptPubKey == payee) return true;
        }

        for (ZelnodePayee& p : vecNIMBUSPayments) {
            if (p.nVotes >= nVotesReq && p.scriptPubKey == payee) return true;
        }

        for (ZelnodePayee& p : vecSTRATUSPayments) {
            if (p.nVotes >= nVotesReq && p.scriptPubKey == payee) return true;
        }

        return false;
    }

    bool IsTransactionValid(const CTransaction& txNew);
    std::string GetRequiredPaymentsString();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(nBlockHeight);
        READWRITE(vecCUMULUSPayments);
        READWRITE(vecNIMBUSPayments);
        READWRITE(vecSTRATUSPayments);
    }
};

// for storing the winning payments
class PaymentWinner
{
public:
    CTxIn vinZelnode;

    int nBlockHeight;
    CScript payee;
    std::vector<unsigned char> vchSig;
    int8_t tier;

    PaymentWinner()
    {
        nBlockHeight = 0;
        vinZelnode = CTxIn();
        payee = CScript();
        tier = 0;
    }

    PaymentWinner(CTxIn vinIn)
    {
        nBlockHeight = 0;
        vinZelnode = vinIn;
        payee = CScript();
        tier = 0;
    }

    uint256 GetHash()
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << *(CScriptBase*)(&payee);
        ss << nBlockHeight;
        ss << vinZelnode.prevout;
        ss << tier;

        return ss.GetHash();
    }

    bool Sign(CKey& keyZelnode, CPubKey& pubKeyZelnode);
    bool IsValid(CNode* pnode, std::string& strError);
    bool SignatureValid();
    void Relay();

    void AddPayee(CScript payeeIn)
    {
        payee = payeeIn;
    }


    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(vinZelnode);
        READWRITE(nBlockHeight);
        READWRITE(*(CScriptBase*)(&payee));
        READWRITE(vchSig);
        if (ser_action.ForRead()) {
            if (!s.empty() && s.size() >= sizeof(int8_t)) {
                ::Unserialize(s, tier);
            }
        } else {
            ::Serialize(s, tier);
        }
    }

    std::string ToString()
    {
        std::string ret = "";
        ret += vinZelnode.ToString();
        ret += ", " + std::to_string(nBlockHeight);
        ret += ", " + payee.ToString();
        ret += ", " + std::to_string((int)vchSig.size());
        ret += ", " + TierToString(tier);
        return ret;
    }
};



//
// Zelnode Payments Class
// Keeps track of who should get paid for which blocks
//

class Payments
{
private:
    int nSyncedFromPeer;
    int nLastBlockHeight;

public:
    std::map<uint256, PaymentWinner> mapZelnodePayeeVotes;
    std::map<int, ZelnodeBlockPayees> mapZelnodeBlocks;
    std::map<COutPoint, int> mapCUMULUSZelnodeLastVote; //prevout.hash, prevout.n, nBlockHeight
    std::map<COutPoint, int> mapNIMBUSZelnodeLastVote; //prevout.hash, prevout.n, nBlockHeight
    std::map<COutPoint, int> mapSTRATUSZelnodeLastVote; //prevout.hash, prevout.n, nBlockHeight

    Payments()
    {
        nSyncedFromPeer = 0;
        nLastBlockHeight = 0;
    }

    void Clear()
    {
        LOCK2(cs_mapZelnodeBlocks, cs_mapZelnodePayeeVotes);
        mapZelnodeBlocks.clear();
        mapZelnodePayeeVotes.clear();
    }

    bool AddWinningZelnode(PaymentWinner& winner, int nNodeTier);
    bool ProcessBlock(int nBlockHeight);

    void Sync(CNode* node, int nCountNeeded);
    void CleanPaymentList();
    int LastPayment(Zelnode& mn);

    bool GetBlockCUMULUSPayee(int nBlockHeight, CScript& payee);
    bool GetBlockNIMBUSPayee(int nBlockHeight, CScript& payee);
    bool GetBlockSTRATUSPayee(int nBlockHeight, CScript& payee);
    bool IsTransactionValid(const CTransaction& txNew, int nBlockHeight);
    bool IsScheduled(Zelnode& mn, int nNotBlockHeight);

    bool CanVote(const PaymentWinner& winner)
    {
        LOCK(cs_mapZelnodePayeeVotes);

        COutPoint out = winner.vinZelnode.prevout;

        if (winner.tier == Zelnode::CUMULUS) {
            if (mapCUMULUSZelnodeLastVote.count(out))
                if (mapCUMULUSZelnodeLastVote[out] == winner.nBlockHeight)
                    return false;

            //record this zelnode voted
            mapCUMULUSZelnodeLastVote[out] = winner.nBlockHeight;
            return true;
        }

        else if (winner.tier == Zelnode::NIMBUS) {
            if (mapNIMBUSZelnodeLastVote.count(out))
                if (mapNIMBUSZelnodeLastVote[out] == winner.nBlockHeight)
                    return false;

            //record this zelnode voted
            mapNIMBUSZelnodeLastVote[out] = winner.nBlockHeight;
            return true;
        }

        else if (winner.tier == Zelnode::STRATUS) {
            if (mapSTRATUSZelnodeLastVote.count(out))
                if (mapSTRATUSZelnodeLastVote[out] == winner.nBlockHeight)
                    return false;

            //record this zelnode voted
            mapSTRATUSZelnodeLastVote[out] = winner.nBlockHeight;
            return true;
        }

        return false;
    }

    int GetMinZelnodePaymentsProto();
    void ProcessMessageZelnodePayments(CNode* pfrom, std::string& strCommand, CDataStream& vRecv);
    std::string GetRequiredPaymentsString(int nBlockHeight);
    void FillBlockPayee(CMutableTransaction& txNew, int64_t nFees, std::map<int, std::pair<CScript, CAmount>>* payments = nullptr);
    std::string ToString() const;
    int GetOldestBlock();
    int GetNewestBlock();

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(mapZelnodePayeeVotes);
        READWRITE(mapZelnodeBlocks);
    }
};


#endif //ZELCASHNODES_PAYMENTS_H
