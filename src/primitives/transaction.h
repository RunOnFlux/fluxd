// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2018-2022 The Flux Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include "amount.h"
#include "random.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "consensus/consensus.h"

#include <array>

#include <boost/variant.hpp>
#include <netbase.h>
#include <pubkey.h>

#include "flux/NoteEncryption.hpp"
#include "flux/Zelcash.h"
#include "flux/JoinSplit.hpp"
#include "flux/Proof.hpp"

#define JOINSPLIT_SIZE GetSerializeSize(JSDescription(), SER_NETWORK, PROTOCOL_VERSION)
#define OUTPUTDESCRIPTION_SIZE GetSerializeSize(OutputDescription(), SER_NETWORK, PROTOCOL_VERSION)
#define SPENDDESCRIPTION_SIZE GetSerializeSize(SpendDescription(), SER_NETWORK, PROTOCOL_VERSION)

// Overwinter transaction version
static const int32_t OVERWINTER_TX_VERSION = 3;
static_assert(OVERWINTER_TX_VERSION >= OVERWINTER_MIN_TX_VERSION,
    "Overwinter tx version must not be lower than minimum");
static_assert(OVERWINTER_TX_VERSION <= OVERWINTER_MAX_TX_VERSION,
    "Overwinter tx version must not be higher than maximum");

// Sapling transaction version
static const int32_t SAPLING_TX_VERSION = 4;
static_assert(SAPLING_TX_VERSION >= SAPLING_MIN_TX_VERSION,
    "Sapling tx version must not be lower than minimum");
static_assert(SAPLING_TX_VERSION <= SAPLING_MAX_TX_VERSION,
    "Sapling tx version must not be higher than maximum");

static const int32_t FLUXNODE_TX_VERSION = 5;
static const int32_t FLUXNODE_TX_UPGRADEABLE_VERSION = 6;

// Legacy version constants for backward compatibility
static const int32_t FLUXNODE_INTERNAL_NORMAL_TX_VERSION = 1;
static const int32_t FLUXNODE_INTERNAL_P2SH_TX_VERSION = 2;

// Bit-based version system (for use after PON fork)
// Bits 0-7: Transaction type
static const int32_t FLUXNODE_TX_TYPE_MASK = 0xFF;
static const int32_t FLUXNODE_TX_TYPE_NORMAL_BIT = 0x01;  // Bit 0
static const int32_t FLUXNODE_TX_TYPE_P2SH_BIT = 0x02;    // Bit 1

// Bits 8-15: Feature flags
static const int32_t FLUXNODE_TX_FEATURE_MASK = 0xFF00;
static const int32_t FLUXNODE_TX_FEATURE_DELEGATES_BIT = 0x0100;  // Bit 8
static const int32_t FLUXNODE_TX_FEATURE_RESERVED1_BIT = 0x0200;  // Bit 9
static const int32_t FLUXNODE_TX_FEATURE_RESERVED2_BIT = 0x0400;  // Bit 10

inline bool HasConflictingBits(const int32_t& version) {
    return (version & FLUXNODE_TX_TYPE_NORMAL_BIT) != 0 && (version & FLUXNODE_TX_TYPE_P2SH_BIT) != 0;
}
// Helper functions for version checking
inline bool IsFluxTxNormalType(const int32_t& version, bool includeBitCheck = false) {
    if (includeBitCheck) {
        if (HasConflictingBits(version))
            return false;
        return (version & FLUXNODE_TX_TYPE_NORMAL_BIT) != 0 || version == FLUXNODE_INTERNAL_NORMAL_TX_VERSION;
    }
    return version == FLUXNODE_INTERNAL_NORMAL_TX_VERSION;
}

inline bool IsFluxTxP2SHType(const int32_t& version, bool includeBitCheck = false) {
    if (includeBitCheck) {
        if (HasConflictingBits(version))
            return false;
        return (version & FLUXNODE_TX_TYPE_P2SH_BIT) != 0 || version == FLUXNODE_INTERNAL_P2SH_TX_VERSION;
    }
    return version == FLUXNODE_INTERNAL_P2SH_TX_VERSION;
}

inline bool HasFluxTxDelegatesFeature(int32_t version) {
    return (version & FLUXNODE_TX_FEATURE_DELEGATES_BIT) != 0;
}

class CFluxnodeDelegates
{
public:
    static const int MAX_PUBKEYS_LENGTH = 4;
    static const int8_t INITIAL_VERSION = 1;
    static const int8_t NONE = 0;
    static const int8_t UPDATE = 1;
    static const int8_t SIGNING = 2;

    int8_t nDelegateVersion;
    int8_t nType;
    std::vector<CPubKey> delegateStartingKeys;

    void SetNull() {
        nDelegateVersion = 1;
        nType = NONE;
        delegateStartingKeys.clear();
    }

    CFluxnodeDelegates() {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nDelegateVersion);
        READWRITE(nType);
        if(nDelegateVersion == INITIAL_VERSION) {
            if (nType == UPDATE) {
                READWRITE(delegateStartingKeys);
            }
        }
    }

    bool IsSigning() const {
        return nType == SIGNING;
    }

    bool IsUpdating() const {
        return nType == UPDATE;
    }

    bool IsValid() const {
        if (nType != UPDATE && nType != SIGNING)
            return false;

        if (delegateStartingKeys.size() > MAX_PUBKEYS_LENGTH)
            return false;

        for (const auto& pubkey : delegateStartingKeys) {
            if (!pubkey.IsValid() || !pubkey.IsCompressed()) {
                return false;
            }
        }
        return true;
    }
};

/**
 * A shielded input to a transaction. It contains data that describes a Spend transfer.
 */
class SpendDescription
{
public:
    typedef std::array<unsigned char, 64> spend_auth_sig_t;

    uint256 cv;                    //!< A value commitment to the value of the input note.
    uint256 anchor;                //!< A Merkle root of the Sapling note commitment tree at some block height in the past.
    uint256 nullifier;             //!< The nullifier of the input note.
    uint256 rk;                    //!< The randomized public key for spendAuthSig.
    libflux::GrothProof zkproof;  //!< A zero-knowledge proof using the spend circuit.
    spend_auth_sig_t spendAuthSig; //!< A signature authorizing this spend.

    SpendDescription() { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(cv);
        READWRITE(anchor);
        READWRITE(nullifier);
        READWRITE(rk);
        READWRITE(zkproof);
        READWRITE(spendAuthSig);
    }

    friend bool operator==(const SpendDescription& a, const SpendDescription& b)
    {
        return (
            a.cv == b.cv &&
            a.anchor == b.anchor &&
            a.nullifier == b.nullifier &&
            a.rk == b.rk &&
            a.zkproof == b.zkproof &&
            a.spendAuthSig == b.spendAuthSig
            );
    }

    friend bool operator!=(const SpendDescription& a, const SpendDescription& b)
    {
        return !(a == b);
    }
};

/**
 * A shielded output to a transaction. It contains data that describes an Output transfer.
 */
class OutputDescription
{
public:
    uint256 cv;                     //!< A value commitment to the value of the output note.
    uint256 cm;                     //!< The note commitment for the output note.
    uint256 ephemeralKey;           //!< A Jubjub public key.
    libflux::SaplingEncCiphertext encCiphertext; //!< A ciphertext component for the encrypted output note.
    libflux::SaplingOutCiphertext outCiphertext; //!< A ciphertext component for the encrypted output note.
    libflux::GrothProof zkproof;   //!< A zero-knowledge proof using the output circuit.

    OutputDescription() { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(cv);
        READWRITE(cm);
        READWRITE(ephemeralKey);
        READWRITE(encCiphertext);
        READWRITE(outCiphertext);
        READWRITE(zkproof);
    }

    friend bool operator==(const OutputDescription& a, const OutputDescription& b)
    {
        return (
            a.cv == b.cv &&
            a.cm == b.cm &&
            a.ephemeralKey == b.ephemeralKey &&
            a.encCiphertext == b.encCiphertext &&
            a.outCiphertext == b.outCiphertext &&
            a.zkproof == b.zkproof
            );
    }

    friend bool operator!=(const OutputDescription& a, const OutputDescription& b)
    {
        return !(a == b);
    }
};

template <typename Stream>
class SproutProofSerializer : public boost::static_visitor<>
{
    Stream& s;
    bool useGroth;

public:
    SproutProofSerializer(Stream& s, bool useGroth) : s(s), useGroth(useGroth) {}

    void operator()(const libflux::PHGRProof& proof) const
    {
        if (useGroth) {
            throw std::ios_base::failure("Invalid Sprout proof for transaction format (expected GrothProof, found PHGRProof)");
        }
        ::Serialize(s, proof);
    }

    void operator()(const libflux::GrothProof& proof) const
    {
        if (!useGroth) {
            throw std::ios_base::failure("Invalid Sprout proof for transaction format (expected PHGRProof, found GrothProof)");
        }
        ::Serialize(s, proof);
    }
};

template<typename Stream, typename T>
inline void SerReadWriteSproutProof(Stream& s, const T& proof, bool useGroth, CSerActionSerialize ser_action)
{
    auto ps = SproutProofSerializer<Stream>(s, useGroth);
    boost::apply_visitor(ps, proof);
}

template<typename Stream, typename T>
inline void SerReadWriteSproutProof(Stream& s, T& proof, bool useGroth, CSerActionUnserialize ser_action)
{
    if (useGroth) {
        libflux::GrothProof grothProof;
        ::Unserialize(s, grothProof);
        proof = grothProof;
    } else {
        libflux::PHGRProof pghrProof;
        ::Unserialize(s, pghrProof);
        proof = pghrProof;
    }
}

class JSDescription
{
public:
    // These values 'enter from' and 'exit to' the value
    // pool, respectively.
    CAmount vpub_old;
    CAmount vpub_new;

    // JoinSplits are always anchored to a root in the note
    // commitment tree at some point in the blockchain
    // history or in the history of the current
    // transaction.
    uint256 anchor;

    // Nullifiers are used to prevent double-spends. They
    // are derived from the secrets placed in the note
    // and the secret spend-authority key known by the
    // spender.
    std::array<uint256, ZC_NUM_JS_INPUTS> nullifiers;

    // Note commitments are introduced into the commitment
    // tree, blinding the public about the values and
    // destinations involved in the JoinSplit. The presence of
    // a commitment in the note commitment tree is required
    // to spend it.
    std::array<uint256, ZC_NUM_JS_OUTPUTS> commitments;

    // Ephemeral key
    uint256 ephemeralKey;

    // Ciphertexts
    // These contain trapdoors, values and other information
    // that the recipient needs, including a memo field. It
    // is encrypted using the scheme implemented in crypto/NoteEncryption.cpp
    std::array<ZCNoteEncryption::Ciphertext, ZC_NUM_JS_OUTPUTS> ciphertexts = {{ {{0}} }};

    // Random seed
    uint256 randomSeed;

    // MACs
    // The verification of the JoinSplit requires these MACs
    // to be provided as an input.
    std::array<uint256, ZC_NUM_JS_INPUTS> macs;

    // JoinSplit proof
    // This is a zk-SNARK which ensures that this JoinSplit is valid.
    libflux::SproutProof proof;

    JSDescription(): vpub_old(0), vpub_new(0) { }

    JSDescription(
            ZCJoinSplit& params,
            const uint256& joinSplitPubKey,
            const uint256& rt,
            const std::array<libflux::JSInput, ZC_NUM_JS_INPUTS>& inputs,
            const std::array<libflux::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
            CAmount vpub_old,
            CAmount vpub_new,
            bool computeProof = true, // Set to false in some tests
            uint256 *esk = nullptr // payment disclosure
    );

    static JSDescription Randomized(
            ZCJoinSplit& params,
            const uint256& joinSplitPubKey,
            const uint256& rt,

            std::array<libflux::JSInput, ZC_NUM_JS_INPUTS>& inputs,
            std::array<libflux::JSOutput, ZC_NUM_JS_OUTPUTS>& outputs,
            std::array<size_t, ZC_NUM_JS_INPUTS>& inputMap,
            std::array<size_t, ZC_NUM_JS_OUTPUTS>& outputMap,

            CAmount vpub_old,
            CAmount vpub_new,
            bool computeProof = true, // Set to false in some tests
            uint256 *esk = nullptr, // payment disclosure
            std::function<int(int)> gen = GetRandInt
    );

    // Verifies that the JoinSplit proof is correct.
    bool Verify(
        ZCJoinSplit& params,
        libflux::ProofVerifier& verifier,
        const uint256& joinSplitPubKey
    ) const;

    // Returns the calculated h_sig
    uint256 h_sig(ZCJoinSplit& params, const uint256& joinSplitPubKey) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        // nVersion is set by CTransaction and CMutableTransaction to
        // (tx.fOverwintered << 31) | tx.nVersion
        bool fOverwintered = s.GetVersion() >> 31;
        int32_t txVersion = s.GetVersion() & 0x7FFFFFFF;
        bool useGroth = fOverwintered && txVersion >= SAPLING_TX_VERSION;

        READWRITE(vpub_old);
        READWRITE(vpub_new);
        READWRITE(anchor);
        READWRITE(nullifiers);
        READWRITE(commitments);
        READWRITE(ephemeralKey);
        READWRITE(randomSeed);
        READWRITE(macs);
        ::SerReadWriteSproutProof(s, proof, useGroth, ser_action);
        READWRITE(ciphertexts);
    }

    friend bool operator==(const JSDescription& a, const JSDescription& b)
    {
        return (
            a.vpub_old == b.vpub_old &&
            a.vpub_new == b.vpub_new &&
            a.anchor == b.anchor &&
            a.nullifiers == b.nullifiers &&
            a.commitments == b.commitments &&
            a.ephemeralKey == b.ephemeralKey &&
            a.ciphertexts == b.ciphertexts &&
            a.randomSeed == b.randomSeed &&
            a.macs == b.macs &&
            a.proof == b.proof
            );
    }

    friend bool operator!=(const JSDescription& a, const JSDescription& b)
    {
        return !(a == b);
    }
};

class BaseOutPoint
{
public:
    uint256 hash;
    uint32_t n;

    BaseOutPoint() { SetNull(); }
    BaseOutPoint(uint256 hashIn, uint32_t nIn) { hash = hashIn; n = nIn; }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
        READWRITE(n);
    }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }

    friend bool operator<(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const BaseOutPoint& a, const BaseOutPoint& b)
    {
        return !(a == b);
    }
};

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint : public BaseOutPoint
{
public:
    COutPoint() : BaseOutPoint() {};
    COutPoint(uint256 hashIn, uint32_t nIn) : BaseOutPoint(hashIn, nIn) {};
    std::string ToString() const;
    std::string ToFullString() const;
    std::string GetTxHash() const;
    std::string GetTxIndex() const;
};

/** An outpoint - a combination of a transaction hash and an index n into its sapling
 * output description (vShieldedOutput) */
class SaplingOutPoint : public BaseOutPoint
{
public:
    SaplingOutPoint() : BaseOutPoint() {};
    SaplingOutPoint(uint256 hashIn, uint32_t nIn) : BaseOutPoint(hashIn, nIn) {}; 
    std::string ToString() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;

    CTxIn()
    {
        nSequence = std::numeric_limits<unsigned int>::max();
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=std::numeric_limits<unsigned int>::max());
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=std::numeric_limits<uint32_t>::max());

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(prevout);
        READWRITE(*(CScriptBase*)(&scriptSig));
        READWRITE(nSequence);
    }

    bool IsFinal() const
    {
        return (nSequence == std::numeric_limits<uint32_t>::max());
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator<(const CTxIn& a, const CTxIn& b)
    {
        return a.prevout < b.prevout;
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nValue);
        READWRITE(*(CScriptBase*)(&scriptPubKey));
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    uint256 GetHash() const;

    CAmount GetDustThreshold(const CFeeRate &minRelayTxFee) const
    {
        // "Dust" is defined in terms of CTransaction::minRelayTxFee,
        // which has units satoshis-per-kilobyte.
        // If you'd pay more than 1/3 in fees
        // to spend something, then we consider it dust.
        // A typical spendable txout is 34 bytes big, and will
        // need a CTxIn of at least 148 bytes to spend:
        // so dust is a spendable txout less than 54 satoshis
        // with default minRelayTxFee.
        if (scriptPubKey.IsUnspendable())
            return 0;

        size_t nSize = GetSerializeSize(*this, SER_DISK, 0) + 148u;
        return 3*minRelayTxFee.GetFee(nSize);
    }

    bool IsDust(const CFeeRate &minRelayTxFee) const
    {
        return (nValue < GetDustThreshold(minRelayTxFee));
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

// Overwinter version group id
static constexpr uint32_t OVERWINTER_VERSION_GROUP_ID = 0x03C48270;
static_assert(OVERWINTER_VERSION_GROUP_ID != 0, "version group id must be non-zero as specified in ZIP 202");

// Sapling version group id
static constexpr uint32_t SAPLING_VERSION_GROUP_ID = 0x892F2085;
static_assert(SAPLING_VERSION_GROUP_ID != 0, "version group id must be non-zero as specified in ZIP 202");

enum {
    FLUXNODE_NO_TYPE = 1 << 0, // 00000001
    FLUXNODE_START_TX_TYPE = 1 << 1, // 00000010
    FLUXNODE_CONFIRM_TX_TYPE = 1 << 2, // 00000100
    FLUXNODE_HAS_COLLATERAL= 1 << 3, // 00001000
    FLUXNODE_TX_TYPE_UPGRADED = 1 << 7, // 10000000
};

struct CMutableTransaction;

/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
private:
    /** Memory only. */
    const uint256 hash;
    void UpdateHash() const;

protected:
    /** Developer testing only.  Set evilDeveloperFlag to true.
     * Convert a CMutableTransaction into a CTransaction without invoking UpdateHash()
     */
    CTransaction(const CMutableTransaction &tx, bool evilDeveloperFlag);

public:
    typedef std::array<unsigned char, 64> joinsplit_sig_t;
    typedef std::array<unsigned char, 64> binding_sig_t;

    // Transactions that include a list of JoinSplits are >= version 2.
    static const int32_t SPROUT_MIN_CURRENT_VERSION = 1;
    static const int32_t SPROUT_MAX_CURRENT_VERSION = 2;
    static const int32_t OVERWINTER_MIN_CURRENT_VERSION = 3;
    static const int32_t OVERWINTER_MAX_CURRENT_VERSION = 3;
    static const int32_t SAPLING_MIN_CURRENT_VERSION = 4;
    static const int32_t SAPLING_MAX_CURRENT_VERSION = 4;

    static_assert(SPROUT_MIN_CURRENT_VERSION >= SPROUT_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert(OVERWINTER_MIN_CURRENT_VERSION >= OVERWINTER_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (OVERWINTER_MAX_CURRENT_VERSION <= OVERWINTER_MAX_TX_VERSION &&
                    OVERWINTER_MAX_CURRENT_VERSION >= OVERWINTER_MIN_CURRENT_VERSION),
                  "standard rule for tx version should be consistent with network rule");

    static_assert(SAPLING_MIN_CURRENT_VERSION >= SAPLING_MIN_TX_VERSION,
                  "standard rule for tx version should be consistent with network rule");

    static_assert( (SAPLING_MAX_CURRENT_VERSION <= SAPLING_MAX_TX_VERSION &&
                    SAPLING_MAX_CURRENT_VERSION >= SAPLING_MIN_CURRENT_VERSION),
                  "standard rule for tx version should be consistent with network rule");

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const bool fOverwintered;
    const int32_t nVersion;
    const uint32_t nVersionGroupId;
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const uint32_t nLockTime;
    const uint32_t nExpiryHeight;
    const CAmount valueBalance;
    const std::vector<SpendDescription> vShieldedSpend;
    const std::vector<OutputDescription> vShieldedOutput;
    const std::vector<JSDescription> vJoinSplit;
    const uint256 joinSplitPubKey;
    const joinsplit_sig_t joinSplitSig = {{0}};
    const binding_sig_t bindingSig = {{0}};

    // Fluxnode Tx version 5 (Normal p2pkh nodes only)
    const int8_t nType;
    const COutPoint collateralIn; // collateral in
    const CPubKey collateralPubkey;
    const CPubKey pubKey; // Pubkey used for VPS signature verification
    const uint32_t sigTime; // Timestamp to be used for hash verification
    const std::string ip;
    const std::vector<unsigned char> sig;
    const int8_t benchmarkTier;
    const std::vector<unsigned char> benchmarkSig;
    const uint32_t benchmarkSigTime;
    const int8_t nUpdateType;

    // Fluxnode Tx Version 6 (Includes P2SH nodes ability)
    const int32_t nFluxTxVersion; // Adding this field for further upgradability to fluxnode txes in the future
    const CScript P2SHRedeemScript;
    
    // Delegate support (when FLUXNODE_TX_FEATURE_DELEGATES_BIT is set)
    const bool fUsingDelegates;
    const CFluxnodeDelegates delegateData;

    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    CTransaction& operator=(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint32_t header;
        if (ser_action.ForRead()) {
            // When deserializing, unpack the 4 byte header to extract fOverwintered and nVersion.
            READWRITE(header);
            *const_cast<bool*>(&fOverwintered) = header >> 31;
            *const_cast<int32_t*>(&this->nVersion) = header & 0x7FFFFFFF;
        } else {
            header = GetHeader();
            READWRITE(header);
        }
        if (fOverwintered) {
            READWRITE(*const_cast<uint32_t*>(&this->nVersionGroupId));
        }

        bool isOverwinterV3 =
            fOverwintered &&
            nVersionGroupId == OVERWINTER_VERSION_GROUP_ID &&
            nVersion == OVERWINTER_TX_VERSION;
        bool isSaplingV4 =
            fOverwintered &&
            nVersionGroupId == SAPLING_VERSION_GROUP_ID &&
            nVersion == SAPLING_TX_VERSION;
        if (fOverwintered && !(isOverwinterV3 || isSaplingV4)) {
            throw std::ios_base::failure("Unknown transaction format");
        }
        if (nVersion == FLUXNODE_TX_VERSION) {
            READWRITE(*const_cast<int8_t *>(&nType));
            if (nType == FLUXNODE_START_TX_TYPE) {
                READWRITE(*const_cast<COutPoint *>(&collateralIn));
                READWRITE(*const_cast<CPubKey *>(&collateralPubkey));
                READWRITE(*const_cast<CPubKey *>(&pubKey));
                READWRITE(*const_cast<uint32_t *>(&sigTime));
                if (!(s.GetType() & SER_GETHASH))
                    READWRITE(*const_cast<std::vector<unsigned char> *>(&sig));

            } else if (nType == FLUXNODE_CONFIRM_TX_TYPE) {
                READWRITE(*const_cast<COutPoint *>(&collateralIn));
                READWRITE(*const_cast<uint32_t *>(&sigTime));
                READWRITE(*const_cast<int8_t *>(&benchmarkTier));
                READWRITE(*const_cast<uint32_t *>(&benchmarkSigTime));
                READWRITE(*const_cast<int8_t *>(&nUpdateType));
                READWRITE(*const_cast<std::string *>(&ip));
                if (!(s.GetType() & SER_GETHASH)) {
                    READWRITE(*const_cast<std::vector<unsigned char> *>(&sig));
                    READWRITE(*const_cast<std::vector<unsigned char> *>(&benchmarkSig));
                }
            }
            if (ser_action.ForRead())
                UpdateHash();
            return;
        } else if (nVersion == FLUXNODE_TX_UPGRADEABLE_VERSION) { // Support P2SH and Normal Fluxnode Tx
            LogPrintf("FLUXNODE_TX_UPGRADEABLE_VERSION Found------------------------- %d\n", nVersion);
            READWRITE(*const_cast<int8_t*>(&nType)); // Start, Confirm

            if (nType == FLUXNODE_START_TX_TYPE) {
                READWRITE(*const_cast<int32_t *>(&nFluxTxVersion)); // Normal or P2SH
                
                // Check for backward compatibility (exact match) or bit-based check
                bool isNormalTx = (nFluxTxVersion == FLUXNODE_INTERNAL_NORMAL_TX_VERSION) || 
                                  ((nFluxTxVersion & FLUXNODE_TX_TYPE_NORMAL_BIT) != 0);
                bool isP2SHTx = (nFluxTxVersion == FLUXNODE_INTERNAL_P2SH_TX_VERSION) || 
                                ((nFluxTxVersion & FLUXNODE_TX_TYPE_P2SH_BIT) != 0);
                
                if (isNormalTx && !(nFluxTxVersion & FLUXNODE_TX_TYPE_P2SH_BIT)) {
                    READWRITE(*const_cast<COutPoint *>(&collateralIn));
                    READWRITE(*const_cast<CPubKey *>(&collateralPubkey));
                    READWRITE(*const_cast<CPubKey *>(&pubKey));
                    READWRITE(*const_cast<uint32_t *>(&sigTime));
                    if (!(s.GetType() & SER_GETHASH))
                        READWRITE(*const_cast<std::vector<unsigned char> *>(&sig));
                } else if (isP2SHTx) {
                    READWRITE(*const_cast<COutPoint *>(&collateralIn));
                    READWRITE(*const_cast<CPubKey *>(&pubKey));
                    READWRITE(*const_cast<CScriptBase *>((CScriptBase *) (&P2SHRedeemScript))); // New Addition to Tx
                    READWRITE(*const_cast<uint32_t *>(&sigTime));
                    if (!(s.GetType() & SER_GETHASH))
                        READWRITE(*const_cast<std::vector<unsigned char> *>(&sig));
                }
                
                // Handle delegate data if the feature bit is set
                if (HasFluxTxDelegatesFeature(nFluxTxVersion)) {
                    READWRITE(*const_cast<bool *>(&fUsingDelegates));
                    if (fUsingDelegates) {
                        READWRITE(*const_cast<CFluxnodeDelegates *>(&delegateData));
                    }
                }
            } else if (nType == FLUXNODE_CONFIRM_TX_TYPE) {
                READWRITE(*const_cast<COutPoint *>(&collateralIn));
                READWRITE(*const_cast<uint32_t *>(&sigTime));
                READWRITE(*const_cast<int8_t *>(&benchmarkTier));
                READWRITE(*const_cast<uint32_t *>(&benchmarkSigTime));
                READWRITE(*const_cast<int8_t *>(&nUpdateType));
                READWRITE(*const_cast<std::string *>(&ip));
                if (!(s.GetType() & SER_GETHASH)) {
                    READWRITE(*const_cast<std::vector<unsigned char> *>(&sig));
                    READWRITE(*const_cast<std::vector<unsigned char> *>(&benchmarkSig));
                }
            }
            if (ser_action.ForRead())
                UpdateHash();

            return;
        }

        READWRITE(*const_cast<std::vector<CTxIn>*>(&vin));
        READWRITE(*const_cast<std::vector<CTxOut>*>(&vout));
        READWRITE(*const_cast<uint32_t*>(&nLockTime));
        if (isOverwinterV3 || isSaplingV4) {
            READWRITE(*const_cast<uint32_t*>(&nExpiryHeight));
        }
        if (isSaplingV4) {
            READWRITE(*const_cast<CAmount*>(&valueBalance));
            READWRITE(*const_cast<std::vector<SpendDescription>*>(&vShieldedSpend));
            READWRITE(*const_cast<std::vector<OutputDescription>*>(&vShieldedOutput));
        }
        if (nVersion >= 2) {
            auto os = WithVersion(&s, static_cast<int>(header));
            ::SerReadWrite(os, *const_cast<std::vector<JSDescription>*>(&vJoinSplit), ser_action);
            if (vJoinSplit.size() > 0) {
                READWRITE(*const_cast<uint256*>(&joinSplitPubKey));
                READWRITE(*const_cast<joinsplit_sig_t*>(&joinSplitSig));
            }
        }
        if (isSaplingV4 && !(vShieldedSpend.empty() && vShieldedOutput.empty())) {
            READWRITE(*const_cast<binding_sig_t*>(&bindingSig));
        }
        if (ser_action.ForRead())
            UpdateHash();
    }

    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsFluxnodeTx() const {
        return nVersion == FLUXNODE_TX_VERSION || nVersion == FLUXNODE_TX_UPGRADEABLE_VERSION;
    }

    bool IsFluxnodeUpgradeTx() const {
        return nVersion == FLUXNODE_TX_UPGRADEABLE_VERSION;
    }

    bool IsFluxnodeUpgradedNormalTx() const {
        return IsFluxnodeUpgradeTx() && IsFluxTxNormalType(nFluxTxVersion, true);
    }

    bool IsFluxnodeUpgradedP2SHTx() const {
        return IsFluxnodeUpgradeTx() && IsFluxTxP2SHType(nFluxTxVersion, true);
    }
    
    bool HasDelegates() const {
        return IsFluxnodeUpgradeTx() && HasFluxTxDelegatesFeature(nFluxTxVersion);
    }

    bool IsSigningAsDelegate() const {
        return HasDelegates() && delegateData.IsValid() && delegateData.IsSigning();
    }

    bool IsUpdatingDelegate() const {
        return HasDelegates() && delegateData.IsValid() && delegateData.IsUpdating();
    }

    bool IsNull() const {
        return (vin.empty() && vout.empty() && !IsFluxnodeTx()) || (IsFluxnodeTx() && collateralIn.IsNull());
    }

    std::string TypeToString() const {
        if (nType == FLUXNODE_START_TX_TYPE) {
            return "Starting a fluxnode";
        } else if (nType == FLUXNODE_CONFIRM_TX_TYPE) {
            return "Confirming a fluxnode";
        } else {
            return "No type (Error)";
        }
    }

    const uint256& GetHash() const {
        return hash;
    }

    uint32_t GetHeader() const {
        // When serializing v1 and v2, the 4 byte header is nVersion
        uint32_t header = this->nVersion;
        // When serializing Overwintered tx, the 4 byte header is the combination of fOverwintered and nVersion
        if (fOverwintered) {
            header |= 1 << 31;
        }
        return header;
    }

    /*
     * Context for the two methods below:
     * As at most one of vpub_new and vpub_old is non-zero in every JoinSplit,
     * we can think of a JoinSplit as an input or output according to which one
     * it is (e.g. if vpub_new is non-zero the joinSplit is "giving value" to
     * the outputs in the transaction). Similarly, we can think of the Sapling
     * shielded part of the transaction as an input or output according to
     * whether valueBalance - the sum of shielded input values minus the sum of
     * shielded output values - is positive or negative.
     */

    // Return sum of txouts, (negative valueBalance or zero) and JoinSplit vpub_old.
    CAmount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    // Return sum of (positive valueBalance or zero) and JoinSplit vpub_new
    CAmount GetShieldedValueIn() const;

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    // Compute modified tx size for priority calculation (optionally given tx size)
    unsigned int CalculateModifiedSize(unsigned int nTxSize=0) const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    std::string ToString() const;
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    bool fOverwintered;
    int32_t nVersion;
    uint32_t nVersionGroupId;
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    uint32_t nLockTime;
    uint32_t nExpiryHeight;
    CAmount valueBalance;
    std::vector<SpendDescription> vShieldedSpend;
    std::vector<OutputDescription> vShieldedOutput;
    std::vector<JSDescription> vJoinSplit;
    uint256 joinSplitPubKey;
    CTransaction::joinsplit_sig_t joinSplitSig = {{0}};
    CTransaction::binding_sig_t bindingSig = {{0}};

    int8_t nType;
    COutPoint collateralIn; // collateral in
    CPubKey collateralPubkey;
    CPubKey pubKey; // Pubkey used for VPS signature verification
    uint32_t sigTime; // Timestamp to be used for hash verification
    std::string ip;
    std::vector<unsigned char> sig;
    int8_t benchmarkTier;
    std::vector<unsigned char> benchmarkSig;
    uint32_t benchmarkSigTime;
    int8_t nUpdateType;

    // P2SH Nodes -> If nType is certain number we introduce a new version that will allow to
    // customize the code even further.
    // Fluxnode Tx Version 6 (Includes P2SH nodes ability)
    int32_t nFluxTxVersion; // Adding this field for further upgradability to fluxnode txes in the future
    CScript P2SHRedeemScript;
    
    // Delegate support (when FLUXNODE_TX_FEATURE_DELEGATES_BIT is set)
    bool fUsingDelegates;
    CFluxnodeDelegates delegateData;

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        uint32_t header;
        if (ser_action.ForRead()) {
            // When deserializing, unpack the 4 byte header to extract fOverwintered and nVersion.
            READWRITE(header);
            fOverwintered = header >> 31;
            this->nVersion = header & 0x7FFFFFFF;
        } else {
            // When serializing v1 and v2, the 4 byte header is nVersion
            header = this->nVersion;
            // When serializing Overwintered tx, the 4 byte header is the combination of fOverwintered and nVersion
            if (fOverwintered) {
                header |= 1 << 31;
            }
            READWRITE(header);
        }
        if (fOverwintered) {
            READWRITE(nVersionGroupId);
        }

        bool isOverwinterV3 =
            fOverwintered &&
            nVersionGroupId == OVERWINTER_VERSION_GROUP_ID &&
            nVersion == OVERWINTER_TX_VERSION;
        bool isSaplingV4 =
            fOverwintered &&
            nVersionGroupId == SAPLING_VERSION_GROUP_ID &&
            nVersion == SAPLING_TX_VERSION;
        if (fOverwintered && !(isOverwinterV3 || isSaplingV4)) {
            throw std::ios_base::failure("Unknown transaction format");
        }

        // We use the operator ^ which is xor. XOR will return 0/false if the numbers match, and true/1 if they don't
        if (nVersion == FLUXNODE_TX_VERSION) {
            READWRITE(nType);
            if (nType == FLUXNODE_START_TX_TYPE) {
                READWRITE(collateralIn);
                READWRITE(collateralPubkey);
                READWRITE(pubKey);
                READWRITE(sigTime);
                if (!(s.GetType() & SER_GETHASH))
                    READWRITE(sig);

            } else if (nType == FLUXNODE_CONFIRM_TX_TYPE) {
                READWRITE(collateralIn);
                READWRITE(sigTime);
                READWRITE(benchmarkTier);
                READWRITE(benchmarkSigTime);
                READWRITE(nUpdateType);
                READWRITE(ip);
                if (!(s.GetType() & SER_GETHASH)) {
                    READWRITE(sig);
                    READWRITE(benchmarkSig);
                }
            }
            return;
        } else if (nVersion == FLUXNODE_TX_UPGRADEABLE_VERSION) {
            READWRITE(nType);
            if ((nType & FLUXNODE_START_TX_TYPE) == FLUXNODE_START_TX_TYPE) {
                READWRITE(nFluxTxVersion);
                
                // Check for backward compatibility (exact match) or bit-based check
                bool isNormalTx = (nFluxTxVersion == FLUXNODE_INTERNAL_NORMAL_TX_VERSION) || 
                                  ((nFluxTxVersion & FLUXNODE_TX_TYPE_NORMAL_BIT) != 0);
                bool isP2SHTx = (nFluxTxVersion == FLUXNODE_INTERNAL_P2SH_TX_VERSION) || 
                                ((nFluxTxVersion & FLUXNODE_TX_TYPE_P2SH_BIT) != 0);
                
                if (isNormalTx && !(nFluxTxVersion & FLUXNODE_TX_TYPE_P2SH_BIT)) {
                    READWRITE(collateralIn);
                    READWRITE(collateralPubkey);
                    READWRITE(pubKey);
                    READWRITE(sigTime);

                    if (!(s.GetType() & SER_GETHASH))
                        READWRITE(sig);
                } else if (isP2SHTx) {
                    READWRITE(collateralIn);
                    READWRITE(pubKey);
                    READWRITE(*(CScriptBase*)(&P2SHRedeemScript));
                    READWRITE(sigTime);
                    if (!(s.GetType() & SER_GETHASH))
                        READWRITE(sig);
                }
                
                // Handle delegate data if the feature bit is set
                if (HasFluxTxDelegatesFeature(nFluxTxVersion)) {
                    READWRITE(fUsingDelegates);
                    if (fUsingDelegates) {
                        READWRITE(delegateData);
                    }
                }
            } else if (nType == FLUXNODE_CONFIRM_TX_TYPE) {
                READWRITE(collateralIn);
                READWRITE(sigTime);
                READWRITE(benchmarkTier);
                READWRITE(benchmarkSigTime);
                READWRITE(nUpdateType);
                READWRITE(ip);
                if (!(s.GetType() & SER_GETHASH)) {
                    READWRITE(sig);
                    READWRITE(benchmarkSig);
                }
            }
            return;
        }

        READWRITE(vin);
        READWRITE(vout);
        READWRITE(nLockTime);
        if (isOverwinterV3 || isSaplingV4) {
            READWRITE(nExpiryHeight);
        }
        if (isSaplingV4) {
            READWRITE(valueBalance);
            READWRITE(vShieldedSpend);
            READWRITE(vShieldedOutput);
        }
        if (nVersion >= 2) {
            auto os = WithVersion(&s, static_cast<int>(header));
            ::SerReadWrite(os, vJoinSplit, ser_action);
            if (vJoinSplit.size() > 0) {
                READWRITE(joinSplitPubKey);
                READWRITE(joinSplitSig);
            }
        }
        if (isSaplingV4 && !(vShieldedSpend.empty() && vShieldedOutput.empty())) {
            READWRITE(bindingSig);
        }
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;

    std::string ToString() const;

    friend bool operator==(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return a.GetHash() == b.GetHash();
    }

    friend bool operator!=(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return !(a == b);
    }
};

// 1 Master key creates delgates.
// 2 delegates can start nodes
// 3 delegates cannot change delegates

// Gate lock delegates to be changes with only the pubkey that matches the collateral.

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
