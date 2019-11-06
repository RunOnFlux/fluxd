#ifndef ZC_JOINSPLIT_H_
#define ZC_JOINSPLIT_H_

#include "Zelcash.h"
#include "Proof.hpp"
#include "Address.hpp"
#include "Note.hpp"
#include "IncrementalMerkleTree.hpp"
#include "NoteEncryption.hpp"

#include "uint256.h"
#include "uint252.h"

#include <array>

namespace libzelcash {

static constexpr size_t GROTH_PROOF_SIZE = (
    48 + // π_A
    96 + // π_B
    48); // π_C

typedef std::array<unsigned char, GROTH_PROOF_SIZE> GrothProof;
typedef boost::variant<PHGRProof, GrothProof> SproutProof;

class JSInput {
public:
    SproutWitness witness;
    SproutNote note;
    SproutSpendingKey key;

    JSInput();
    JSInput(SproutWitness witness,
            SproutNote note,
            SproutSpendingKey key) : witness(witness), note(note), key(key) { }

    uint256 nullifier() const {
        return note.nullifier(key);
    }
};

class JSOutput {
public:
    SproutPaymentAddress addr;
    uint64_t value;
    std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}};  // 0xF6 is invalid UTF8 as per spec, rest of array is 0x00

    JSOutput();
    JSOutput(SproutPaymentAddress addr, uint64_t value) : addr(addr), value(value) { }

    SproutNote note(const uint252& phi, const uint256& r, size_t i, const uint256& h_sig) const;
};

template<size_t NumInputs, size_t NumOutputs>
class JoinSplit {
public:
    virtual ~JoinSplit() {}

    static JoinSplit<NumInputs, NumOutputs>* Prepared();

    static uint256 h_sig(const uint256& randomSeed,
                         const std::array<uint256, NumInputs>& nullifiers,
                         const uint256& joinSplitPubKey
                        );

    // Compute nullifiers, macs, note commitments & encryptions, and SNARK proof
    virtual SproutProof prove(
        const std::array<JSInput, NumInputs>& inputs,
        const std::array<JSOutput, NumOutputs>& outputs,
        std::array<SproutNote, NumOutputs>& out_notes,
        std::array<ZCNoteEncryption::Ciphertext, NumOutputs>& out_ciphertexts,
        uint256& out_ephemeralKey,
        const uint256& joinSplitPubKey,
        uint256& out_randomSeed,
        std::array<uint256, NumInputs>& out_hmacs,
        std::array<uint256, NumInputs>& out_nullifiers,
        std::array<uint256, NumOutputs>& out_commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt,
        bool computeProof = true,
        // For paymentdisclosure, we need to retrieve the esk.
        // Reference as non-const parameter with default value leads to compile error.
        // So use pointer for simplicity.
        uint256 *out_esk = nullptr
    ) = 0;

protected:
    JoinSplit() {}
};

}

typedef libzelcash::JoinSplit<ZC_NUM_JS_INPUTS,
                            ZC_NUM_JS_OUTPUTS> ZCJoinSplit;

#endif // ZC_JOINSPLIT_H_
