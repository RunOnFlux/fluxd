// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "utiltest.h"

#include "consensus/upgrades.h"

#include <array>

CWalletTx GetValidReceive(ZCJoinSplit& params,
                          const libzelcash::SproutSpendingKey& sk, CAmount value,
                          bool randomInputs,
                          int32_t version /* = 2 */) {
    CMutableTransaction mtx;
    mtx.nVersion = version;
    mtx.vin.resize(2);
    if (randomInputs) {
        mtx.vin[0].prevout.hash = GetRandHash();
        mtx.vin[1].prevout.hash = GetRandHash();
    } else {
        mtx.vin[0].prevout.hash = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
        mtx.vin[1].prevout.hash = uint256S("0000000000000000000000000000000000000000000000000000000000000002");
    }
    mtx.vin[0].prevout.n = 0;
    mtx.vin[1].prevout.n = 0;

    // Generate an ephemeral keypair.
    uint256 joinSplitPubKey;
    unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(joinSplitPubKey.begin(), joinSplitPrivKey);
    mtx.joinSplitPubKey = joinSplitPubKey;

    std::array<libzelcash::JSInput, 2> inputs = {
        libzelcash::JSInput(), // dummy input
        libzelcash::JSInput() // dummy input
    };

    std::array<libzelcash::JSOutput, 2> outputs = {
        libzelcash::JSOutput(sk.address(), value),
        libzelcash::JSOutput(sk.address(), value)
    };

    // Prepare JoinSplits
    uint256 rt;
    JSDescription jsdesc {false, params, mtx.joinSplitPubKey, rt,
                          inputs, outputs, 2*value, 0, false};
    mtx.vjoinsplit.push_back(jsdesc);

    if (version >= 4) {
        // Shielded Output
        OutputDescription od;
        mtx.vShieldedOutput.push_back(od);
    }

    // Empty output script.
    uint32_t consensusBranchId = SPROUT_BRANCH_ID;
    CScript scriptCode;
    CTransaction signTx(mtx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId);

    // Add the signature
    assert(crypto_sign_detached(&mtx.joinSplitSig[0], NULL,
                                dataToBeSigned.begin(), 32,
                                joinSplitPrivKey
                               ) == 0);

    CTransaction tx {mtx};
    CWalletTx wtx {NULL, tx};
    return wtx;
}

<<<<<<< HEAD
libzelcash::SproutNote GetNote(ZCJoinSplit& params,
                       const libzelcash::SproutSpendingKey& sk,
                       const CTransaction& tx, size_t js, size_t n) {
    ZCNoteDecryption decryptor {sk.receiving_key()};
    auto hSig = tx.vjoinsplit[js].h_sig(params, tx.joinSplitPubKey);
    auto note_pt = libzelcash::SproutNotePlaintext::decrypt(
=======
libzelcash::Note GetNote(ZCJoinSplit& params,
                       const libzelcash::SpendingKey& sk,
                       const CTransaction& tx, size_t js, size_t n) {
    ZCNoteDecryption decryptor {sk.receiving_key()};
    auto hSig = tx.vjoinsplit[js].h_sig(params, tx.joinSplitPubKey);
    auto note_pt = libzelcash::NotePlaintext::decrypt(
>>>>>>> adfdef7... initial ZEL changes to Overwinter
        decryptor,
        tx.vjoinsplit[js].ciphertexts[n],
        tx.vjoinsplit[js].ephemeralKey,
        hSig,
        (unsigned char) n);
    return note_pt.note(sk.address());
}

CWalletTx GetValidSpend(ZCJoinSplit& params,
<<<<<<< HEAD
                        const libzelcash::SproutSpendingKey& sk,
                        const libzelcash::SproutNote& note, CAmount value) {
=======
                        const libzelcash::SpendingKey& sk,
                        const libzelcash::Note& note, CAmount value) {
>>>>>>> adfdef7... initial ZEL changes to Overwinter
    CMutableTransaction mtx;
    mtx.vout.resize(2);
    mtx.vout[0].nValue = value;
    mtx.vout[1].nValue = 0;

    // Generate an ephemeral keypair.
    uint256 joinSplitPubKey;
    unsigned char joinSplitPrivKey[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(joinSplitPubKey.begin(), joinSplitPrivKey);
    mtx.joinSplitPubKey = joinSplitPubKey;

    // Fake tree for the unused witness
    SproutMerkleTree tree;

    libzelcash::JSOutput dummyout;
    libzelcash::JSInput dummyin;

    {
<<<<<<< HEAD
        if (note.value() > value) {
            libzelcash::SproutSpendingKey dummykey = libzelcash::SproutSpendingKey::random();
            libzelcash::SproutPaymentAddress dummyaddr = dummykey.address();
            dummyout = libzelcash::JSOutput(dummyaddr, note.value() - value);
        } else if (note.value() < value) {
            libzelcash::SproutSpendingKey dummykey = libzelcash::SproutSpendingKey::random();
            libzelcash::SproutPaymentAddress dummyaddr = dummykey.address();
            libzelcash::SproutNote dummynote(dummyaddr.a_pk, (value - note.value()), uint256(), uint256());
=======
        if (note.value > value) {
            libzelcash::SpendingKey dummykey = libzelcash::SpendingKey::random();
            libzelcash::PaymentAddress dummyaddr = dummykey.address();
            dummyout = libzelcash::JSOutput(dummyaddr, note.value - value);
        } else if (note.value < value) {
            libzelcash::SpendingKey dummykey = libzelcash::SpendingKey::random();
            libzelcash::PaymentAddress dummyaddr = dummykey.address();
            libzelcash::Note dummynote(dummyaddr.a_pk, (value - note.value), uint256(), uint256());
>>>>>>> adfdef7... initial ZEL changes to Overwinter
            tree.append(dummynote.cm());
            dummyin = libzelcash::JSInput(tree.witness(), dummynote, dummykey);
        }
    }

    tree.append(note.cm());

<<<<<<< HEAD
    std::array<libzelcash::JSInput, 2> inputs = {
        libzelcash::JSInput(tree.witness(), note, sk),
        dummyin
    };

    std::array<libzelcash::JSOutput, 2> outputs = {
=======
    boost::array<libzelcash::JSInput, 2> inputs = {
        libzelcash::JSInput(tree.witness(), note, sk),
        dummyin
    };

    boost::array<libzelcash::JSOutput, 2> outputs = {
>>>>>>> adfdef7... initial ZEL changes to Overwinter
        dummyout, // dummy output
        libzelcash::JSOutput() // dummy output
    };

<<<<<<< HEAD
=======
    boost::array<libzelcash::Note, 2> output_notes;

>>>>>>> adfdef7... initial ZEL changes to Overwinter
    // Prepare JoinSplits
    uint256 rt = tree.root();
    JSDescription jsdesc {false, params, mtx.joinSplitPubKey, rt,
                          inputs, outputs, 0, value, false};
    mtx.vjoinsplit.push_back(jsdesc);

    // Empty output script.
    uint32_t consensusBranchId = SPROUT_BRANCH_ID;
    CScript scriptCode;
    CTransaction signTx(mtx);
    uint256 dataToBeSigned = SignatureHash(scriptCode, signTx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId);

    // Add the signature
    assert(crypto_sign_detached(&mtx.joinSplitSig[0], NULL,
                                dataToBeSigned.begin(), 32,
                                joinSplitPrivKey
                               ) == 0);
    CTransaction tx {mtx};
    CWalletTx wtx {NULL, tx};
    return wtx;
}
