"""Tests script decoding via the ``decodescript`` and ``decoderawtransaction`` RPCs.

Verifies the human-readable ``asm`` rendering of every standard script form, for
both scriptSig and scriptPubKey, plus the sighash-type annotation ([ALL],
[NONE|ANYONECANPAY]) appended to signatures inside decoded raw transactions. All
inputs are literal hex; no chain state is required.
"""

from conftest import NodeFactory

# A real single-input mainnet P2SH-multisig transaction, split into the bytes
# that surround its scriptSig so crafted scriptSig variants can be spliced in by
# string construction (the legacy test mutated a deserialized CTransaction; the
# mininode serializer is not ported).
TX_HEADER = "01000000018d1f5635abd06e2c7e2ddf58dc85b3de111e4ad6e0ab51bb0dcf5e84126d927300000000"
TX_SUFFIX = (
    "ffffffff02611e0000000000001976a914dc863734a218bfe83ef770ee9d41a27f824a6e5688ac"
    "ee2a02000000000017a9142a5edea39971049a540474c6a99edf0aa4074c588700000000"
)

# The transaction's real 2-of-3 P2SH-multisig scriptSig: OP_0 <sigA> <sigB>
# <redeemScript>. Shared so the multisig and DER-lookalike cases stay in sync.
MULTISIG_SCRIPTSIG = (
    "00483045022100ae3b4e589dfc9d48cb82d41008dc5fa6a86f94d5c54f9935531924602730"
    "ab8002202f88cf464414c4ed9fa11b773c5ee944f66e9b05cc1e51d97abc22ce098937ea01"
    "483045022100b44883be035600e9328a01b66c7d8439b74db64187e76b99a68f7893b701d5"
    "380220225bf286493e4c4adcf928c40f785422572eb232f84a0b83b0dea823c3a19c75014c"
    "695221020743d44be989540d27b1b4bbbcfd17721c337cb6bc9af20eb8a32520b393532f21"
    "02c0120a1dda9e51a938d39ddd9fe0ebc45ea97e1d27a7cbd671d5431416d3dd8721021382"
    "0eb3d5f509d7438c9eeecb4157b2f595105e7cd564b3cdbb9ead3da41eed53ae"
)
# Its first signature push (the leading OP_0 byte stripped).
FIRST_SIG_PUSH = MULTISIG_SCRIPTSIG[2:148]


def _compact_size(n: int) -> str:
    """Bitcoin CompactSize encoding of ``n`` as hex (covers scriptSig lengths)."""
    if n < 0xFD:
        return f"{n:02x}"
    if n <= 0xFFFF:
        return f"fd{n & 0xFF:02x}{(n >> 8) & 0xFF:02x}"
    raise ValueError(f"scriptSig length {n} out of supported range")


def _tx_with_scriptsig(scriptsig_hex: str) -> str:
    """Rebuild the single-input transaction with ``scriptsig_hex`` in vin[0]."""
    length = len(bytes.fromhex(scriptsig_hex))
    return f"{TX_HEADER}{_compact_size(length)}{scriptsig_hex}{TX_SUFFIX}"


async def test_decodescript_script_sig(node_factory: NodeFactory) -> None:
    """scriptSig 'asm' decodes for the standard transaction types."""
    node = await node_factory(0)

    signature = (
        "304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a"
        "022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001"
    )
    push_signature = "48" + signature
    public_key = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2"
    push_public_key = "21" + public_key

    # P2PK scriptSig: simply pushes a signature onto the stack.
    rpc_result = await node.rpc.decodescript(push_signature)
    assert rpc_result["asm"] == signature

    # P2PKH scriptSig: signature then public key.
    rpc_result = await node.rpc.decodescript(push_signature + push_public_key)
    assert rpc_result["asm"] == signature + " " + public_key

    # Multisig scriptSig (also the leading portion of a P2SH multisig scriptSig):
    # OP_0 <A sig> <B sig>.
    rpc_result = await node.rpc.decodescript("00" + push_signature + push_signature)
    assert rpc_result["asm"] == "0 " + signature + " " + signature

    # P2SH scriptSig: an empty redeemScript is valid and the simplest case.
    rpc_result = await node.rpc.decodescript("5100")
    assert rpc_result["asm"] == "1 0"

    # Null-data scriptSig has no test case: null-data scripts cannot be spent.


async def test_decodescript_script_pub_key(node_factory: NodeFactory) -> None:
    """scriptPubKey 'asm' decodes for the standard transaction types."""
    node = await node_factory(0)

    public_key = "03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2"
    push_public_key = "21" + public_key
    public_key_hash = "11695b6cd891484c2d49ec5aa738ec2b2f897777"
    push_public_key_hash = "14" + public_key_hash

    # P2PK scriptPubKey: <pubkey> OP_CHECKSIG.
    rpc_result = await node.rpc.decodescript(push_public_key + "ac")
    assert rpc_result["asm"] == public_key + " OP_CHECKSIG"

    # P2PKH scriptPubKey: OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG.
    rpc_result = await node.rpc.decodescript("76a9" + push_public_key_hash + "88ac")
    assert (
        rpc_result["asm"] == "OP_DUP OP_HASH160 " + public_key_hash + " OP_EQUALVERIFY OP_CHECKSIG"
    )

    # Multisig scriptPubKey: <m> <A> <B> <C> <n> OP_CHECKMULTISIG. The repeated
    # key is irrelevant to the decode being tested.
    rpc_result = await node.rpc.decodescript(
        "52" + push_public_key + push_public_key + push_public_key + "53ae"
    )
    assert (
        rpc_result["asm"]
        == "2 " + public_key + " " + public_key + " " + public_key + " 3 OP_CHECKMULTISIG"
    )

    # P2SH scriptPubKey: OP_HASH160 <Hash160(redeemScript)> OP_EQUAL. The hash
    # value is arbitrary for the decode.
    rpc_result = await node.rpc.decodescript("a9" + push_public_key_hash + "87")
    assert rpc_result["asm"] == "OP_HASH160 " + public_key_hash + " OP_EQUAL"

    # Null-data scriptPubKey. A signature look-alike confirms random pushed data
    # is not mistaken for a signature (no sighash decoding on a scriptPubKey).
    signature_imposter = (
        "48304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a"
        "022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001"
    )
    rpc_result = await node.rpc.decodescript("6a" + signature_imposter)
    assert rpc_result["asm"] == "OP_RETURN " + signature_imposter[2:]

    # A CLTV redeem script (a scriptPubKey-shaped script). OP_NOP2 is
    # OP_CHECKLOCKTIMEVERIFY; lock until block 500,000.
    rpc_result = await node.rpc.decodescript(
        "63" + push_public_key + "ad670320a107b17568" + push_public_key + "ac"
    )
    assert rpc_result["asm"] == (
        "OP_IF " + public_key + " OP_CHECKSIGVERIFY OP_ELSE 500000 OP_NOP2 OP_DROP "
        "OP_ENDIF " + public_key + " OP_CHECKSIG"
    )


async def test_decoderawtransaction_p2pkh_input(node_factory: NodeFactory) -> None:
    """A plain mainnet P2PKH tx decodes its scriptSig asm with the [ALL] sighash."""
    node = await node_factory(0)

    tx = (
        "0100000001696a20784a2c70143f634e95227dbdfdf0ecd51647052e70854512235f5986ca"
        "010000008a47304402207174775824bec6c2700023309a168231ec80b82c6069282f5133e6"
        "f11cbb04460220570edc55c7c5da2ca687ebd0372d3546ebc3f810516a002350cac72dfe19"
        "2dfb014104d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544"
        "fc7088d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536ffffffff01"
        "00e1f505000000001976a914eb6c6e0cdb2d256a32d97b8df1fc75d1920d9bca88ac00000000"
    )
    rpc_result = await node.rpc.decoderawtransaction(tx)
    assert rpc_result["vin"][0]["scriptSig"]["asm"] == (
        "304402207174775824bec6c2700023309a168231ec80b82c6069282f5133e6f11cbb0446"
        "0220570edc55c7c5da2ca687ebd0372d3546ebc3f810516a002350cac72dfe192dfb[ALL] "
        "04d3f898e6487787910a690410b7a917ef198905c27fb9d3b0a42da12aceae0544fc7088"
        "d239d9a48f2828a15a09e84043001f27cc80d162cb95404e1210161536"
    )


async def test_decoderawtransaction_p2sh_multisig_input(node_factory: NodeFactory) -> None:
    """A mainnet P2SH tx decodes its txid, multisig scriptSig and both outputs."""
    node = await node_factory(0)

    tx = _tx_with_scriptsig(MULTISIG_SCRIPTSIG)
    rpc_result = await node.rpc.decoderawtransaction(tx)
    assert rpc_result["txid"] == "8e3730608c3b0bb5df54f09076e196bc292a8e39a78e73b44b6ba08c78f5cbb0"
    assert rpc_result["vin"][0]["scriptSig"]["asm"] == (
        "0 3045022100ae3b4e589dfc9d48cb82d41008dc5fa6a86f94d5c54f99355319246027"
        "30ab8002202f88cf464414c4ed9fa11b773c5ee944f66e9b05cc1e51d97abc22ce0989"
        "37ea[ALL] 3045022100b44883be035600e9328a01b66c7d8439b74db64187e76b99a6"
        "8f7893b701d5380220225bf286493e4c4adcf928c40f785422572eb232f84a0b83b0de"
        "a823c3a19c75[ALL] 5221020743d44be989540d27b1b4bbbcfd17721c337cb6bc9af2"
        "0eb8a32520b393532f2102c0120a1dda9e51a938d39ddd9fe0ebc45ea97e1d27a7cbd6"
        "71d5431416d3dd87210213820eb3d5f509d7438c9eeecb4157b2f595105e7cd564b3cd"
        "bb9ead3da41eed53ae"
    )
    assert rpc_result["vout"][0]["scriptPubKey"]["asm"] == (
        "OP_DUP OP_HASH160 dc863734a218bfe83ef770ee9d41a27f824a6e56 OP_EQUALVERIFY OP_CHECKSIG"
    )
    assert rpc_result["vout"][1]["scriptPubKey"]["asm"] == (
        "OP_HASH160 2a5edea39971049a540474c6a99edf0aa4074c58 OP_EQUAL"
    )


async def test_decoderawtransaction_op_return_not_sighash(node_factory: NodeFactory) -> None:
    """A crafted OP_RETURN value is not mistaken for a signature/sighash type."""
    node = await node_factory(0)

    tx = (
        "01000000015ded05872fdbda629c7d3d02b194763ce3b9b1535ea884e3c8e765d42e316724"
        "020000006b48304502204c10d4064885c42638cbff3585915b322de33762598321145ba033"
        "fc796971e2022100bb153ad3baa8b757e30a2175bd32852d2e1cb9080f84d7e32fcdfd6679"
        "34ef1b012103163c0ff73511ea1743fb5b98384a2ff09dd06949488028fd819f4d83f56264"
        "efffffffff0200000000000000000b6a0930060201000201000180380100000000001976a9"
        "141cabd296e753837c086da7a45a6c2fe0d49d7b7b88ac00000000"
    )
    rpc_result = await node.rpc.decoderawtransaction(tx)
    assert rpc_result["vout"][0]["scriptPubKey"]["asm"] == "OP_RETURN 300602010002010001"


async def test_decoderawtransaction_der_lookalike_hashes(node_factory: NodeFactory) -> None:
    """P2PKH/P2SH output hashes crafted to pass DER checks still decode as hashes."""
    node = await node_factory(0)

    tx = _tx_with_scriptsig(MULTISIG_SCRIPTSIG)
    # Replace both output script hashes with DER-signature look-alikes; the asm
    # must still render them as plain 20-byte hashes, not signatures.
    crafted_hash = "3011020701010101010101020601010101010101"
    tx = tx.replace("dc863734a218bfe83ef770ee9d41a27f824a6e56", crafted_hash)
    tx = tx.replace("2a5edea39971049a540474c6a99edf0aa4074c58", crafted_hash)
    rpc_result = await node.rpc.decoderawtransaction(tx)
    assert rpc_result["vout"][0]["scriptPubKey"]["asm"] == (
        f"OP_DUP OP_HASH160 {crafted_hash} OP_EQUALVERIFY OP_CHECKSIG"
    )
    assert rpc_result["vout"][1]["scriptPubKey"]["asm"] == f"OP_HASH160 {crafted_hash} OP_EQUAL"


async def test_decoderawtransaction_scriptsig_sighash_variants(node_factory: NodeFactory) -> None:
    """Crafted scriptSigs exercise [ALL], [NONE|ANYONECANPAY], multisig and OP_RETURN decodes.

    The decodescript RPC only handles scriptPubKeys, so these scriptSig sighash
    decodes are tested through decoderawtransaction by splicing each crafted
    scriptSig into the known single-input transaction.
    """
    node = await node_factory(0)

    # The first signature push from the known P2SH-multisig scriptSig.
    push_signature = FIRST_SIG_PUSH
    signature = push_signature[2:]
    der_signature = signature[:-2]  # strip the trailing 01 (SIGHASH_ALL) byte
    signature_sighash_decoded = der_signature + "[ALL]"

    # A second signature reusing the same DER body but with sighash byte 0x82
    # (SIGHASH_NONE | SIGHASH_ANYONECANPAY).
    signature_2 = der_signature + "82"
    push_signature_2 = "48" + signature_2
    signature_2_sighash_decoded = der_signature + "[NONE|ANYONECANPAY]"

    # P2PK scriptSig: a single signature push, [ALL].
    rpc_result = await node.rpc.decoderawtransaction(_tx_with_scriptsig(push_signature))
    assert rpc_result["vin"][0]["scriptSig"]["asm"] == signature_sighash_decoded

    # The same single push with the rarer [NONE|ANYONECANPAY] sighash type.
    rpc_result = await node.rpc.decoderawtransaction(_tx_with_scriptsig(push_signature_2))
    assert rpc_result["vin"][0]["scriptSig"]["asm"] == signature_2_sighash_decoded

    # Multisig scriptSig: OP_0 then both signatures, each sighash-decoded.
    rpc_result = await node.rpc.decoderawtransaction(
        _tx_with_scriptsig("00" + push_signature + push_signature_2)
    )
    assert rpc_result["vin"][0]["scriptSig"]["asm"] == (
        "0 " + signature_sighash_decoded + " " + signature_2_sighash_decoded
    )

    # A scriptSig with more than push operations: an OP_RETURN whose data is
    # crafted to provoke a bad decode if sighash handling is not guarded.
    rpc_result = await node.rpc.decoderawtransaction(
        _tx_with_scriptsig("6a143011020701010101010101020601010101010101")
    )
    assert (
        rpc_result["vin"][0]["scriptSig"]["asm"]
        == "OP_RETURN 3011020701010101010101020601010101010101"
    )
