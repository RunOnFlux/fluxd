"""fundrawtransaction: input selection, change, fees, multisig, and a locked wallet.

Covers the full legacy matrix in one ordered flow (scenarios consume the wallet's
utxos as they go): funding a raw tx with no inputs (simple, two-coin, two-output),
supplying inputs that exceed / fall short of the required amount (change omitted or
added), two-vin and two-vin/two-vout funding, an invalid vin that must error
"Insufficient", fee parity with sendtoaddress / sendmany for pubkeyhash, 2of2 and
4of5 multisig outputs, spending a 2of2 over fundraw, the locked (encrypted) wallet
that cannot send until unlocked, the ~19-small-input fee and sign/send paths, and
OP_RETURN funding.
"""

from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# A positive fee delta above this fails the comparison; a negative delta always
# fails. fundrawtransaction may pick a slightly larger fee than sendtoaddress.
FEE_TOLERANCE = Decimal("0.00000002")
NODE_ARGS = [*POW_ARGS, "-experimentalfeatures", "-developerencryptwallet"]


async def _total_out(node: FluxNode, rawhex: str) -> Decimal:
    dec = await node.rpc.decoderawtransaction(rawhex)
    return sum((out["value"] for out in dec["vout"]), Decimal(0))


async def _find_unspent(node: FluxNode, amount: Decimal) -> dict:
    # Skip the unsignable P2SH fund outputs Flux lists on regtest coinbases.
    for utx in await node.rpc.listunspent():
        if utx["amount"] == amount and utx["spendable"]:
            return utx
    raise AssertionError(f"no spendable utxo of {amount} on node {node.index}")


async def _multisig_address(node: FluxNode, required: int, count: int) -> str:
    pubkeys = []
    for _ in range(count):
        addr = await node.rpc.getnewaddress()
        pubkeys.append((await node.rpc.validateaddress(addr))["pubkey"])
    return await node.rpc.addmultisigaddress(required, pubkeys)


async def _received(node: FluxNode, txid: str) -> Decimal:
    """Total amount received by ``node``'s wallet in ``txid``."""
    details = (await node.rpc.gettransaction(txid))["details"]
    return sum((d["amount"] for d in details if d["category"] == "receive"), Decimal(0))


async def test_fundrawtransaction(node_factory: NodeFactory) -> None:
    n0 = await node_factory(0, extra_args=NODE_ARGS)
    n1 = await node_factory(1, extra_args=NODE_ARGS)
    n2 = await node_factory(2, extra_args=NODE_ARGS)
    await connect_nodes_bi(n0, n1)
    await connect_nodes_bi(n1, n2)
    await connect_nodes_bi(n0, n2)
    await sync_blocks([n0, n1, n2])

    # node2 mines block 1 (the premine); node0 mines enough to mature a coinbase
    # it can spend, then funds node2 with the 1.5/1.0/5.0 utxos the scenarios pick.
    await n2.mine(1)
    await sync_blocks([n0, n1, n2])
    await n0.mine(COINBASE_MATURITY + 1)
    await sync_blocks([n0, n1, n2])
    for amount in (1.5, 1.0, 5.0):
        await n0.rpc.sendtoaddress(await n2.rpc.getnewaddress(), amount)
    await n0.mine(1)
    await sync_blocks([n0, n1, n2])

    # Simple: a raw tx with no inputs gets at least one funding vin.
    for out_amount in (1.0, 2.2):
        rawtx = await n2.rpc.createrawtransaction([], {await n0.rpc.getnewaddress(): out_amount})
        funded = await n2.rpc.fundrawtransaction(rawtx)
        dec = await n2.rpc.decoderawtransaction(funded["hex"])
        assert len(dec["vin"]) > 0

    # A funding-added input has an empty scriptSig.
    rawtx = await n2.rpc.createrawtransaction([], {await n0.rpc.getnewaddress(): 2.6})
    funded = await n2.rpc.fundrawtransaction(rawtx)
    dec = await n2.rpc.decoderawtransaction(funded["hex"])
    assert len(dec["vin"]) > 0
    assert dec["vin"][0]["scriptSig"]["hex"] == ""

    # Two outputs.
    outputs = {await n0.rpc.getnewaddress(): 2.6, await n1.rpc.getnewaddress(): 2.5}
    rawtx = await n2.rpc.createrawtransaction([], outputs)
    funded = await n2.rpc.fundrawtransaction(rawtx)
    dec = await n2.rpc.decoderawtransaction(funded["hex"])
    assert len(dec["vin"]) > 0
    assert dec["vin"][0]["scriptSig"]["hex"] == ""

    # A supplied 5.0 vin covers a 1.0 output; fee + total out equals the vin.
    utx = await _find_unspent(n2, Decimal("5.0"))
    inputs = [{"txid": utx["txid"], "vout": utx["vout"]}]
    rawtx = await n2.rpc.createrawtransaction(inputs, {await n0.rpc.getnewaddress(): 1.0})
    dec = await n2.rpc.decoderawtransaction(rawtx)
    assert dec["vin"][0]["txid"] == utx["txid"]
    funded = await n2.rpc.fundrawtransaction(rawtx)
    fee = funded["fee"]
    assert fee + await _total_out(n2, funded["hex"]) == utx["amount"]

    # No change output when the output consumes (vin - fee).
    utx = await _find_unspent(n2, Decimal("5.0"))
    inputs = [{"txid": utx["txid"], "vout": utx["vout"]}]
    out_amount = Decimal("5.0") - fee - FEE_TOLERANCE
    rawtx = await n2.rpc.createrawtransaction(inputs, {await n0.rpc.getnewaddress(): out_amount})
    dec = await n2.rpc.decoderawtransaction(rawtx)
    assert dec["vin"][0]["txid"] == utx["txid"]
    funded = await n2.rpc.fundrawtransaction(rawtx)
    fee = funded["fee"]
    assert funded["changepos"] == -1
    assert fee + await _total_out(n2, funded["hex"]) == utx["amount"]

    # A 1.0 vin under a 1.0 output forces a second vin and a change output.
    utx = await _find_unspent(n2, Decimal("1.0"))
    addr = await n0.rpc.getnewaddress()
    inputs = [{"txid": utx["txid"], "vout": utx["vout"]}]
    rawtx = await n2.rpc.createrawtransaction(inputs, {addr: 1.0})
    # Splice a one-byte (00) scriptSig into the single vin: 4-byte version + 1-byte
    # vin count + 36-byte prevout = 82 hex chars, then the script-len byte.
    rawtx = rawtx[:82] + "0100" + rawtx[84:]
    dec = await n2.rpc.decoderawtransaction(rawtx)
    assert dec["vin"][0]["txid"] == utx["txid"]
    assert dec["vin"][0]["scriptSig"]["hex"] == "00"
    funded = await n2.rpc.fundrawtransaction(rawtx)
    dec = await n2.rpc.decoderawtransaction(funded["hex"])
    matching_outs = 0
    for i, out in enumerate(dec["vout"]):
        if out["scriptPubKey"]["addresses"][0] == addr:
            matching_outs += 1
        else:
            assert i == funded["changepos"]
    assert dec["vin"][0]["txid"] == utx["txid"]
    assert dec["vin"][0]["scriptSig"]["hex"] == "00"
    assert matching_outs == 1
    assert len(dec["vout"]) == 2

    # Two supplied vins.
    utx = await _find_unspent(n2, Decimal("1.0"))
    utx2 = await _find_unspent(n2, Decimal("5.0"))
    addr = await n0.rpc.getnewaddress()
    inputs = [
        {"txid": utx["txid"], "vout": utx["vout"]},
        {"txid": utx2["txid"], "vout": utx2["vout"]},
    ]
    rawtx = await n2.rpc.createrawtransaction(inputs, {addr: 6.0})
    dec = await n2.rpc.decoderawtransaction(rawtx)
    assert dec["vin"][0]["txid"] == utx["txid"]
    funded = await n2.rpc.fundrawtransaction(rawtx)
    dec = await n2.rpc.decoderawtransaction(funded["hex"])
    matching_outs = sum(1 for out in dec["vout"] if out["scriptPubKey"]["addresses"][0] == addr)
    assert matching_outs == 1
    assert len(dec["vout"]) == 2
    given = {vin["txid"] for vin in inputs}
    matching_ins = sum(1 for vin in dec["vin"] if vin["txid"] in given)
    assert matching_ins == 2

    # Two supplied vins and two vouts.
    utx = await _find_unspent(n2, Decimal("1.0"))
    utx2 = await _find_unspent(n2, Decimal("5.0"))
    addr_a = await n0.rpc.getnewaddress()
    addr_b = await n0.rpc.getnewaddress()
    inputs = [
        {"txid": utx["txid"], "vout": utx["vout"]},
        {"txid": utx2["txid"], "vout": utx2["vout"]},
    ]
    outputs = {addr_a: 6.0, addr_b: 1.0}
    rawtx = await n2.rpc.createrawtransaction(inputs, outputs)
    dec = await n2.rpc.decoderawtransaction(rawtx)
    assert dec["vin"][0]["txid"] == utx["txid"]
    funded = await n2.rpc.fundrawtransaction(rawtx)
    dec = await n2.rpc.decoderawtransaction(funded["hex"])
    matching_outs = sum(1 for out in dec["vout"] if out["scriptPubKey"]["addresses"][0] in outputs)
    assert matching_outs == 2
    assert len(dec["vout"]) == 3

    # An invalid vin must error "Insufficient".
    inputs = [
        {"txid": "1c7f966dab21119bac53213a2bc7532bff1fa844c124fd750a7d0b1332440bd1", "vout": 0}
    ]
    rawtx = await n2.rpc.createrawtransaction(inputs, {await n0.rpc.getnewaddress(): 1.0})
    with pytest.raises(JSONRPCError) as exc:
        await n2.rpc.fundrawtransaction(rawtx)
    assert "Insufficient" in str(exc.value)

    # Fee parity: pubkeyhash, single output.
    rawtx = await n0.rpc.createrawtransaction([], {await n1.rpc.getnewaddress(): 1.1})
    funded = await n0.rpc.fundrawtransaction(rawtx)
    txid = await n0.rpc.sendtoaddress(await n1.rpc.getnewaddress(), 1.1)
    signed_fee = (await n0.rpc.getrawmempool(True))[txid]["fee"]
    fee_delta = funded["fee"] - signed_fee
    assert 0 <= fee_delta <= FEE_TOLERANCE

    # Fee parity: pubkeyhash, multiple outputs (vs sendmany).
    outputs = {
        await n1.rpc.getnewaddress(): 1.1,
        await n1.rpc.getnewaddress(): 1.2,
        await n1.rpc.getnewaddress(): 0.1,
        await n1.rpc.getnewaddress(): 1.3,
        await n1.rpc.getnewaddress(): 0.2,
        await n1.rpc.getnewaddress(): 0.3,
    }
    rawtx = await n0.rpc.createrawtransaction([], outputs)
    funded = await n0.rpc.fundrawtransaction(rawtx)
    txid = await n0.rpc.sendmany("", outputs)
    signed_fee = (await n0.rpc.getrawmempool(True))[txid]["fee"]
    fee_delta = funded["fee"] - signed_fee
    assert 0 <= fee_delta <= FEE_TOLERANCE

    # Fee parity: 2of2 multisig output.
    msig = await _multisig_address(n1, 2, 2)
    rawtx = await n0.rpc.createrawtransaction([], {msig: 1.1})
    funded = await n0.rpc.fundrawtransaction(rawtx)
    txid = await n0.rpc.sendtoaddress(msig, 1.1)
    signed_fee = (await n0.rpc.getrawmempool(True))[txid]["fee"]
    fee_delta = funded["fee"] - signed_fee
    assert 0 <= fee_delta <= FEE_TOLERANCE

    # Fee parity: 4of5 multisig output.
    msig = await _multisig_address(n1, 4, 5)
    rawtx = await n0.rpc.createrawtransaction([], {msig: 1.1})
    funded = await n0.rpc.fundrawtransaction(rawtx)
    txid = await n0.rpc.sendtoaddress(msig, 1.1)
    signed_fee = (await n0.rpc.getrawmempool(True))[txid]["fee"]
    fee_delta = funded["fee"] - signed_fee
    assert 0 <= fee_delta <= FEE_TOLERANCE

    # Spend a 2of2 multisig over fundraw; node1 receives 1.1.
    # Legacy asserted ``oldBalance + 11.1`` (a zcash 10-coin block reward + the 1.1
    # spend). The reward depends on coinbase maturation unrelated to fundraw, so we
    # assert the only behaviour fundraw owns -- that the 1.1 output was received.
    msig = await _multisig_address(n2, 2, 2)
    await n0.rpc.sendtoaddress(msig, 1.2)
    await n0.mine(1)
    await sync_blocks([n0, n1, n2])
    rawtx = await n2.rpc.createrawtransaction([], {await n1.rpc.getnewaddress(): 1.1})
    funded = await n2.rpc.fundrawtransaction(rawtx)
    signed = await n2.rpc.signrawtransaction(funded["hex"])
    txid = await n2.rpc.sendrawtransaction(signed["hex"])
    await n2.mine(1)
    await sync_blocks([n0, n1, n2])
    assert await _received(n1, txid) == Decimal("1.10000000")

    # Locked wallet: encrypt node1, restart, sending while locked fails, then unlock.
    # Legacy asserted ``oldBalance + 11.1`` on node0; we assert node0 received the
    # 1.1 spend directly rather than via a balance folding in a zcash subsidy.
    # Give node1 a confirmed, spendable balance to fund the post-unlock send.
    await n0.rpc.sendtoaddress(await n1.rpc.getnewaddress(), 10)
    await n0.mine(1)
    await sync_blocks([n0, n1, n2])
    assert await n1.rpc.getbalance() >= Decimal("1.1")

    await n1.rpc.encryptwallet("test")
    await n1.restart()
    await connect_nodes_bi(n0, n1)
    await connect_nodes_bi(n1, n2)
    await sync_blocks([n0, n1, n2])

    with pytest.raises(JSONRPCError):
        await n1.rpc.sendtoaddress(await n0.rpc.getnewaddress(), 1.2)

    rawtx = await n1.rpc.createrawtransaction([], {await n0.rpc.getnewaddress(): 1.1})
    funded = await n1.rpc.fundrawtransaction(rawtx)
    await n1.rpc.walletpassphrase("test", 100)
    signed = await n1.rpc.signrawtransaction(funded["hex"])
    txid = await n1.rpc.sendrawtransaction(signed["hex"])
    await n1.mine(1)
    await sync_blocks([n0, n1, n2])
    assert await _received(n0, txid) == Decimal("1.10000000")

    # ~19 small inputs: fundraw fee tracks sendmany within a wider tolerance.
    await _drain(n1, n0, [n0, n1, n2])
    for _ in range(20):
        await n0.rpc.sendtoaddress(await n1.rpc.getnewaddress(), 0.01)
    await n0.mine(1)
    await sync_blocks([n0, n1, n2])
    outputs = {await n0.rpc.getnewaddress(): 0.15, await n0.rpc.getnewaddress(): 0.04}
    rawtx = await n1.rpc.createrawtransaction([], outputs)
    funded = await n1.rpc.fundrawtransaction(rawtx)
    txid = await n1.rpc.sendmany("", outputs)
    signed_fee = (await n1.rpc.getrawmempool(True))[txid]["fee"]
    fee_delta = funded["fee"] - signed_fee
    assert 0 <= fee_delta <= FEE_TOLERANCE * 19

    # ~19 small inputs: fund -> sign -> send; node0 receives the 0.19 it sent.
    # Legacy asserted ``oldBalance + 10.19`` (zcash 10-coin reward + 0.19 spent
    # back); we assert the 0.19 receipt, which is what the funded+signed tx owns.
    await _drain(n1, n0, [n0, n1, n2])
    for _ in range(20):
        await n0.rpc.sendtoaddress(await n1.rpc.getnewaddress(), 0.01)
    await n0.mine(1)
    await sync_blocks([n0, n1, n2])
    outputs = {await n0.rpc.getnewaddress(): 0.15, await n0.rpc.getnewaddress(): 0.04}
    rawtx = await n1.rpc.createrawtransaction([], outputs)
    funded = await n1.rpc.fundrawtransaction(rawtx)
    signed = await n1.rpc.signrawtransaction(funded["hex"])
    txid = await n1.rpc.sendrawtransaction(signed["hex"])
    await n1.mine(1)
    await sync_blocks([n0, n1, n2])
    assert await _received(n0, txid) == Decimal("0.19000000")

    # OP_RETURN with no vin gets a funding vin and a change vout.
    rawtx = "0100000000010000000000000000066a047465737400000000"
    dec = await n2.rpc.decoderawtransaction(rawtx)
    assert len(dec["vin"]) == 0
    assert len(dec["vout"]) == 1
    funded = await n2.rpc.fundrawtransaction(rawtx)
    dec = await n2.rpc.decoderawtransaction(funded["hex"])
    assert len(dec["vin"]) > 0
    assert len(dec["vout"]) == 2


async def _drain(src: FluxNode, dst: FluxNode, group: list[FluxNode]) -> None:
    """Sweep src's whole spendable balance to dst (subtractfeefromamount) and mine."""
    src_balance = await src.rpc.getbalance()
    if src_balance > 0:
        await src.rpc.sendtoaddress(await dst.rpc.getnewaddress(), src_balance, "", "", True)
        await dst.mine(1)
        await sync_blocks(group)
