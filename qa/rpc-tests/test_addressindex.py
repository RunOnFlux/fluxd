"""The insightexplorer addressindex RPCs over a Flux regtest chain.

Exercises getaddresstxids / getaddressbalance / getaddressdeltas /
getaddressutxos / getaddressmempool plus the insight fields getrawtransaction
adds when ``-insightexplorer`` is enabled (a spending input's prior value and
address). ``-insightexplorer`` turns on the address index; it requires
``-txindex`` and the experimental-features gate.

Flux's PoW-mode coinbase differs from upstream Zcash: a regular block has a
single output paying the miner (no per-block founders' reward), and ``generate``
pays a fresh wallet address each block. The funding chain therefore spreads its
coinbases across many addresses; each coinbase is verified to be indexed under
the one address it pays, with balances read off the chain rather than assumed
from fixed block economics. A fixed address accruing many entries is exercised
through repeated wallet sends instead.
"""

import asyncio
from decimal import Decimal
from typing import Any

from addressindex_dup_output_tx import (
    p2pkh_script,
    splice_outputs,
    unrecognized_script,
)
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes, sync_blocks
from fluxtest.node import FluxNode

COIN = 100_000_000

# -insightexplorer enables the address/spent/timestamp indices; it requires
# -txindex and the experimental-features gate. PoW mode pays coinbases to the
# wallet so an address can accrue spendable balance.
INSIGHT_ARGS = ["-experimentalfeatures", "-insightexplorer", "-txindex", *POW_ARGS]

# A whole coinbase output is spent less a normal-sized fee, dodging the
# absurd-fee guard that a tiny hardcoded output would trip on ~150 FLUX coinbases.
FEE = Decimal("0.0001")

# Coinbases paid to the fixed miner address over the funding phase. Enough that
# many mature (COINBASE_MATURITY) for spending while a known count remains.
FUNDING_BLOCKS = COINBASE_MATURITY + 10


def _sat(amount: Decimal) -> int:
    return int((amount * COIN).to_integral_value())


async def _coinbase_value_sat(node: FluxNode, blockhash: str, address: str) -> int:
    """Satoshis the coinbase of ``blockhash`` pays to ``address``.

    Read from the chain so no assumption is made about Flux's coinbase layout
    (a regular block pays only the miner; the periodic fund blocks carry extra
    outputs to other addresses that this address-scoped sum excludes).
    """
    block = await node.rpc.getblock(blockhash, 2)
    coinbase = block["tx"][0]
    total = 0
    for vout in coinbase["vout"]:
        if address in vout["scriptPubKey"].get("addresses", []):
            total += _sat(vout["value"])
    return total


async def _balance(node: FluxNode, address: str | list[str]) -> dict[str, int]:
    if isinstance(address, list):
        return await node.rpc.getaddressbalance({"addresses": address})
    return await node.rpc.getaddressbalance(address)


async def _assert_balance(
    node: FluxNode,
    address: str | list[str],
    expected_balance: int,
    expected_received: int | None = None,
) -> None:
    bal = await _balance(node, address)
    assert bal["balance"] == expected_balance
    assert bal["received"] == (expected_balance if expected_received is None else expected_received)


async def _txids(node: FluxNode, addresses: list[str], start: int, end: int) -> list[str]:
    return await node.rpc.getaddresstxids({"addresses": addresses, "start": start, "end": end})


async def _deltas(
    node: FluxNode,
    addresses: list[str],
    start: int | None = None,
    end: int | None = None,
    chain_info: bool | None = None,
) -> Any:
    params: dict[str, Any] = {"addresses": addresses}
    if start is not None:
        params["start"] = start
    if end is not None:
        params["end"] = end
    if chain_info is not None:
        params["chainInfo"] = chain_info
    return await node.rpc.getaddressdeltas(params)


async def _wait_in_all_mempools(nodes: list[FluxNode], txid: str, timeout: float = 60) -> None:
    """Wait until the unconfirmed ``txid`` has propagated to every node's mempool."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        # Materialize the awaits first: an await inside a generator expression
        # makes it an async generator, which all() cannot consume.
        pools = [await node.rpc.getrawmempool() for node in nodes]
        if all(txid in pool for pool in pools):
            return
        if loop.time() > deadline:
            raise AssertionError(f"{txid} did not reach every mempool")
        await asyncio.sleep(0.25)


async def test_addressindex(node_factory: NodeFactory) -> None:
    miner = await node_factory(0, extra_args=INSIGHT_ARGS)
    reader = await node_factory(1, extra_args=INSIGHT_ARGS)
    recipient = await node_factory(2, extra_args=INSIGHT_ARGS)
    await connect_nodes(miner, reader)
    await connect_nodes(miner, recipient)
    await connect_nodes(reader, miner)
    await connect_nodes(recipient, miner)
    nodes = [miner, reader, recipient]

    # Fund by mining. Flux pays each PoW coinbase to a fresh wallet address (there
    # is no -mineraddress override on this build: the wallet's mining-script hook
    # bails out when -mineraddress is set and nothing else fills the script, so
    # generate cannot pin coinbases to one address). The address index therefore
    # holds one coinbase per distinct address rather than N to a single address.
    funding_hashes = await miner.mine(FUNDING_BLOCKS)
    await sync_blocks(nodes)
    assert await reader.rpc.getblockcount() == FUNDING_BLOCKS

    # Each coinbase is indexed by the single fresh address it pays: that address
    # has exactly that one coinbase txid and a balance equal to its (chain-read)
    # coinbase value. Block 1 (the premine) is skipped as its value dwarfs the
    # rest and would mask a regression in the ordinary per-block coinbase. The
    # first such address is retained for the multi-address sum below.
    coinbase_addr = ""
    for blockhash in funding_hashes[1:6]:
        block = await miner.rpc.getblock(blockhash, 2)
        coinbase = block["tx"][0]
        addr = coinbase["vout"][0]["scriptPubKey"]["addresses"][0]
        value_sat = await _coinbase_value_sat(miner, blockhash, addr)
        assert await reader.rpc.getaddresstxids(addr) == [coinbase["txid"]]
        await _assert_balance(reader, addr, value_sat)
        if not coinbase_addr:
            coinbase_addr = addr

    # Five transfers of increasing value to one address, one per block. The
    # output value to addr1 is exactly the requested amount, so each delta is
    # chain-exact without reading it back.
    addr1 = await reader.rpc.getnewaddress()
    txids_a1: list[str] = []
    expected_deltas: list[dict[str, Any]] = []
    expected_balance = 0
    base_height = await miner.rpc.getblockcount()
    for i in range(5):
        amount = Decimal(i + 1)
        txid = await miner.rpc.sendtoaddress(addr1, amount)
        txids_a1.append(txid)
        await miner.mine(1)
        await sync_blocks(nodes)
        expected_balance += _sat(amount)
        expected_deltas.append(
            {"height": base_height + 1 + i, "satoshis": _sat(amount), "txid": txid}
        )

    await _assert_balance(reader, addr1, expected_balance)
    assert sorted(await miner.rpc.getaddresstxids(addr1)) == sorted(txids_a1)
    assert sorted(await reader.rpc.getaddresstxids(addr1)) == sorted(txids_a1)

    # Restart every node so the indices are reloaded from disk, then re-query.
    for node in nodes:
        await node.restart(extra_args=INSIGHT_ARGS)
    await connect_nodes(miner, reader)
    await connect_nodes(miner, recipient)
    await connect_nodes(reader, miner)
    await connect_nodes(recipient, miner)

    await _assert_balance(reader, addr1, expected_balance)
    assert sorted(await miner.rpc.getaddresstxids(addr1)) == sorted(txids_a1)
    assert sorted(await reader.rpc.getaddresstxids(addr1)) == sorted(txids_a1)

    # Spend from addr1 to a fresh address on the recipient node. Coin selection
    # consumes one of addr1's UTXOs; which value it picks is read from the tx
    # rather than assumed, so the insight-field and mempool-delta checks stay
    # exact regardless of selection.
    addr2 = await recipient.rpc.getnewaddress()
    send_txid = await reader.rpc.sendtoaddress(addr2, Decimal(3))
    await _wait_in_all_mempools(nodes, send_txid)

    spend_tx = await miner.rpc.getrawtransaction(send_txid, 1)
    spent_input = spend_tx["vin"][0]
    assert spent_input["address"] == addr1
    spent_value = spent_input["value"]
    spent_value_sat = _sat(spent_value)
    assert spent_input["valueSat"] == spent_value_sat

    # The mempool delta references both addresses; duplicate address args are
    # surfaced once per occurrence (here addr2 appears twice).
    mempool = await miner.rpc.getaddressmempool({"addresses": [addr2, addr1, addr2]})
    assert len(mempool) == 3
    assert mempool[0]["address"] == addr2
    assert mempool[0]["satoshis"] == 3 * COIN
    assert mempool[0]["txid"] == send_txid
    assert mempool[1]["address"] == addr1
    assert mempool[1]["satoshis"] == -spent_value_sat
    assert mempool[1]["txid"] == send_txid
    assert mempool[2]["address"] == addr2
    assert mempool[2]["satoshis"] == 3 * COIN
    assert mempool[2]["txid"] == send_txid

    # A single address may be given as a bare string rather than an object.
    assert await miner.rpc.getaddressmempool(addr1) == [mempool[1]]

    txids_a1.append(send_txid)
    expected_deltas.append(
        {"height": base_height + 6, "satoshis": -spent_value_sat, "txid": send_txid}
    )

    await miner.mine(1)
    await sync_blocks(nodes)
    # The send is mined, so it is no longer a mempool delta.
    assert len(await miner.rpc.getaddressmempool({"addresses": [addr2, addr1]})) == 0

    spent_block_height = base_height + 6
    assert await miner.rpc.getblockcount() == spent_block_height

    # invalidateblock rolls the spend out: addr1 regains the spent UTXO and the
    # send re-enters the mempool; remined, the balances settle back.
    tip_hash = await reader.rpc.getbestblockhash()
    for node in nodes:
        await _assert_balance(node, addr1, expected_balance - spent_value_sat, expected_balance)
        await _assert_balance(node, addr2, 3 * COIN)
        assert await node.rpc.getblockcount() == spent_block_height

        await node.rpc.invalidateblock(tip_hash)
        assert await node.rpc.getblockcount() == spent_block_height - 1

        assert len(await node.rpc.getaddressmempool({"addresses": [addr2, addr1]})) == 2
        await _assert_balance(node, addr1, expected_balance)
        await _assert_balance(node, addr2, 0)

    # Re-mine the rolled-back send.
    await miner.mine(1)
    await sync_blocks(nodes)
    for node in nodes:
        assert await node.rpc.getblockcount() == spent_block_height
    assert len(await miner.rpc.getaddressmempool({"addresses": [addr2, addr1]})) == 0
    await _assert_balance(recipient, addr1, expected_balance - spent_value_sat, expected_balance)

    # The change output of the spend pays a fresh address; it carries the spent
    # value less the payment and a small fee, and the index lists just that send.
    spend_tx = await miner.rpc.getrawtransaction(send_txid, 1)
    change_vouts = [v for v in spend_tx["vout"] if _sat(v["value"]) != 3 * COIN]
    assert len(change_vouts) == 1
    change_addr = change_vouts[0]["scriptPubKey"]["addresses"][0]
    change_bal = await _balance(recipient, change_addr)
    assert change_bal["received"] > 0
    assert change_bal["received"] < (spent_value_sat - 3 * COIN)
    assert change_bal["received"] == change_bal["balance"]
    assert await recipient.rpc.getaddresstxids(change_addr) == [send_txid]

    # Height-range filtering over the five addr1 receipts (heights base+1..base+5).
    for i in range(5):
        sliced = await _txids(reader, [addr1], base_height + 1, base_height + 1 + i)
        assert sliced == txids_a1[: i + 1]
    # A range ending before the fourth receipt yields the first three.
    assert await _txids(reader, [addr1], 1, base_height + 3) == txids_a1[:3]

    # A multi-address query sums and dedupes across addresses (a coinbase
    # address and the busy addr1), read live so spends of the coinbase are
    # accounted for consistently on both sides.
    txids_all = set(txids_a1) | set(await reader.rpc.getaddresstxids(coinbase_addr))
    multi = await reader.rpc.getaddresstxids({"addresses": [addr1, coinbase_addr]})
    assert len(multi) == len(set(multi))  # the result itself carries no dups
    assert set(multi) == txids_all

    # getaddressdeltas: full list matches the recorded deltas in order.
    deltas = await _deltas(reader, [addr1])
    assert len(deltas) == len(expected_deltas)
    for got, want in zip(deltas, expected_deltas, strict=True):
        assert got["address"] == addr1
        assert got["height"] == want["height"]
        assert got["satoshis"] == want["satoshis"]
        assert got["txid"] == want["txid"]

    # Limited ranges slice the same delta list.
    low = base_height + 1
    high = base_height + 6
    assert await _deltas(reader, [addr1], low, high) == deltas
    assert await _deltas(reader, [addr1], low + 1, high) == deltas[1:]
    assert await _deltas(reader, [addr1], low + 3, low + 3) == deltas[3:4]

    # chainInfo wraps the deltas with the start/end block identities.
    info = await _deltas(reader, [addr1], low, high, chain_info=True)
    assert info["deltas"] == deltas
    assert info["start"]["height"] == low
    assert info["start"]["hash"] == await reader.rpc.getblockhash(low)
    assert info["end"]["height"] == high
    assert info["end"]["hash"] == await reader.rpc.getblockhash(high)

    # getaddressutxos lines up with the deltas once the spent value (and its
    # negative spend delta) are removed: those are no longer unspent.
    utxos = await reader.rpc.getaddressutxos(addr1)
    remaining = [d for d in deltas if abs(d["satoshis"]) != spent_value_sat]
    assert len(utxos) == len(remaining)
    for utxo, delta in zip(utxos, remaining, strict=True):
        assert utxo["address"] == addr1
        assert utxo["height"] == delta["height"]
        assert utxo["satoshis"] == delta["satoshis"]
        assert utxo["txid"] == delta["txid"]

    # Two outputs to the same address (plus an address-less output) in one tx
    # must collapse to a single txid in the index. createrawtransaction would
    # merge the duplicate-address outputs, so the output vector is spliced by
    # hand onto a node-built transaction.
    dup_addr = await recipient.rpc.getnewaddress()
    # The P2PKH scriptPubKey is OP_DUP OP_HASH160 <20-byte push> OP_EQUALVERIFY
    # OP_CHECKSIG; bytes 3..23 are the 20-byte address hash.
    dup_hash = bytes.fromhex((await recipient.rpc.validateaddress(dup_addr))["scriptPubKey"])[3:23]
    funding = next(u for u in await miner.rpc.listunspent(1) if u["spendable"] and u["amount"] >= 4)
    # The output vector is replaced wholesale below, so this placeholder output
    # address only has to be valid; a fresh miner address serves.
    placeholder = await miner.rpc.getnewaddress()
    base_raw = await miner.rpc.createrawtransaction(
        [{"txid": funding["txid"], "vout": funding["vout"]}],
        {placeholder: funding["amount"] - FEE},
    )
    remainder_sat = _sat(funding["amount"] - FEE) - 3 * COIN
    spliced = splice_outputs(
        base_raw,
        [
            (1 * COIN, p2pkh_script(dup_hash)),
            (2 * COIN, p2pkh_script(dup_hash)),
            (remainder_sat, unrecognized_script(dup_hash)),
        ],
    )
    signed = await miner.rpc.signrawtransaction(spliced)
    assert signed["complete"] is True
    dup_txid = await miner.rpc.sendrawtransaction(signed["hex"])
    await miner.mine(1)
    await sync_blocks(nodes)

    assert await reader.rpc.getaddresstxids(dup_addr) == [dup_txid]
    await _assert_balance(recipient, dup_addr, 3 * COIN)
