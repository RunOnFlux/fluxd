"""The unauthenticated REST HTTP interface served alongside JSON-RPC.

Exercises every REST endpoint and its content negotiation (``.json``/``.hex``/
``.bin``): transaction lookup, block and header retrieval (with the binary block
prefix matching the standalone header and the hex/json forms agreeing), chain
info, mempool info/contents, and the ``getutxos`` spentness query in its URI,
binary-POST, and JSON forms including its outpoint limit and malformed-request
errors.

REST is not JSON-RPC: requests are plain unauthenticated HTTP GETs/POSTs against
``/rest/...`` on the node's RPC port. Amounts and block fields are read off the
chain rather than assumed, so the assertions hold on Flux's PoW-mode coinbases
(one ~150 FLUX output to a fresh address per block) instead of fixed economics.
"""

import binascii
import json
import struct
from collections.abc import AsyncIterator
from decimal import Decimal
from typing import Any

import aiohttp
import pytest
from fluxtest.node import FluxNode

# A whole coinbase output is spent less a normal-sized fee, so the spend is never
# rejected by the absurd-fee check that a small hardcoded output would trip on
# Flux's ~150 FLUX coinbases.
FEE = Decimal("0.0001")

# fluxd's REST handler reports every malformed/oversized getutxos request as a
# generic internal server error rather than a 400.
HTTP_INTERNAL_SERVER_ERROR = 500
HTTP_OK = 200

# rest.cpp MAX_GETUTXOS_OUTPOINTS.
MAX_GETUTXOS_OUTPOINTS = 15


def _base(node: FluxNode) -> str:
    return f"http://127.0.0.1:{node.rpc_port}/rest"


async def _get(
    session: aiohttp.ClientSession, url: str
) -> tuple[int, bytes, aiohttp.ClientResponse]:
    async with session.get(url) as resp:
        body = await resp.read()
        return resp.status, body, resp


def _loads(text: str) -> Any:
    # Parse amounts as Decimal so coinbase values compare exactly.
    return json.loads(text, parse_float=Decimal)


async def _get_json(session: aiohttp.ClientSession, url: str) -> Any:
    async with session.get(url) as resp:
        assert resp.status == HTTP_OK, f"{url} -> {resp.status}"
        return _loads(await resp.text())


async def _post(session: aiohttp.ClientSession, url: str, data: bytes) -> tuple[int, bytes]:
    async with session.post(url, data=data) as resp:
        return resp.status, await resp.read()


async def _spendable_coinbases(
    node: FluxNode, count: int, mine_until: int = 0
) -> list[dict[str, Any]]:
    """Return ``count`` spendable utxos.

    listunspent also surfaces the unsignable P2SH fund outputs (spendable
    False); those are filtered out so a raw spend always signs to completion.

    Coinbases mature only after COINBASE_MATURITY confirmations, so a freshly
    funded node has just block 1's coinbase spendable; ``mine_until`` mines extra
    blocks until at least that many spendable utxos exist.
    """

    async def spendable() -> list[dict[str, Any]]:
        return [u for u in await node.rpc.listunspent(1) if u["spendable"]]

    utxos = await spendable()
    while len(utxos) < mine_until:
        await node.mine(1)
        utxos = await spendable()
    assert len(utxos) >= count, f"need {count} spendable utxos, have {len(utxos)}"
    return utxos[:count]


class Spend:
    """A broadcast spend of one whole coinbase output to a single address."""

    def __init__(
        self, txid: str, payment_vout: int, value: Decimal, source: dict[str, Any]
    ) -> None:
        self.txid = txid
        self.payment_vout = payment_vout
        self.value = value
        # The coinbase output consumed by this spend (now a spent outpoint).
        self.spent_txid = source["txid"]
        self.spent_vout = source["vout"]


async def _send_one_coinbase(node: FluxNode, to_address: str) -> Spend:
    """Spend one whole coinbase (less a fee) to ``to_address``.

    Everything (the payment vout, its value, the consumed outpoint) is read back
    from the node so nothing about Flux's coinbase layout is assumed.
    """
    coin = (await _spendable_coinbases(node, 1))[0]
    value = coin["amount"] - FEE
    rawtx = await node.rpc.createrawtransaction(
        [{"txid": coin["txid"], "vout": coin["vout"]}], {to_address: value}
    )
    signed = await node.rpc.signrawtransaction(rawtx)
    assert signed["complete"] is True
    txid = await node.rpc.sendrawtransaction(signed["hex"])
    # Locate the payment output by the address it pays, not by a fixed index.
    decoded = await node.rpc.decoderawtransaction(signed["hex"])
    payment_vout = next(
        vout["n"]
        for vout in decoded["vout"]
        if to_address in vout["scriptPubKey"].get("addresses", [])
    )
    return Spend(txid, payment_vout, value, coin)


@pytest.fixture
async def session() -> AsyncIterator[aiohttp.ClientSession]:
    # REST is unauthenticated: no Authorization header, unlike the JSON-RPC port.
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as s:
        yield s


async def test_tx_endpoint(funded_node: FluxNode, session: aiohttp.ClientSession) -> None:
    """/rest/tx/<txid>.(json|hex) returns the transaction in each form."""
    node = funded_node
    address = await node.rpc.getnewaddress()
    spend = await _send_one_coinbase(node, address)
    await node.mine(1)

    json_obj = await _get_json(session, f"{_base(node)}/tx/{spend.txid}.json")
    assert json_obj["txid"] == spend.txid
    assert isinstance(json_obj["vin"], list) and len(json_obj["vin"]) == 1
    assert isinstance(json_obj["vout"], list)

    status, body, _ = await _get(session, f"{_base(node)}/tx/{spend.txid}.hex")
    assert status == HTTP_OK
    # The hex body decodes back to the same transaction the node holds.
    rawhex = body.decode().strip()
    assert (await node.rpc.decoderawtransaction(rawhex))["txid"] == spend.txid


async def test_tx_unknown_hash(funded_node: FluxNode, session: aiohttp.ClientSession) -> None:
    """A malformed hash is a 400, a well-formed but unknown one is a 404."""
    node = funded_node
    status, _, _ = await _get(session, f"{_base(node)}/tx/zzzz.json")
    assert status == 400
    status, _, _ = await _get(session, f"{_base(node)}/tx/{'0' * 64}.json")
    assert status == 404


async def test_getutxos_unspent_and_spent(
    funded_node: FluxNode, session: aiohttp.ClientSession
) -> None:
    """getutxos reports an unspent outpoint as a hit and a spent one as a miss."""
    node = funded_node
    address = await node.rpc.getnewaddress()
    spend = await _send_one_coinbase(node, address)
    await node.mine(1)
    bb_hash = await node.rpc.getbestblockhash()

    unspent = f"{spend.txid}-{spend.payment_vout}"
    spent = f"{spend.spent_txid}-{spend.spent_vout}"

    # Unspent: the just-created payment output.
    obj = await _get_json(session, f"{_base(node)}/getutxos/checkmempool/{unspent}.json")
    assert obj["chaintipHash"] == bb_hash
    assert len(obj["utxos"]) == 1
    assert obj["utxos"][0]["value"] == spend.value
    assert obj["bitmap"] == "1"

    # Spent: the coinbase output that funded the spend is now consumed.
    obj = await _get_json(session, f"{_base(node)}/getutxos/checkmempool/{spent}.json")
    assert obj["chaintipHash"] == bb_hash
    assert len(obj["utxos"]) == 0
    assert obj["bitmap"] == "0"

    # Both in one request: one hit (the unspent payment) then one miss.
    obj = await _get_json(session, f"{_base(node)}/getutxos/checkmempool/{unspent}/{spent}.json")
    assert len(obj["utxos"]) == 1
    assert obj["bitmap"] == "10"


async def test_getutxos_binary(funded_node: FluxNode, session: aiohttp.ClientSession) -> None:
    """The binary getutxos response carries the current chain height and tip hash."""
    node = funded_node
    address = await node.rpc.getnewaddress()
    spend = await _send_one_coinbase(node, address)
    await node.mine(1)
    bb_hash = await node.rpc.getbestblockhash()
    height = await node.rpc.getblockcount()

    # bin request: [bool fCheckMemPool][vector<COutPoint>] per BIP64; the vector
    # is a CompactSize count followed by 32-byte txid + 4-byte (LE) index each.
    body = b"\x01"  # checkmempool = true
    body += b"\x02"  # two outpoints
    body += binascii.unhexlify(spend.txid)[::-1] + struct.pack("<i", spend.payment_vout)
    body += binascii.unhexlify(spend.spent_txid)[::-1] + struct.pack("<i", spend.spent_vout)

    status, response = await _post(session, f"{_base(node)}/getutxos.bin", body)
    assert status == HTTP_OK
    # Response prefix: int32 chainHeight (LE) then the 32-byte tip hash.
    chain_height = struct.unpack("<i", response[:4])[0]
    tip_hash = response[4:36][::-1].hex()
    assert chain_height == height
    assert tip_hash == bb_hash


async def test_getutxos_mempool(funded_node: FluxNode, session: aiohttp.ClientSession) -> None:
    """checkmempool surfaces an unconfirmed output that the chain-only view misses."""
    node = funded_node
    address = await node.rpc.getnewaddress()
    spend = await _send_one_coinbase(node, address)
    # Deliberately not mined: the output lives only in the mempool.
    outpoint = f"{spend.txid}-{spend.payment_vout}"

    obj = await _get_json(session, f"{_base(node)}/getutxos/{outpoint}.json")
    assert len(obj["utxos"]) == 0

    obj = await _get_json(session, f"{_base(node)}/getutxos/checkmempool/{outpoint}.json")
    assert len(obj["utxos"]) == 1


async def test_getutxos_invalid_requests(
    funded_node: FluxNode, session: aiohttp.ClientSession
) -> None:
    """Malformed getutxos POST bodies are rejected with a 500."""
    node = funded_node
    status, _ = await _post(session, f"{_base(node)}/getutxos.json", b'{"checkmempool')
    assert status == HTTP_INTERNAL_SERVER_ERROR
    status, _ = await _post(session, f"{_base(node)}/getutxos.bin", b'{"checkmempool')
    assert status == HTTP_INTERNAL_SERVER_ERROR
    # Empty body with only the checkmempool flag and no outpoints.
    status, _ = await _post(session, f"{_base(node)}/getutxos/checkmempool.bin", b"")
    assert status == HTTP_INTERNAL_SERVER_ERROR


async def test_getutxos_outpoint_limit(
    funded_node: FluxNode, session: aiohttp.ClientSession
) -> None:
    """At most 15 outpoints may be queried in one getutxos request."""
    node = funded_node
    address = await node.rpc.getnewaddress()
    spend = await _send_one_coinbase(node, address)
    await node.mine(1)
    outpoint = f"{spend.txid}-{spend.payment_vout}"

    over = "/".join([outpoint] * (MAX_GETUTXOS_OUTPOINTS + 5))
    status, _, _ = await _get(session, f"{_base(node)}/getutxos/checkmempool/{over}.json")
    assert status == HTTP_INTERNAL_SERVER_ERROR

    at_limit = "/".join([outpoint] * MAX_GETUTXOS_OUTPOINTS)
    status, _, _ = await _get(session, f"{_base(node)}/getutxos/checkmempool/{at_limit}.json")
    assert status == HTTP_OK


async def test_block_formats_and_header(
    funded_node: FluxNode, session: aiohttp.ClientSession
) -> None:
    """block bin/hex/json agree, and the block's binary prefix is its header."""
    node = funded_node
    bb_hash = await node.rpc.getbestblockhash()

    status, block_bin, resp = await _get(session, f"{_base(node)}/block/{bb_hash}.bin")
    assert status == HTTP_OK
    assert resp.headers["Content-Type"] == "application/octet-stream"

    # The standalone single-header response is exactly the block's leading bytes.
    status, header_bin, hresp = await _get(session, f"{_base(node)}/headers/1/{bb_hash}.bin")
    assert status == HTTP_OK
    header_len = int(hresp.headers["Content-Length"])
    assert header_len == len(header_bin)
    assert block_bin[:header_len] == header_bin

    # hex form is the hex encoding of the binary form.
    _, block_hex, _ = await _get(session, f"{_base(node)}/block/{bb_hash}.hex")
    assert block_hex.decode().strip() == block_bin.hex()
    _, header_hex, _ = await _get(session, f"{_base(node)}/headers/1/{bb_hash}.hex")
    assert header_hex.decode().strip() == header_bin.hex()
    assert block_hex.decode().strip().startswith(header_hex.decode().strip())

    # json block reports the requested hash.
    block_json = await _get_json(session, f"{_base(node)}/block/{bb_hash}.json")
    assert block_json["hash"] == bb_hash


async def test_headers_json_matches_rpc(
    funded_node: FluxNode, session: aiohttp.ClientSession
) -> None:
    """The single-header JSON response matches getblock's header fields."""
    node = funded_node
    bb_hash = await node.rpc.getbestblockhash()

    headers = await _get_json(session, f"{_base(node)}/headers/1/{bb_hash}.json")
    assert len(headers) == 1
    header = headers[0]
    assert header["hash"] == bb_hash

    rpc_block = await node.rpc.getblock(bb_hash)
    for field in (
        "hash",
        "confirmations",
        "height",
        "version",
        "merkleroot",
        "time",
        "nonce",
        "bits",
        "difficulty",
        "chainwork",
        "previousblockhash",
    ):
        assert header[field] == rpc_block[field], field


async def test_headers_multiple(funded_node: FluxNode, session: aiohttp.ClientSession) -> None:
    """Requesting N headers from a hash returns N forward-walked headers."""
    node = funded_node
    start_hash = await node.rpc.getbestblockhash()
    await node.mine(5)

    headers = await _get_json(session, f"{_base(node)}/headers/5/{start_hash}.json")
    assert len(headers) == 5
    assert headers[0]["hash"] == start_hash
    # The walk follows the active chain forward from the start hash.
    for prev, nxt in zip(headers[:-1], headers[1:], strict=True):
        assert nxt["previousblockhash"] == prev["hash"]


async def test_headers_bad_count(funded_node: FluxNode, session: aiohttp.ClientSession) -> None:
    """A header count outside [1, 2000] is a 400."""
    node = funded_node
    bb_hash = await node.rpc.getbestblockhash()
    status, _, _ = await _get(session, f"{_base(node)}/headers/0/{bb_hash}.json")
    assert status == 400
    status, _, _ = await _get(session, f"{_base(node)}/headers/2001/{bb_hash}.json")
    assert status == 400


async def test_block_tx_details(funded_node: FluxNode, session: aiohttp.ClientSession) -> None:
    """A mined block lists its non-coinbase txids, in full and id-only forms."""
    node = funded_node
    # funded_node has matured only block 1's coinbase; mine until at least three
    # coinbases are mature so three distinct, non-conflicting spends are possible.
    coins = await _spendable_coinbases(node, 3, mine_until=3)
    sent = []
    for coin in coins:
        addr = await node.rpc.getnewaddress()
        rawtx = await node.rpc.createrawtransaction(
            [{"txid": coin["txid"], "vout": coin["vout"]}], {addr: coin["amount"] - FEE}
        )
        signed = await node.rpc.signrawtransaction(rawtx)
        assert signed["complete"] is True
        sent.append(await node.rpc.sendrawtransaction(signed["hex"]))

    info = await _get_json(session, f"{_base(node)}/mempool/info.json")
    assert info["size"] == 3
    # Three single-input transactions are well over 3x ~100 bytes.
    assert info["bytes"] > 300

    contents = await _get_json(session, f"{_base(node)}/mempool/contents.json")
    for txid in sent:
        assert txid in contents

    newblockhash = (await node.mine(1))[0]

    # With tx details: each non-coinbase entry carries the expected txid.
    block_json = await _get_json(session, f"{_base(node)}/block/{newblockhash}.json")
    block_txids = {tx["txid"] for tx in block_json["tx"] if "coinbase" not in tx["vin"][0]}
    assert set(sent) <= block_txids

    # Without tx details: the tx list is bare txid strings.
    notx = await _get_json(session, f"{_base(node)}/block/notxdetails/{newblockhash}.json")
    for txid in sent:
        assert txid in notx["tx"]


async def test_chaininfo(funded_node: FluxNode, session: aiohttp.ClientSession) -> None:
    """/rest/chaininfo.json reports the current best block hash."""
    node = funded_node
    bb_hash = await node.rpc.getbestblockhash()
    obj = await _get_json(session, f"{_base(node)}/chaininfo.json")
    assert obj["bestblockhash"] == bb_hash


async def test_unauthenticated(funded_node: FluxNode) -> None:
    """REST GETs need no credentials even though JSON-RPC rejects them."""
    node = funded_node
    bb_hash = await node.rpc.getbestblockhash()
    async with aiohttp.ClientSession() as anon:
        async with anon.get(f"{_base(node)}/chaininfo.json") as resp:
            assert resp.status == HTTP_OK
        # The same node's JSON-RPC port refuses an unauthenticated request.
        rpc_body = '{"method":"getblockcount","params":[],"id":1}'
        async with anon.post(f"http://127.0.0.1:{node.rpc_port}", data=rpc_body) as resp:
            assert resp.status == 401
    # The node still serves authenticated RPC afterwards.
    assert await node.rpc.getbestblockhash() == bb_hash


# A REST-only failure mode that has no JSON-RPC analogue: the bin format with a
# combination of URI inputs and a raw POST body is rejected.
async def test_getutxos_uri_and_body_conflict(
    funded_node: FluxNode, session: aiohttp.ClientSession
) -> None:
    node = funded_node
    address = await node.rpc.getnewaddress()
    spend = await _send_one_coinbase(node, address)
    await node.mine(1)
    outpoint = f"{spend.txid}-{spend.payment_vout}"
    body = (
        b"\x01\x01" + binascii.unhexlify(spend.txid)[::-1] + struct.pack("<i", spend.payment_vout)
    )
    status, _ = await _post(session, f"{_base(node)}/getutxos/checkmempool/{outpoint}.bin", body)
    assert status == HTTP_INTERNAL_SERVER_ERROR
