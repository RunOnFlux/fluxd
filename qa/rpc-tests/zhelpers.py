"""Shared helpers for the shielded (z_*) RPC integration tests.

Shielded sends run as background wallet operations: z_sendmany / z_shieldcoinbase
/ z_mergetoaddress return an operation id immediately and the transaction is
built and broadcast asynchronously. Tests must poll z_getoperationresult to
completion before asserting on the resulting balances or mempool.

Sapling (and Overwintered transparent transactions) are gated on the ACADIA
network upgrade in Flux; regtest leaves it at NO_ACTIVATION_HEIGHT by default,
so shielded tests pass -acadiaactivation=<low height> to switch it on. PON is
kept off (-ponactivation far in the future) so mined coinbase funds the wallet.
"""

import asyncio
from decimal import Decimal
from typing import Any

from conftest import POW_ARGS
from fluxtest.node import FluxNode


def shielded_args(acadia_height: int = 1, extra: list[str] | None = None) -> list[str]:
    """Daemon args for a shielded regtest node: ACADIA on, PON off (PoW funding).

    ACADIA at ``acadia_height`` activates Sapling and Overwintered transactions;
    keeping PON off lets mined coinbase fund the wallet so there are transparent
    coins to shield.
    """
    return [f"-acadiaactivation={acadia_height}", *POW_ARGS, *(extra or [])]


async def wait_and_assert_operationid_status_result(
    node: FluxNode,
    opid: str,
    in_status: str = "success",
    in_errormsg: str | None = None,
    timeout: float = 300,
) -> dict[str, Any]:
    """Poll a wallet async operation to completion and assert its final status.

    Returns the full operation result dict. On an expected failure, also asserts
    the error message matches ``in_errormsg`` (when given).
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    result: dict[str, Any] | None = None
    while True:
        results = await node.rpc.z_getoperationresult([opid])
        if results:
            result = results[0]
            break
        if loop.time() > deadline:
            raise AssertionError(f"timed out waiting for async operation {opid}")
        await asyncio.sleep(0.5)

    status = result["status"]
    if status == "failed" and in_errormsg is not None:
        assert result["error"]["message"] == in_errormsg, (
            f"operation {opid} error {result['error']['message']!r} != {in_errormsg!r}"
        )
    assert status == in_status, (
        f"operation {opid} status {status!r} != {in_status!r}: {result.get('error')}"
    )
    return result


async def wait_and_assert_operationid_status(
    node: FluxNode,
    opid: str,
    in_status: str = "success",
    in_errormsg: str | None = None,
    timeout: float = 300,
) -> str | None:
    """Wait for an async operation and return its txid (None unless succeeded)."""
    result = await wait_and_assert_operationid_status_result(
        node, opid, in_status, in_errormsg, timeout
    )
    if result["status"] == "success":
        return result["result"]["txid"]
    return None


async def get_coinbase_address(node: FluxNode, expected_utxos: int | None = None) -> str:
    """Return a coinbase address on ``node``, optionally one holding exactly
    ``expected_utxos`` spendable coinbase outputs.

    With no filter, returns the coinbase address holding the most spendable
    UTXOs. Each PoW-mode coinbase pays a fresh wallet address, so callers that
    need a known UTXO count must mine that many blocks first.
    """
    addrs = [u["address"] for u in await node.rpc.listunspent() if u["generated"]]
    assert addrs, "node has no spendable coinbase outputs"
    if expected_utxos is None:
        return max(set(addrs), key=addrs.count)
    matching = [a for a in set(addrs) if addrs.count(a) == expected_utxos]
    assert matching, f"no coinbase address with exactly {expected_utxos} utxos"
    return matching[0]


async def wait_for_received_notes(
    node: FluxNode, zaddr: str, count: int, minconf: int = 0, timeout: float = 30
) -> list[dict[str, Any]]:
    """Poll z_listreceivedbyaddress until ``zaddr`` shows at least ``count`` notes.

    A z_sendmany / z_shieldcoinbase operation reports success once its transaction
    is built and broadcast, but the sending wallet takes a moment longer to
    register the output note in its received-note view, so an immediate
    z_listreceivedbyaddress can still be empty. This waits for that to settle.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        received = await node.rpc.z_listreceivedbyaddress(zaddr, minconf)
        if len(received) >= count:
            return received
        if loop.time() > deadline:
            raise AssertionError(
                f"{zaddr} did not receive {count} note(s) within {timeout}s (got {len(received)})"
            )
        await asyncio.sleep(0.25)


async def z_total(node: FluxNode) -> dict[str, Decimal]:
    """Return z_gettotalbalance as {transparent, private, total} Decimals."""
    bal = await node.rpc.z_gettotalbalance()
    return {k: Decimal(v) for k, v in bal.items()}
