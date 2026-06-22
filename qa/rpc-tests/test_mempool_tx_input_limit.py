"""Exercise the per-transaction transparent-input cap set by -mempooltxinputlimit.

A node started with -mempooltxinputlimit=N rejects any transaction the mempool
would otherwise accept that spends more than N transparent inputs, and accepts
one spending exactly N. The cap is enforced in AcceptToMemoryPool, so it is
exercised here by building raw transactions that spend a controlled number of
matured coinbase outputs and submitting them with sendrawtransaction.

The cap is also tied to the consensus epoch: AcceptToMemoryPool forces the limit
to zero once the ACADIA upgrade activates, so an over-limit transaction that is
dropped beforehand is accepted afterwards.
"""

from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError


def _limit_args(limit: int) -> list[str]:
    return [*POW_ARGS, "-checkmempool", "-debug=mempool", f"-mempooltxinputlimit={limit}"]


async def _spendable_coinbases(node: FluxNode, count: int) -> list[dict[str, object]]:
    """Return ``count`` matured, spendable coinbase utxos owned by ``node``.

    Coinbase outputs of the early miner-reward blocks are large (~150 FLUX) and
    signable by the mining node; the unsignable P2SH fund outputs that appear on
    a few coinbases are filtered out via the spendable flag.
    """
    utxos = [u for u in await node.rpc.listunspent(1) if u["spendable"]]
    assert len(utxos) >= count, f"need {count} spendable utxos, have {len(utxos)}"
    return utxos[:count]


async def _raw_spend(node: FluxNode, utxos: list[dict[str, object]]) -> str:
    """Build and sign a raw tx spending every utxo in ``utxos`` to one address.

    The whole input value (minus a single normal fee) is forwarded so the tx is
    rejected only on the input-count cap, not the absurd-fee check that a tiny
    hardcoded output would trip on Flux's large coinbases.
    """
    inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos]
    total = sum((Decimal(str(u["amount"])) for u in utxos), Decimal(0))
    outputs = {await node.rpc.getnewaddress(): total - Decimal("0.0001")}
    rawtx = await node.rpc.createrawtransaction(inputs, outputs)
    signed = await node.rpc.signrawtransaction(rawtx)
    assert signed["complete"] is True
    return signed["hex"]


async def test_at_limit_accepted_over_limit_rejected(node_factory: NodeFactory) -> None:
    """Exactly ``limit`` inputs is accepted; ``limit + 1`` inputs is rejected."""
    limit = 2
    node = await node_factory(0, extra_args=_limit_args(limit))
    # Mature enough coinbases to assemble both an at-limit and an over-limit tx.
    await node.mine(COINBASE_MATURITY + limit + 2)

    over = await _spendable_coinbases(node, limit + 1)
    over_tx = await _raw_spend(node, over)
    # The over-limit drop carries no reject reason, so the error shape alone does
    # not prove the cap is the cause; test_rejection_is_caused_by_the_cap isolates
    # that differentially. Here it is enough that the tx is refused entry.
    with pytest.raises(JSONRPCError):
        await node.rpc.sendrawtransaction(over_tx)
    assert set(await node.rpc.getrawmempool()) == set()

    at = await _spendable_coinbases(node, limit)
    at_tx = await _raw_spend(node, at)
    txid = await node.rpc.sendrawtransaction(at_tx)
    assert set(await node.rpc.getrawmempool()) == {txid}

    # The accepted spend confirms and leaves the mempool empty.
    await node.mine(1)
    assert set(await node.rpc.getrawmempool()) == set()


async def test_rejection_is_caused_by_the_cap(node_factory: NodeFactory) -> None:
    """The same multi-input tx that a low cap rejects is accepted under a higher cap.

    Building the identical 3-input spend against two nodes that differ only in
    -mempooltxinputlimit isolates the input count as the sole cause of the
    rejection, ruling out an incidental failure.
    """
    inputs = 3
    low = await node_factory(0, extra_args=_limit_args(inputs - 1))
    high = await node_factory(1, extra_args=_limit_args(inputs + 1))

    # Run the positive control (higher cap accepts) first so it is observed even
    # if the negative case were to fail.
    for node in (high, low):
        await node.mine(COINBASE_MATURITY + inputs + 1)
        tx = await _raw_spend(node, await _spendable_coinbases(node, inputs))
        if node is low:
            with pytest.raises(JSONRPCError):
                await node.rpc.sendrawtransaction(tx)
            assert set(await node.rpc.getrawmempool()) == set()
        else:
            txid = await node.rpc.sendrawtransaction(tx)
            assert set(await node.rpc.getrawmempool()) == {txid}


async def test_cap_lifts_after_acadia(node_factory: NodeFactory) -> None:
    """The input cap stops being enforced once ACADIA activates.

    AcceptToMemoryPool forces the limit to zero from the ACADIA activation height
    onward, so the same over-limit spend that is dropped while ACADIA is still
    pending is accepted once it has activated -- proving the cap is epoch-gated,
    not absolute.
    """
    limit = 2
    over = limit + 1
    # The cap check evaluates ACADIA against the next block's height. Place the
    # activation a few blocks above coinbase maturity so the over-limit spend has
    # matured inputs both before and after the boundary.
    activation = COINBASE_MATURITY + 10
    node = await node_factory(
        0,
        extra_args=[
            *POW_ARGS,
            "-checkmempool",
            "-debug=mempool",
            f"-mempooltxinputlimit={limit}",
            f"-acadiaactivation={activation}",
        ],
    )

    # Pre-ACADIA: the next block is below the activation height, so the cap is
    # live and the over-limit spend is dropped.
    await node.mine(activation - 2)
    assert await node.rpc.getblockcount() == activation - 2
    pre_tx = await _raw_spend(node, await _spendable_coinbases(node, over))
    with pytest.raises(JSONRPCError):
        await node.rpc.sendrawtransaction(pre_tx)
    assert set(await node.rpc.getrawmempool()) == set()

    # Cross the boundary: the next block is now an ACADIA block, so the cap is
    # forced to zero and the same-shape over-limit spend is accepted.
    await node.mine(1)
    assert await node.rpc.getblockcount() == activation - 1
    post_tx = await _raw_spend(node, await _spendable_coinbases(node, over))
    txid = await node.rpc.sendrawtransaction(post_tx)
    assert set(await node.rpc.getrawmempool()) == {txid}

    await node.mine(1)
    assert set(await node.rpc.getrawmempool()) == set()
