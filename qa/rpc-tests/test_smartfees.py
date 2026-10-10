"""estimatefee tracks the fees that recently paid for confirmation.

A single PoW-mode node floods its mempool with many fee-varied transactions and
mines them under three deliberately different mining regimes -- blocks large
enough to clear the mempool every block, blocks too small to keep up, and blocks
just big enough -- exactly the regimes the legacy test exercised. After each
regime the estimator's output is checked against the same invariants the legacy
asserted, restated as behaviour rather than zcash's literal satoshi values:

* every produced estimate lies within the range of fee rates actually paid;
* estimates are monotonically non-increasing as the confirmation target rises
  (a slower target never costs more than a faster one);
* once a confirmation target yields a valid estimate, every higher target does
  too (no valid estimate sits below an invalid one);
* the number of confirmation targets without a valid estimate stays within the
  per-regime tolerance the legacy allowed (1, then 3, then 2).

Flux exposes estimatefee / estimatepriority (no estimatesmartfee). The legacy
floods only fee-paying transactions, so it exercises -- and this test preserves
-- the estimatefee path; see the module notes for estimatepriority.

The legacy built unsigned P2SH-puzzle transactions and spliced scriptSigs into
the raw hex at fixed byte offsets to avoid signing; that offset math assumes a
Bitcoin transaction layout. This test instead spends real, signed, low-value
low-priority outputs, which keeps the transactions in the estimator's fee bucket
(not its priority bucket) and derives every fee from on-chain values.
"""

import random
from collections import Counter
from decimal import Decimal

import pytest
from conftest import POW_ARGS, NodeFactory
from fluxtest.node import FluxNode

# src/policy/fees.h MAX_BLOCK_CONFIRMS: the estimator tracks confirmation targets
# 1..25, so those are the targets worth querying.
MAX_CONFIRMS = 25

# Exponentially spaced fee multiples of the relay fee, mirroring the legacy's
# exponential fee distribution but bounded to a handful of tiers so the volume
# concentrates enough for the estimator to bootstrap quickly. Each transaction
# pays (tier * relayfee), well above the relay minimum, so it is classified as a
# fee data point rather than a priority data point.
FEE_TIERS = [2, 3, 4, 6, 9, 13, 20, 30]

# Splitting one ~150 FLUX coinbase into this many equal outputs yields low-value
# outputs whose priority (value * age / size) stays below the estimator's
# AllowFreeThreshold once confirmed, so spends of them count as fee data points.
SPLITS_PER_COINBASE = 200

# Mocktime keeps regtest mining instant, so these counts cost seconds, not the
# real minutes the legacy warned about. They are sized only as high as needed for
# the estimator's decayed moving average to produce stable, in-range estimates.
POOL_COINBASES = 100
PER_BLOCK = 60

# A rounding slack matching the legacy's, to absorb the estimator reporting a
# bucket average rather than an exact paid fee rate.
DELTA = Decimal("0.000001")

BASE_ARGS = [*POW_ARGS, "-relaypriority=0", "-maxorphantx=1000", "-blockprioritysize=0"]


def _miner_args(block_max_size: int) -> list[str]:
    return [*BASE_ARGS, f"-blockmaxsize={block_max_size}"]


def check_estimates(estimates: list[Decimal], fees_seen: list[Decimal], max_invalid: int) -> None:
    """Assert estimatefee's output meets the legacy invariants against paid fees.

    ``estimates`` is estimatefee(1..MAX_CONFIRMS); ``fees_seen`` is every fee
    rate (FLUX/kB) actually paid so far. ``max_invalid`` is the tolerated number
    of confirmation targets that may lack a valid estimate.
    """
    lo, hi = min(fees_seen), max(fees_seen)
    # A faster confirmation target never costs less than a slower one, so the
    # estimate sequence must be non-increasing; seed the bound at the max paid.
    last = hi
    for estimate in estimates:
        if estimate < 0:
            continue
        assert estimate + DELTA >= lo, f"estimate {estimate} below paid range floor {lo}"
        assert estimate - DELTA <= hi, f"estimate {estimate} above paid range ceiling {hi}"
        assert estimate - DELTA <= last, (
            f"estimate {estimate} exceeds faster-target estimate {last}"
        )
        last = estimate

    # No valid estimate may appear at a lower confirmation target than an invalid
    # one: once the estimator can answer a target, it answers every slower target.
    seen_valid = False
    for estimate in estimates:
        if estimate >= 0:
            seen_valid = True
        elif seen_valid:
            raise AssertionError("a valid estimate appears below an invalid one")

    invalid = sum(1 for estimate in estimates if estimate < 0)
    assert invalid <= max_invalid, f"{invalid} targets lacked an estimate (max {max_invalid})"


async def _all_estimates(node: FluxNode) -> list[Decimal]:
    return [await node.rpc.estimatefee(target) for target in range(1, MAX_CONFIRMS + 1)]


async def _spendable(node: FluxNode, amount: Decimal | None = None) -> list[dict]:
    """Spendable utxos, excluding the unsignable P2SH fund outputs Flux lists.

    When ``amount`` is given, only outputs of exactly that value are returned --
    used to pick up the equal-valued small outputs produced by splitting.
    """
    utxos = [u for u in await node.rpc.listunspent(1) if u["spendable"]]
    if amount is not None:
        utxos = [u for u in utxos if u["amount"] == amount]
    return utxos


async def _build_low_priority_pool(node: FluxNode, coinbases: int) -> list[dict]:
    """Split matured coinbases into many equal low-value confirmed outputs.

    Only the uniform regular coinbases (a single flat reward each) are split, not
    the much larger block-1 premine coinbase: applying one per-output value to a
    differently valued input would leave a huge residual that trips the
    absurd-fee check. Splitting a same-valued input into outputs that sum back to
    it (less a tiny fee) keeps the split transaction acceptable. Returns the list
    of confirmed equal-valued small outputs that the flood spends from.
    """
    coins = await _spendable(node)
    assert coins, "no spendable coinbases to split"
    # The regular coinbase reward is the most common spendable value; the premine
    # is a lone outlier and is excluded by selecting that modal value.
    reward = Counter(c["amount"] for c in coins).most_common(1)[0][0]
    coins = [c for c in coins if c["amount"] == reward][:coinbases]
    per = ((reward - Decimal("0.001")) / SPLITS_PER_COINBASE).quantize(Decimal("0.00000001"))
    addresses = [await node.rpc.getnewaddress() for _ in range(SPLITS_PER_COINBASE)]
    for coin in coins:
        outputs = {addresses[i]: per for i in range(SPLITS_PER_COINBASE)}
        rawtx = await node.rpc.createrawtransaction(
            [{"txid": coin["txid"], "vout": coin["vout"]}], outputs
        )
        signed = await node.rpc.signrawtransaction(rawtx)
        assert signed["complete"] is True
        await node.rpc.sendrawtransaction(signed["hex"])
    await node.mine(1)
    return await _spendable(node, per)


async def _flood_and_mine(
    node: FluxNode,
    pool: list[dict],
    relayfee: Decimal,
    fees_seen: list[Decimal],
    rng: random.Random,
    blocks: int,
) -> None:
    """Spend small outputs at fee-varied rates, mining one block per round.

    Each round spends up to PER_BLOCK outputs popped from ``pool``, each to a
    fresh address with an explicit, chain-derived fee (input value minus output
    value). Outputs are consumed from the caller-owned pool and never re-queried
    from the wallet, so a backlogged spend sitting unmined in the mempool is
    never offered up again (mempool replacement is disabled, so re-spending an
    already-spent input would be rejected). The fee per kB is recorded so the
    estimates can be bounded by what was actually paid. When the miner's block
    size cannot keep up, the backlog is what drives the estimate for slower
    confirmation targets upward.
    """
    for _ in range(blocks):
        for _ in range(PER_BLOCK):
            if not pool:
                return
            utxo = pool.pop()
            fee = (relayfee * rng.choice(FEE_TIERS)).quantize(Decimal("0.00000001"))
            output_value = utxo["amount"] - fee
            address = await node.rpc.getnewaddress()
            rawtx = await node.rpc.createrawtransaction(
                [{"txid": utxo["txid"], "vout": utxo["vout"]}], {address: output_value}
            )
            signed = await node.rpc.signrawtransaction(rawtx)
            assert signed["complete"] is True
            await node.rpc.sendrawtransaction(signed["hex"])
            tx_kb = Decimal(len(signed["hex"]) // 2) / Decimal(1000)
            fees_seen.append(fee / tx_kb)
        await node.mine(1)


async def _drain_mempool(node: FluxNode, max_blocks: int = 40) -> None:
    """Mine until the mempool is empty (or a safety cap is reached)."""
    for _ in range(max_blocks):
        if not await node.rpc.getrawmempool():
            return
        await node.mine(1)


async def test_estimatefee_tracks_paid_fees(node_factory: NodeFactory) -> None:
    # A fixed seed makes the fee-tier choices reproducible run to run; the wallet
    # keys and addresses are random per run but each transaction targets a fresh
    # address, so the flood is order- and address-independent.
    rng = random.Random(20240619)

    # Start with blocks large enough to clear the whole mempool every block.
    node = await node_factory(0, extra_args=_miner_args(400000))
    relayfee = (await node.rpc.getnetworkinfo())["relayfee"]
    assert relayfee > 0

    # Mature enough coinbases to both seed the small-output pool and have spares.
    await node.mine(POOL_COINBASES + 105)
    # One shared pool of confirmed small outputs, consumed across every regime.
    # The split keeps these outputs confirmed on-chain, so they survive the
    # restarts between regimes; each flood pops the ones it spends.
    pool = await _build_low_priority_pool(node, POOL_COINBASES)
    assert len(pool) >= PER_BLOCK * 100, f"pool too small to sustain the flood: {len(pool)}"

    fees_seen: list[Decimal] = []

    # Regime 1: a huge block size empties the mempool each block, so every
    # transaction confirms in one block. At most one confirmation target may
    # still lack an estimate.
    await _flood_and_mine(node, pool, relayfee, fees_seen, rng, blocks=30)
    check_estimates(await _all_estimates(node), fees_seen, max_invalid=1)

    # Regime 2: a stingy block size cannot keep up with the transaction rate, so
    # a backlog forms and confirmations spread across several blocks. The
    # estimator tolerates up to three targets without an estimate here.
    await node.restart(extra_args=_miner_args(8000))
    await _flood_and_mine(node, pool, relayfee, fees_seen, rng, blocks=30)
    await _drain_mempool(node)
    check_estimates(await _all_estimates(node), fees_seen, max_invalid=3)

    # Regime 3: a block size just above the transaction rate -- the steady state
    # the estimator is built for. Up to two targets may lack an estimate.
    await node.restart(extra_args=_miner_args(20000))
    await _flood_and_mine(node, pool, relayfee, fees_seen, rng, blocks=40)
    await _drain_mempool(node)
    check_estimates(await _all_estimates(node), fees_seen, max_invalid=2)

    # Final state after every mempool has been emptied: the estimates must still
    # hold the same invariants.
    await _drain_mempool(node)
    check_estimates(await _all_estimates(node), fees_seen, max_invalid=2)


@pytest.mark.parametrize("target", [-5, 0])
async def test_estimatefee_below_one_clamps_to_one(node_factory: NodeFactory, target: int) -> None:
    """estimatefee clamps a confirmation target below 1 up to 1.

    A fresh node has observed no confirmations, so estimatefee returns the
    insufficient-data sentinel (-1) for target 1; a target of 0 or negative is
    clamped to 1 (src/rpc/mining.cpp) and must return the same sentinel rather
    than erroring.
    """
    node = await node_factory(0, extra_args=POW_ARGS)
    assert await node.rpc.estimatefee(1) == Decimal(-1)
    assert await node.rpc.estimatefee(target) == Decimal(-1)
