"""importprivkey carries a key's full UTXO history via rescan.

A single bob address receives a sequence of distinct confirmed UTXOs from alice.
The key exported from bob and imported into charlie (rescan=true) makes charlie
observe exactly the same UTXO set bob had at export time, and importprivkey is
idempotent. Further sends after the import land on both bob and charlie.
"""

from decimal import Decimal

from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode

# Arbitrary small sends, each mined into its own block so it becomes a distinct
# confirmed UTXO on the shared address.
AMOUNTS = [Decimal(a) for a in ("2.3", "3.7", "0.1", "0.5", "1.0", "0.19")]


async def _verify_utxos(node: FluxNode, addr: str, amounts: list[Decimal]) -> None:
    """Assert ``node``'s UTXOs on ``addr`` match ``amounts`` in send order.

    Each amount was mined in its own block, so every UTXO has a distinct
    confirmation count; ordering by confirmations descending (oldest first)
    reproduces the order the sends were made. Amount breaks any tie.
    """
    utxos = await node.rpc.listunspent(1, 10**9, [addr])
    utxos.sort(key=lambda u: (-u["confirmations"], u["amount"]))
    got = [u["amount"] for u in utxos]
    assert got == amounts, f"expected {amounts!r}; utxos {utxos!r}"


async def test_key_import_export(node_factory: NodeFactory) -> None:
    alice = await node_factory(0, extra_args=POW_ARGS)
    bob = await node_factory(1, extra_args=POW_ARGS)
    charlie = await node_factory(2, extra_args=POW_ARGS)

    await connect_nodes_bi(alice, bob)
    await connect_nodes_bi(bob, charlie)
    await connect_nodes_bi(alice, charlie)

    # Seed alice with a matured, spendable balance; alice is both funder and miner.
    await alice.mine(COINBASE_MATURITY + 1)
    await sync_blocks([alice, bob, charlie])

    addr = await bob.rpc.getnewaddress()
    await _verify_utxos(bob, addr, [])
    await _verify_utxos(charlie, addr, [])

    # alice must be able to cover every send.
    assert await alice.rpc.getbalance() > sum(AMOUNTS, Decimal(0))

    async def alice_to_bob(amount: Decimal) -> None:
        # alice is the miner, so the send is already in alice's mempool when she
        # mines it; only the resulting block needs to propagate to the peers.
        await alice.rpc.sendtoaddress(addr, amount)
        await alice.mine(1)
        await sync_blocks([alice, bob, charlie])

    for amount in AMOUNTS[0:2]:
        await alice_to_bob(amount)

    privkey = await bob.rpc.dumpprivkey(addr)

    for amount in AMOUNTS[2:4]:
        await alice_to_bob(amount)

    await _verify_utxos(bob, addr, AMOUNTS[:4])
    await _verify_utxos(charlie, addr, [])

    # rescan=true backfills the key's whole confirmed history.
    ipkaddr = await charlie.rpc.importprivkey(privkey, "", True)
    assert ipkaddr == addr
    await _verify_utxos(charlie, addr, AMOUNTS[:4])

    # Re-importing the same key is idempotent and leaves the UTXO set unchanged.
    ipkaddr2 = await charlie.rpc.importprivkey(privkey, "", True)
    assert ipkaddr2 == addr
    await _verify_utxos(charlie, addr, AMOUNTS[:4])

    for amount in AMOUNTS[4:]:
        await alice_to_bob(amount)

    await _verify_utxos(bob, addr, AMOUNTS)
    await _verify_utxos(charlie, addr, AMOUNTS)
