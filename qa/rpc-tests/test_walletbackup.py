"""Wallet backup, dump, and restore across a multi-node regtest network.

Three spender nodes (0, 1, 2) trade coins amongst themselves while a fourth
node (3) mines. Each spender's wallet is captured two ways -- a binary
``wallet.dat`` copy via ``backupwallet`` and a text key dump via
``dumpwallet`` -- and the balances are recorded. Each spender's wallet is then
destroyed and rebuilt from each backup form in turn, and the recovered balances
are asserted to match what was recorded before the wipe.

The restored value is checked against chain-derived per-node balances captured
at backup time (not any hardcoded reward/total), so the test is faithful to
Flux's PoW coinbase economics. One spender additionally has its block/chainstate
data wiped before the wallet.dat restore, proving the balance is recovered after
a fresh re-sync from the miner, not merely read back from a local chain copy.
"""

import random
import shutil
from collections.abc import Sequence
from decimal import Decimal

import pytest
from conftest import POW_ARGS, NodeFactory
from fluxtest.network import connect_nodes, sync_blocks, sync_mempools
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# Spender nodes get a generous keypool so the many getnewaddress calls across
# the sending rounds never stall on a single-key refill.
SPENDER_ARGS = [*POW_ARGS, "-keypool=100"]
ROUNDS = 5


async def _wire_network(spenders: Sequence[FluxNode], miner: FluxNode) -> None:
    """Mirror the legacy topology: each spender peers the miner, plus 2<->0."""
    for spender in spenders:
        await connect_nodes(spender, miner)
        await connect_nodes(miner, spender)
    await connect_nodes(spenders[2], spenders[0])
    await connect_nodes(spenders[0], spenders[2])


async def _one_send(rng: random.Random, sender: FluxNode, to_address: str) -> None:
    """Half the time, send a small random amount, matching the legacy coin spread."""
    if rng.randint(1, 2) == 1:
        amount = Decimal(rng.randint(1, 10)) / Decimal(10)
        await sender.rpc.sendtoaddress(to_address, amount)


async def _do_one_round(
    rng: random.Random, spenders: Sequence[FluxNode], all_nodes: Sequence[FluxNode], miner: FluxNode
) -> None:
    """One round: spenders swap coins, mempools sync, miner seals a block."""
    addresses = [await spender.rpc.getnewaddress() for spender in spenders]
    await _one_send(rng, spenders[0], addresses[1])
    await _one_send(rng, spenders[0], addresses[2])
    await _one_send(rng, spenders[1], addresses[0])
    await _one_send(rng, spenders[1], addresses[2])
    await _one_send(rng, spenders[2], addresses[0])
    await _one_send(rng, spenders[2], addresses[1])

    await sync_mempools(list(all_nodes))
    await miner.mine(1)
    await sync_blocks(list(all_nodes))


def _wallet_path(node: FluxNode) -> str:
    return str(node.datadir / "regtest" / "wallet.dat")


async def test_walletbackup_restore_from_backup_and_dump(node_factory: NodeFactory) -> None:
    # Nodes 0, 1, 2 are spenders; node 3 is the dedicated miner. All run in PoW
    # mode so coinbases pay the mining wallet. Each spender exports its backups
    # into its own data dir; the data dir path is only known after the node is
    # created, so the -exportdir arg is applied on a same-datadir restart.
    spenders: list[FluxNode] = []
    for i in range(3):
        node = await node_factory(i, extra_args=SPENDER_ARGS)
        await node.restart(extra_args=[*SPENDER_ARGS, f"-exportdir={node.datadir}"])
        spenders.append(node)
    miner = await node_factory(3, extra_args=POW_ARGS)
    all_nodes = [*spenders, miner]
    await _wire_network(spenders, miner)
    await sync_blocks(all_nodes)

    # Each spender mines one block, then the miner matures everyone's coinbase
    # by burying it under 100 more blocks (COINBASE_MATURITY), so every spender
    # has exactly one spendable coinbase to start trading with.
    for spender in spenders:
        await spender.mine(1)
        await sync_blocks(all_nodes)
    await miner.mine(100)
    await sync_blocks(all_nodes)

    for spender in spenders:
        assert await spender.rpc.getbalance() > 0
    assert await miner.rpc.getbalance() == 0

    # Deterministic-per-run sends: the amounts vary, but balances are recorded
    # and restoration is asserted against those recorded values, never a total.
    rng = random.Random(0xF1)
    for _ in range(ROUNDS):
        await _do_one_round(rng, spenders, all_nodes, miner)

    # Capture both backup forms for every spender. dumpwallet/backupwallet write
    # into each node's -exportdir (its data dir); importwallet later reads the
    # dump back by absolute path.
    for spender in spenders:
        await spender.rpc.backupwallet("walletbak")
        await spender.rpc.dumpwallet("walletdump")

    # dumpwallet refuses to clobber an existing file.
    with pytest.raises(JSONRPCError) as exc:
        await spenders[2].rpc.dumpwallet("walletdump")
    assert "Cannot overwrite existing file" in str(exc.value)

    # More trading after the backups, then mature any outstanding fees so the
    # recorded balances are stable (no immature change in flight).
    for _ in range(ROUNDS):
        await _do_one_round(rng, spenders, all_nodes, miner)
    await miner.mine(101)
    await sync_blocks(all_nodes)

    recorded = [await spender.rpc.getbalance() for spender in spenders]
    # Sanity: trading conserved value into the spender wallets (no node lost all
    # its coins), so each recovery target is a real, positive balance.
    assert all(balance > 0 for balance in recorded)

    # --- Restore from the binary wallet.dat backup ---
    # Stop the spenders, wipe each wallet.dat, and additionally wipe node 2's
    # chain so its restored balance must come from a fresh re-sync. The daemon
    # must be down while the on-disk wallet is swapped, then started again on the
    # same datadir; the public restart() cannot wrap a file swap, so the process
    # is stopped and started directly while the RPC session stays open.
    for spender in spenders:
        await spender.stop_daemon()
    for spender in spenders:
        shutil.copyfile(
            str(spender.datadir / "walletbak"),
            _wallet_path(spender),
        )
    shutil.rmtree(spenders[2].datadir / "regtest" / "blocks")
    shutil.rmtree(spenders[2].datadir / "regtest" / "chainstate")

    for spender in spenders:
        await spender.start()
    await _wire_network(spenders, miner)
    # node 2 re-syncs its whole chain from scratch here, so allow well beyond the
    # default sync timeout on a loaded host.
    await sync_blocks(all_nodes, timeout=180)

    for spender, expected in zip(spenders, recorded, strict=True):
        assert await spender.rpc.getbalance() == expected

    # --- Restore from the text dumpwallet dump ---
    # Wipe wallets again (and node 2's chain again); the restarted nodes start at
    # zero balance, then importwallet replays the keys and rescans them back.
    for spender in spenders:
        await spender.stop_daemon()
    for spender in spenders:
        (spender.datadir / "regtest" / "wallet.dat").unlink()
    shutil.rmtree(spenders[2].datadir / "regtest" / "blocks")
    shutil.rmtree(spenders[2].datadir / "regtest" / "chainstate")

    for spender in spenders:
        await spender.start()
    await _wire_network(spenders, miner)
    # node 2 re-syncs its whole chain from scratch here, so allow well beyond the
    # default sync timeout on a loaded host.
    await sync_blocks(all_nodes, timeout=180)

    for spender in spenders:
        assert await spender.rpc.getbalance() == 0

    for spender in spenders:
        await spender.rpc.importwallet(str(spender.datadir / "walletdump"))
    await sync_blocks(all_nodes)

    for spender, expected in zip(spenders, recorded, strict=True):
        assert await spender.rpc.getbalance() == expected
