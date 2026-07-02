"""The automated Sprout -> Sapling wallet migration (ZIP 308).

Flux keeps the whole migration engine: the -migration/-migrationdestaddress
init flags, the 500-block cycle (a saplingmigration operation is queued at
height 495 mod 500 targeting the next multiple of 500, its transactions are
committed to the mempool at 499 mod 500, and they expire 450 blocks past the
target), and the z_getmigrationstatus bookkeeping. The z_setmigration RPC
toggle is deprecated once the FLUX rebrand upgrade is active -- which regtest
never is (NO_ACTIVATION_HEIGHT), so the toggle still drives the test the way
upstream wrote it, while production nodes enable migration through the init
flag this test also covers.

Unlike zcash there is NO default destination: Flux removed the HD account-0
derivation (getMigrationDestAddress without the flag is a stub that reports
failure), so -migrationdestaddress is mandatory -- init refuses -migration
without it, z_setmigration(true) answers with a requirement message instead of
enabling, and z_getmigrationstatus omits destination_address entirely. Run 1
migrates node 0's funds to the configured destination; run 2 asserts that
refusal on the flagless second node, then relaunches it with a destination and
enables migration purely over RPC. Long stretches are mined at a 5s block
interval so a connected peer's frozen clock stays within the 2h future-block
tolerance and the chain relays continuously.
"""

import asyncio
from decimal import Decimal

from conftest import NodeFactory
from fluxtest.network import bump_clocks, connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from zhelpers import (
    shielded_args,
    wait_and_assert_operationid_status,
    wait_and_assert_operationid_status_result,
)

# The upstream test's regtest Sapling address and key: Flux uses the same
# regtest bech32 HRPs, so they decode unchanged. Importing the key lets node
# 0's wallet track the funds migrated to the configured destination.
SAPLING_ADDR = (
    "zregtestsapling1ssqj3f3majnl270985gqcdqedd9t4nlttjqskccwevj2v20sc25deqspv3masufnwcdy6"
    "7cydyy"
)
SAPLING_KEY = (
    "secret-extended-key-regtest1qv62zt2fqyqqpqrh2qzc08h7gncf4447jh9kvnnnhjg959fkwt7mhw9j8"
    "e9at7attx8z6u3953u86vcnsujdc2ckdlcmztjt44x3uxpah5mxtncxd0mqcnz9eq8rghh5m4j44ep5d9702s"
    "dvvwawqassulktfegrcp4twxgqdxx4eww3lau0mywuaeztpla2cmvagr5nj98elt45zh6fjznadl6wz52n2uy"
    "hdwcm2wlsu8fnxstrk6s4t55t8dy6jkgx5g0cwpchh5qffp8x5"
)

MIGRATION_EXPIRY_DELTA = 450

DISABLED_NO_FUNDS = "disabled, no funds"
ENABLED_NO_FUNDS = "enabled, no funds"
DISABLED_BEFORE_MIGRATION = "disabled, before migration"
ENABLED_BEFORE_MIGRATION = "enabled, before migration"
DURING_MIGRATION = "during migration"
AFTER_MIGRATION = "after migration"

BASE_ARGS = shielded_args(1)
NODE0_ARGS = [
    *BASE_ARGS,
    "-migration",
    f"-migrationdestaddress={SAPLING_ADDR}",
    "-debug=zrpcunsafe",
]


async def _sync(nodes: list[FluxNode]) -> None:
    await bump_clocks(nodes)
    await sync_blocks(nodes)


async def _check_status(node: FluxNode, dest: str, state: str) -> None:
    status = await node.rpc.z_getmigrationstatus()
    assert status["destination_address"] == dest, status
    assert status["enabled"] is (state not in {DISABLED_NO_FUNDS, DISABLED_BEFORE_MIGRATION}), (
        status
    )
    if state in {DISABLED_BEFORE_MIGRATION, ENABLED_BEFORE_MIGRATION}:
        assert Decimal(status["unmigrated_amount"]) > 0, status
    # During and after the migration the wallet may have migrated everything at
    # once, so unmigrated_amount is only pinned down in the two states above.
    assert (Decimal(status["unfinalized_migrated_amount"]) > 0) is (state == DURING_MIGRATION), (
        status
    )
    assert (Decimal(status["finalized_migrated_amount"]) > 0) is (state == AFTER_MIGRATION), status
    assert status["finalized_migration_transactions"] == (1 if state == AFTER_MIGRATION else 0), (
        status
    )
    expected_txids = 1 if state in {DURING_MIGRATION, AFTER_MIGRATION} else 0
    assert len(status["migration_txids"]) == expected_txids, status


async def _fund_sprout(funder: FluxNode, nodes: list[FluxNode], sprout_addr: str) -> None:
    """Put exactly 10 into ``sprout_addr``, mining one block.

    A coinbase input forbids change in z_sendmany, so an ordinary output is
    funded first and shielded at 0-conf (the funder's own transaction, so the
    wallet sees it immediately); the zero fee keeps the shielded amount exact.
    """
    taddr = await funder.rpc.getnewaddress()
    await funder.rpc.sendtoaddress(taddr, Decimal("10"))
    opid = await funder.rpc.z_sendmany(
        taddr, [{"address": sprout_addr, "amount": Decimal("10")}], 0, 0
    )
    await wait_and_assert_operationid_status(funder, opid)
    await funder.mine(1)
    await _sync(nodes)


async def _wait_positive_unconfirmed(node: FluxNode, zaddr: str, timeout: float = 30) -> None:
    """Poll until the wallet's 0-conf balance for ``zaddr`` turns positive
    (mempool transactions reach the wallet via the once-per-second notifier)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while await node.rpc.z_getbalance(zaddr, 0) <= 0:
        if loop.time() > deadline:
            raise AssertionError(f"no unconfirmed balance showed up on {zaddr}")
        await asyncio.sleep(0.25)


async def _run_migration(
    node: FluxNode,
    nodes: list[FluxNode],
    sprout_addr: str,
    sapling_addr: str,
    target_height: int,
) -> None:
    assert await node.rpc.getblockcount() % 500 == 102, "must start at 102 mod 500"
    assert await node.rpc.z_getbalance(sprout_addr) == Decimal("10")
    assert await node.rpc.z_getbalance(sapling_addr) == Decimal("0")
    await _check_status(node, sapling_addr, DISABLED_BEFORE_MIGRATION)

    await node.rpc.z_setmigration(True)
    await node.mine(392, interval=5)  # -> 494 mod 500
    await _sync(nodes)

    # Nothing is queued yet one block before the trigger height.
    assert await node.rpc.z_getoperationstatus() == []
    await _check_status(node, sapling_addr, ENABLED_BEFORE_MIGRATION)

    # 495 mod 500: the migration operation is queued, targeting the next
    # multiple of 500, and builds its transaction asynchronously.
    await node.mine(1)
    operations = await node.rpc.z_getoperationstatus()
    assert len(operations) == 1
    assert operations[0]["method"] == "saplingmigration"
    assert operations[0]["target_height"] == target_height
    result = await wait_and_assert_operationid_status_result(node, operations[0]["id"])
    assert result["method"] == "saplingmigration"
    assert result["target_height"] == target_height
    assert result["result"]["num_tx_created"] == 1
    assert len(result["result"]["migration_txids"]) == 1
    assert Decimal(result["result"]["amount_migrated"]) > 0
    assert await node.rpc.getrawmempool() == []

    # Up to 498 mod 500 the transaction stays pending and no funds move.
    await node.mine(3)
    await _sync(nodes)
    assert await node.rpc.getrawmempool() == []
    assert await node.rpc.z_getbalance(sprout_addr) == Decimal("10")
    assert await node.rpc.z_getbalance(sapling_addr) == Decimal("0")

    # 499 mod 500: the pending transaction is committed to the mempool; the
    # Sprout note is locked and the Sapling value is only visible at 0-conf.
    await node.mine(1)
    await _sync(nodes)
    mempool = await node.rpc.getrawmempool()
    assert len(mempool) == 1
    assert await node.rpc.z_getbalance(sprout_addr) == Decimal("0")
    assert await node.rpc.z_getbalance(sapling_addr) == Decimal("0")
    await _wait_positive_unconfirmed(node, sapling_addr)
    status = await node.rpc.z_getmigrationstatus()
    unmigrated = Decimal(status["unmigrated_amount"])
    unfinalized = Decimal(status["unfinalized_migrated_amount"])
    assert unmigrated + unfinalized == Decimal("9.9999"), status  # 10 minus the fee
    assert status["migration_txids"] == mempool
    tx = await node.rpc.getrawtransaction(mempool[0], 1)
    assert tx["expiryheight"] == target_height + MIGRATION_EXPIRY_DELTA

    # 0 mod 500: the migration transaction is mined and the funds have moved.
    await node.mine(1)
    await _sync(nodes)
    sprout_balance = await node.rpc.z_getbalance(sprout_addr)
    sapling_balance = await node.rpc.z_getbalance(sapling_addr)
    assert sprout_balance < Decimal("10")
    assert sapling_balance > Decimal("0")
    assert sprout_balance + sapling_balance == Decimal("9.9999")
    await _check_status(node, sapling_addr, DURING_MIGRATION)

    # Ten confirmations finalize the migration transaction.
    await node.mine(10)
    await _sync(nodes)
    await _check_status(node, sapling_addr, AFTER_MIGRATION)
    status = await node.rpc.z_getmigrationstatus()
    assert Decimal(status["unmigrated_amount"]) == sprout_balance
    assert Decimal(status["finalized_migrated_amount"]) == sapling_balance


async def test_sprout_sapling_migration(node_factory: NodeFactory) -> None:
    n0 = await node_factory(0, extra_args=NODE0_ARGS)
    n1 = await node_factory(1, extra_args=BASE_ARGS)
    nodes = [n0, n1]
    await connect_nodes_bi(n0, n1)

    # The init flag enabled migration at launch; the RPC toggle (valid on
    # regtest, deprecated once the FLUX rebrand is active) disables it again.
    await _check_status(n0, SAPLING_ADDR, ENABLED_NO_FUNDS)
    await n0.rpc.z_setmigration(False)
    await _check_status(n0, SAPLING_ADDR, DISABLED_NO_FUNDS)

    # Run 1: migrate node 0's Sprout funds to the configured destination.
    await n0.mine(101)  # the premine is spendable once block 1 has 100 confs
    await n0.rpc.z_importkey(SAPLING_KEY)
    sprout0 = await n0.rpc.z_getnewaddress("sprout")
    await _fund_sprout(n0, nodes, sprout0)  # block 102
    await _run_migration(n0, nodes, sprout0, SAPLING_ADDR, 500)
    # Disable node 0's migration so its leftover Sprout change does not queue
    # another operation at the next cycle during run 2.
    await n0.rpc.z_setmigration(False)

    # Run 2: without -migrationdestaddress there is no default destination on
    # Flux -- enabling is refused and no destination is reported.
    answer = await n1.rpc.z_setmigration(True)
    assert answer == "Must set -migrationdestaddress with valid sapling address"
    status = await n1.rpc.z_getmigrationstatus()
    assert status["enabled"] is False
    assert "destination_address" not in status

    # Relaunched with a destination, node 1 runs the migration enabled purely
    # over RPC (no -migration flag).
    sprout1 = await n1.rpc.z_getnewaddress("sprout")
    sapling1 = await n1.rpc.z_getnewaddress("sapling")
    await n1.restart([*BASE_ARGS, f"-migrationdestaddress={sapling1}"])
    await connect_nodes_bi(n0, n1)
    await n0.mine(601 - await n0.rpc.getblockcount(), interval=5)
    await _sync(nodes)
    await _fund_sprout(n0, nodes, sprout1)  # block 602
    assert await n1.rpc.z_getbalance(sprout1) == Decimal("10")
    await _run_migration(n1, nodes, sprout1, sapling1, 1000)
