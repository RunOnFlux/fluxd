"""Flux's PON emergency-block RPCs (createemergencyblock, signemergencyblock,
verifyemergencyblock, submitemergencyblock).

An emergency block is a PON-version block carrying a fixed emergency-collateral
outpoint and one or more detached signatures over the block hash. It is only
allowed once PON is active, so the nodes here run with ``-ponactivation=1`` to
turn PON on from the first block (the wallet funding that PON otherwise
redirects is irrelevant -- the RPCs need signing keys, not coins).

On regtest the signing path accepts any valid private key (the mainnet/testnet
authorized-key check is bypassed) and a single signature is enough to complete a
block. So the test generates its own key, and exercises the genuine rejections
that exist on regtest: an invalid private key, and signing twice with the same
key. A completed block verifies, submits, and -- with a second connected node --
syncs across the network.
"""

from decimal import Decimal

from conftest import NodeFactory
from fluxtest.network import connect_nodes_bi, sync_blocks
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# PON active from the first block so emergency blocks are allowed.
PON_ARGS = ["-ponactivation=1"]

# Mine clear of the special foundation/swap-pool coinbase heights before
# building emergency-block templates.
BASE_HEIGHT = 105


async def _key(node: FluxNode) -> str:
    """A fresh WIF private key from the node's wallet."""
    return await node.rpc.dumpprivkey(await node.rpc.getnewaddress())


async def test_unsigned_block_is_created_but_invalid(node_factory: NodeFactory) -> None:
    """createemergencyblock yields a template that fails verification unsigned."""
    node = await node_factory(0, extra_args=PON_ARGS)
    await node.mine(BASE_HEIGHT)

    template = await node.rpc.createemergencyblock()
    assert template["height"] == BASE_HEIGHT + 1
    assert template["signatures_required"] == 1
    assert template["collateral"] == "1" * 64
    assert isinstance(template["authorized_keys"], list)
    assert template["authorized_keys"]

    verify = await node.rpc.verifyemergencyblock(template["hex"])
    assert verify["valid"] is False
    assert verify["signatures"] == 0
    assert verify["signatures_required"] == 1


async def test_signed_block_verifies(node_factory: NodeFactory) -> None:
    """A block signed with one key reaches the regtest signature threshold."""
    node = await node_factory(0, extra_args=PON_ARGS)
    await node.mine(BASE_HEIGHT)

    template = await node.rpc.createemergencyblock()
    signed = await node.rpc.signemergencyblock(template["hex"], await _key(node))
    assert signed["signatures"] == 1
    assert signed["complete"] is True

    verify = await node.rpc.verifyemergencyblock(signed["hex"])
    assert verify["valid"] is True
    assert verify["signatures"] == 1


async def test_invalid_private_key_is_rejected(node_factory: NodeFactory) -> None:
    """signemergencyblock refuses a key that is not a valid WIF secret."""
    node = await node_factory(0, extra_args=PON_ARGS)
    await node.mine(BASE_HEIGHT)

    template = await node.rpc.createemergencyblock()
    try:
        await node.rpc.signemergencyblock(template["hex"], "not-a-valid-private-key")
        raise AssertionError("an invalid private key must be rejected")
    except JSONRPCError as exc:
        assert "Invalid private key" in str(exc)


async def test_duplicate_signature_is_rejected(node_factory: NodeFactory) -> None:
    """Signing the same block twice with one key is refused."""
    node = await node_factory(0, extra_args=PON_ARGS)
    await node.mine(BASE_HEIGHT)

    key = await _key(node)
    template = await node.rpc.createemergencyblock()
    signed = await node.rpc.signemergencyblock(template["hex"], key)
    try:
        await node.rpc.signemergencyblock(signed["hex"], key)
        raise AssertionError("re-signing with the same key must be rejected")
    except JSONRPCError as exc:
        assert "already signed" in str(exc)


async def test_submit_is_accepted_and_syncs(node_factory: NodeFactory) -> None:
    """A completed emergency block submits, becomes the tip, and syncs to a peer."""
    node0 = await node_factory(0, extra_args=PON_ARGS)
    node1 = await node_factory(1, extra_args=PON_ARGS)
    await connect_nodes_bi(node0, node1)
    await node0.mine(BASE_HEIGHT)
    await sync_blocks([node0, node1])

    # createemergencyblock stamps the template with the current (frozen) clock;
    # push it past the tip so the block is not rejected as time-too-old, and
    # keep the peer's clock in the same era so it accepts the synced block.
    when = await node0.advance_mocktime(60)
    await node1.set_mocktime_at_least(when)
    template = await node0.rpc.createemergencyblock()
    signed = await node0.rpc.signemergencyblock(template["hex"], await _key(node0))
    assert signed["complete"] is True

    block_hash = await node0.rpc.submitemergencyblock(signed["hex"])
    assert await node0.rpc.getbestblockhash() == block_hash
    assert await node0.rpc.getblockcount() == BASE_HEIGHT + 1

    await sync_blocks([node0, node1])
    on_peer = await node1.rpc.getblock(block_hash)
    assert on_peer["hash"] == block_hash
    assert on_peer["height"] == BASE_HEIGHT + 1


async def test_submit_unsigned_block_is_refused(node_factory: NodeFactory) -> None:
    """An unsigned emergency block is rejected at submit for missing signatures."""
    node = await node_factory(0, extra_args=PON_ARGS)
    await node.mine(BASE_HEIGHT)

    template = await node.rpc.createemergencyblock()
    try:
        await node.rpc.submitemergencyblock(template["hex"])
        raise AssertionError("an unsigned emergency block must not be accepted")
    except JSONRPCError as exc:
        assert "insufficient signatures" in str(exc)
    # The chain is unchanged: nothing was added.
    assert await node.rpc.getblockcount() == BASE_HEIGHT


async def test_subsidy_is_flux_native(node_factory: NodeFactory) -> None:
    """The emergency-block coinbase pays the chain-derived subsidy, not a fixed sum."""
    node = await node_factory(0, extra_args=PON_ARGS)
    await node.mine(BASE_HEIGHT)

    # Advance the frozen clock so the template's timestamp is past the tip.
    await node.advance_mocktime(60)
    template = await node.rpc.createemergencyblock()
    signed = await node.rpc.signemergencyblock(template["hex"], await _key(node))
    block_hash = await node.rpc.submitemergencyblock(signed["hex"])

    block = await node.rpc.getblock(block_hash, 2)
    coinbase = block["tx"][0]
    paid = sum(vout["value"] for vout in coinbase["vout"])
    assert isinstance(paid, Decimal)
    assert paid > 0
