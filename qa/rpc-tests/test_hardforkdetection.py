"""Flux detects a longer competing (invalid) chain and enters safe mode.

When a node's former main chain becomes invalid and outweighs its new active
tip by more than ~6 blocks of work, fluxd flags ``fLargeWorkInvalidChainFound``
(src/main.cpp CheckForkWarningConditions). That has two observable effects:

* RPC commands flagged ``okSafeMode=false`` (getbalance, listunspent,
  gettransaction) are refused with a ``Safe mode:`` JSON-RPC error whose text
  warns "We do not appear to fully agree with our peers!". Commands flagged
  ``okSafeMode=true`` (getblockcount, getblock, generate, ...) keep working.
* ``-alertnotify`` fires once with "Found invalid chain at least ~6 blocks
  longer than our best chain.".

Mining enough new blocks on the active tip to out-work the invalid chain clears
the condition, and the previously refused RPCs work again.
"""

from alertnotify import notify_arg, wait_for_alert
from conftest import POW_ARGS, NodeFactory
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

# Text of the safe-mode RPC warning (src/main.cpp GetWarnings) and the alert
# message (src/main.cpp CheckForkWarningConditions). fluxd sanitizes the alert
# before invoking -alertnotify (dropping the leading "~"), so the needle is a
# sanitization-safe substring.
SAFE_MODE_NEEDLE = "We do not appear to fully agree with our peers!"
ALERT_NEEDLE = "Found invalid chain at least"


async def _assert_safe_mode_on(node: FluxNode) -> None:
    """A blocked (okSafeMode=false) RPC raises the safe-mode warning."""
    try:
        await node.rpc.getbalance()
    except JSONRPCError as exc:
        message = exc.error.get("message", "")
        assert "Safe mode:" in message, message
        assert SAFE_MODE_NEEDLE in message, message
    else:
        raise AssertionError("getbalance succeeded but safe mode was expected on")


async def _assert_safe_mode_off(node: FluxNode) -> None:
    """A blocked (okSafeMode=false) RPC succeeds when safe mode is clear."""
    await node.rpc.getbalance()


async def test_invalid_chain_triggers_and_clears_safe_mode(
    node_factory: NodeFactory,
) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    # Restart with -alertnotify wired to a capture file under the datadir.
    alert_file = node.datadir / "alert.txt"
    await node.restart(extra_args=[*POW_ARGS, notify_arg(alert_file)])

    # Build a chain, then invalidate its base so the whole former chain becomes
    # an invalid branch far longer than the new (genesis) active tip.
    await node.mine(100)
    assert await node.rpc.getblockcount() == 100
    for height in range(100, 0, -1):
        await node.rpc.invalidateblock(await node.rpc.getblockhash(height))
    assert await node.rpc.getblockcount() == 0

    # okSafeMode=true RPCs still work; blocked RPCs are refused.
    assert await node.rpc.getblockcount() == 0
    await _assert_safe_mode_on(node)

    # -alertnotify fired with the long-fork warning.
    await wait_for_alert(alert_file, ALERT_NEEDLE)

    # While our chain grows but stays shorter than the invalid branch, safe mode
    # stays on. Mining works because generate is okSafeMode=true.
    await node.mine(50)
    assert await node.rpc.getblockcount() == 50
    await _assert_safe_mode_on(node)

    # Once the active tip out-works the invalid branch, safe mode clears and the
    # previously refused RPC works again.
    await node.mine(50)
    assert await node.rpc.getblockcount() == 100
    await _assert_safe_mode_off(node)
