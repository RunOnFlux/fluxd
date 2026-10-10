"""Verify the wallet keypool and its interaction with wallet encryption/locking.

With ``-keypool=1`` the wallet keeps a single pre-generated key. After
``encryptwallet`` the keypool flushes and the first ``getnewaddress`` consumes
the lone key, so the second call must fail with the keypool-exhausted error
(code -12). After unlocking and refilling with ``keypoolrefill(3)``, exactly
four change addresses can be drained (the refilled three plus the reserve key)
and the fifth call again exhausts the pool.
"""

import pytest
from conftest import NodeFactory
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

ENCRYPT_ARGS = ["-experimentalfeatures", "-developerencryptwallet"]
KEYPOOL_EXHAUSTED = -12


async def test_keypool(node_factory: NodeFactory) -> None:
    node: FluxNode = await node_factory(0, extra_args=ENCRYPT_ARGS)

    # Encrypting the wallet shuts the daemon down; bring it back on the same datadir.
    await node.rpc.encryptwallet("test")
    await node.restart()

    # The single keypool key is consumed by the first address; the second exhausts it.
    await node.rpc.getnewaddress()
    with pytest.raises(JSONRPCError) as exc:
        await node.rpc.getnewaddress()
    assert exc.value.code == KEYPOOL_EXHAUSTED

    # Put three new keys in the keypool.
    await node.rpc.walletpassphrase("test", 12000)
    await node.rpc.keypoolrefill(3)
    await node.rpc.walletlock()

    # Drain the keys: four unique change addresses come out.
    addresses = {await node.rpc.getrawchangeaddress() for _ in range(4)}
    assert len(addresses) == 4

    # The next request must fail with keypool exhausted.
    with pytest.raises(JSONRPCError) as exc:
        await node.rpc.getrawchangeaddress()
    assert exc.value.code == KEYPOOL_EXHAUSTED
