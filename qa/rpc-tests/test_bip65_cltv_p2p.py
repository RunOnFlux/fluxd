"""CHECKLOCKTIMEVERIFY (BIP65) enforcement.

A block whose spend prepends a ``-1 CHECKLOCKTIMEVERIFY`` (which fails for a
negative argument) is rejected; the valid spend is accepted. Flux enforces CLTV
unconditionally, so this exercises enforcement, not activation.
"""

from _bip_enforcement import run_enforcement_test
from conftest import NodeFactory
from fluxtest.mininode import CTransaction
from fluxtest.script import OP_1NEGATE, OP_DROP, OP_NOP2, CScript


def _invalidate_cltv(tx: CTransaction) -> None:
    prefix = CScript([OP_1NEGATE, OP_NOP2, OP_DROP])  # OP_NOP2 == OP_CHECKLOCKTIMEVERIFY
    tx.vin[0].scriptSig = prefix + bytes(tx.vin[0].scriptSig)


async def test_bip65_cltv_p2p(node_factory: NodeFactory) -> None:
    await run_enforcement_test(node_factory, _invalidate_cltv)
