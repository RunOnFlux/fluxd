"""Strict DER signature (BIP66) enforcement.

A block whose spend carries a non-canonical signature -- a NUL byte padded in
before the sighash type, breaking the DER length -- is rejected; the valid spend
is accepted. Flux enforces DER encoding on every signature unconditionally, so
this exercises enforcement, not activation.
"""

from _bip_enforcement import run_enforcement_test
from conftest import NodeFactory
from fluxtest.mininode import CTransaction


def _invalidate_dersig(tx: CTransaction) -> None:
    # scriptSig is `<sig> <pubkey>`; the signature is the leading direct push.
    script = bytes(tx.vin[0].scriptSig)
    sig_len = script[0]
    sig, rest = script[1 : 1 + sig_len], script[1 + sig_len :]
    padded = sig[:-1] + b"\x00" + sig[-1:]  # NUL before the sighash byte
    tx.vin[0].scriptSig = bytes([len(padded)]) + padded + rest


async def test_bipdersig_p2p(node_factory: NodeFactory) -> None:
    await run_enforcement_test(node_factory, _invalidate_dersig)
