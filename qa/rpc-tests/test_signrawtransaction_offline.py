"""An offline node must be told the consensus branch id to sign Overwintered txs.

signrawtransaction derives its consensus branch id from the node's LOCAL chain
height. An offline regtest node (no peers) never syncs, so it sits at genesis
height and signs under the pre-upgrade branch id, even though both nodes share
the same activation config. With ACADIA forced active at height 10 the online
node (tip well past 10) builds an Overwintered transaction and validates it under
the ACADIA branch id; the offline node's default (pre-upgrade) signature is
rejected, while passing the explicit ACADIA branch id to signrawtransaction makes
the offline node sign correctly and the online node accepts.

ACADIA shares branch id 0x76b809bb with several other upgrades, so -nuparams
cannot single it out; the regtest-only -acadiaactivation flag activates it
directly (mirroring -ponactivation).
"""

from decimal import Decimal

import pytest
from conftest import COINBASE_MATURITY, POW_ARGS, NodeFactory
from fluxtest.rpc import JSONRPCError

# Forcing ACADIA active at height 10 makes createrawtransaction emit Overwintered
# transactions, whose signatures carry the ACADIA consensus branch id.
ACADIA_ARG = "-acadiaactivation=10"
ACADIA_BRANCH_ID = "76b809bb"


async def test_offline_node_needs_explicit_branch_id(node_factory: NodeFactory) -> None:
    online = await node_factory(0, extra_args=[*POW_ARGS, ACADIA_ARG])
    await online.mine(COINBASE_MATURITY + 1)  # mature block 1's coinbase; tip well past 10

    # The offline node is never connected to anyone, so it never learns the tip
    # and signs as if ACADIA were inactive.
    offline = await node_factory(1, extra_args=["-maxconnections=0", ACADIA_ARG])
    assert len(await offline.rpc.getpeerinfo()) == 0

    # Pick a real spendable coinbase output; listunspent also surfaces unsignable
    # P2SH fund outputs, so filter to spendable and read the true amount.
    spendable = [u for u in await online.rpc.listunspent(1) if u["spendable"]]
    assert spendable, "online node should have matured, spendable coinbase outputs"
    utxo = spendable[0]
    amount = utxo["amount"]
    privkeys = [await online.rpc.dumpprivkey(utxo["address"])]

    create_inputs = [{"txid": utxo["txid"], "vout": utxo["vout"]}]
    sign_inputs = [
        {
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptPubKey": utxo["scriptPubKey"],
            "amount": amount,
        }
    ]

    # Spend the whole output minus a tiny fee; a small hardcoded output against a
    # ~150 FLUX coinbase trips the absurd-fee check before the branch id matters.
    sink = await online.rpc.getnewaddress()
    create_hex = await online.rpc.createrawtransaction(
        create_inputs, {sink: amount - Decimal("0.0001")}
    )

    # The offline node signs with its default (genesis-height) branch id; the online
    # node rejects that signature because it validates under the ACADIA branch id.
    wrong = await offline.rpc.signrawtransaction(create_hex, sign_inputs, privkeys)
    with pytest.raises(JSONRPCError):
        await online.rpc.sendrawtransaction(wrong["hex"])

    # Passing the explicit ACADIA branch id makes the offline node sign under the
    # correct rules, and the online node accepts the result.
    right = await offline.rpc.signrawtransaction(
        create_hex, sign_inputs, privkeys, "ALL", ACADIA_BRANCH_ID
    )
    txid = await online.rpc.sendrawtransaction(right["hex"])
    assert len(txid) > 0
