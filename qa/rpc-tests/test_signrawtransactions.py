"""Test signrawtransaction with explicit inputs and private keys."""

from conftest import NodeFactory

PRIVKEY = "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N"
ADDRESS = "tmJXomn8fhYy3AFqDEteifjHRMUdKtBuTGM"
TX_A = "9b907ef1e3c26fc71fe4a4b3580bc75264112f95050014157059c736f0202e71"
TX_B = "5b8673686910442c644b1f4993d8f7753c7c8fcb5c87ee40d56eaeef25204547"
SCRIPT_A = "76a91460baa0f494b38ce3c940dea67f3804dc52d1fb9488ac"


async def test_successful_signing(node_factory: NodeFactory) -> None:
    node = await node_factory(0)
    inputs = [{"txid": TX_A, "vout": 0, "scriptPubKey": SCRIPT_A}]
    rawtx = await node.rpc.createrawtransaction(inputs, {ADDRESS: 0.1})
    signed = await node.rpc.signrawtransaction(rawtx, inputs, [PRIVKEY])
    assert signed["complete"] is True
    assert "errors" not in signed


async def test_script_verification_errors(node_factory: NodeFactory) -> None:
    node = await node_factory(0)
    inputs = [
        {"txid": TX_A, "vout": 0},
        {"txid": TX_B, "vout": 7},  # invalid (bad scriptPubKey)
        {"txid": TX_A, "vout": 1},  # missing script
    ]
    scripts = [
        {"txid": TX_A, "vout": 0, "scriptPubKey": SCRIPT_A},
        {"txid": TX_B, "vout": 7, "scriptPubKey": "badbadbadbad"},
    ]
    rawtx = await node.rpc.createrawtransaction(inputs, {ADDRESS: 0.1})
    signed = await node.rpc.signrawtransaction(rawtx, scripts, [PRIVKEY])

    assert signed["complete"] is False
    assert len(signed["errors"]) == 2
    for field in ("txid", "vout", "scriptSig", "sequence", "error"):
        assert field in signed["errors"][0]
    # The errors refer to the invalid (vin 1) and missing (vin 2) inputs.
    assert signed["errors"][0]["txid"] == inputs[1]["txid"]
    assert signed["errors"][0]["vout"] == inputs[1]["vout"]
    assert signed["errors"][1]["txid"] == inputs[2]["txid"]
    assert signed["errors"][1]["vout"] == inputs[2]["vout"]
