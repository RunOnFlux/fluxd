"""The node's decided address: the IPv4 address its peers report in their version
messages, taken by majority once enough peers agree: three on mainnet, one on
regtest.

Each mininode peer reports an address of its choosing as the version message's
addrMe. Regtest admits any valid IPv4, so the addresses need not be routable.
The early confirm on an address change needs a confirmed fluxnode, which the
suite does not run; its logic is covered by the DecidedAddress gtests.
"""

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from conftest import POW_ARGS, NodeFactory
from fluxtest.mininode import NodeConn, NodeConnCB
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

PEERS = 3


async def connect_reporting(node: FluxNode, addr_me: str, count: int) -> list[NodeConn]:
    """Open ``count`` peers that each report the node at ``addr_me``. The caller
    keeps the returned connections for as long as the peers must stay: a
    connection that is garbage-collected closes."""
    conns = []
    for _ in range(count):
        cb = NodeConnCB()
        conn = NodeConn("127.0.0.1", node.p2p_port, cb, addr_me=addr_me)
        await conn.connect()
        await cb.wait_for_verack()
        await cb.sync_with_ping()
        conns.append(conn)
    return conns


async def decided(node: FluxNode) -> dict[str, Any]:
    return (await node.rpc.getnetworkinfo())["decided_address"]


async def wait_decided(
    node: FluxNode, address: str, peers: int, timeout: float = 30
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        info = await decided(node)
        if info["address"] == address and info["peers"] == peers:
            return info
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"decided_address is {info}, want {address} with {peers} peers")
        await asyncio.sleep(0.1)


def published(node: FluxNode) -> dict[str, Any]:
    """The decided address fluxd publishes; on regtest under <datadir>/run."""
    content = (node.datadir / "run" / "fluxd.json").read_text()
    print(f"fluxd.json: {content.strip()}")
    return json.loads(content)


def fluxnode_binary(fluxd_binary: str, bindir: Path) -> str:
    """fluxd in a directory beside stand-in fluxbenchd and fluxbench-cli, which
    fluxnode mode requires to exist; the stand-ins answer nothing."""
    bindir.mkdir()
    binary = bindir / "fluxd"
    try:
        os.link(fluxd_binary, binary)
    except OSError:
        shutil.copy2(fluxd_binary, binary)
    for name in ("fluxbenchd", "fluxbench-cli"):
        stub = bindir / name
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(0o755)
    return str(binary)


async def start_fluxnode(
    node_factory: NodeFactory, fluxd_binary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> FluxNode:
    """A regtest daemon in fluxnode mode (-zelnode), with fluxbench left to its
    manager as on ArcaneOS and a made-up collateral."""
    node = await node_factory(0, extra_args=[*POW_ARGS, "-txindex"])
    wif = await node.rpc.dumpprivkey(await node.rpc.getnewaddress())
    monkeypatch.setenv("UNMANAGED_FLUXBENCHD", "1")
    node.binary = fluxnode_binary(fluxd_binary, tmp_path / "bin")
    await node.restart(
        [
            *POW_ARGS,
            "-txindex",
            "-zelnode",
            f"-zelnodeprivkey={wif}",
            "-zelnodeoutpoint=" + "ab" * 32,
            "-zelnodeindex=0",
        ]
    )
    return node


async def test_three_peers_decide_the_address(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    assert await decided(node) == {"address": "", "peers": 0, "changed": 0}

    now = await node.advance_mocktime(10)
    conns = await connect_reporting(node, "1.2.3.4", PEERS)
    info = await wait_decided(node, "1.2.3.4", PEERS)
    assert info["changed"] == now

    for conn in conns:
        await conn.disconnect_node()
    await wait_decided(node, "", 0)

    # Not a fluxnode: nothing is published.
    assert not (node.datadir / "run").exists()


async def test_fluxnode_publishes_the_decided_address(
    node_factory: NodeFactory, fluxd_binary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = await start_fluxnode(node_factory, fluxd_binary, tmp_path, monkeypatch)
    assert node._proc is not None
    pid = node._proc.pid
    assert published(node) == {"address": "", "pid": pid}

    conns = await connect_reporting(node, "1.2.3.4", PEERS)
    await wait_decided(node, "1.2.3.4", PEERS)
    assert published(node) == {"address": "1.2.3.4", "pid": pid}

    # A peer more behind the same address leaves the file as it is.
    path = node.datadir / "run" / "fluxd.json"
    path.write_text("untouched")
    conns += await connect_reporting(node, "1.2.3.4", 1)
    await wait_decided(node, "1.2.3.4", PEERS + 1)
    assert path.read_text() == "untouched"

    for conn in conns:
        await conn.disconnect_node()
    await wait_decided(node, "", 0)
    assert published(node) == {"address": "", "pid": pid}

    # A clean stop removes the file.
    await node.stop_daemon()
    assert not (node.datadir / "run" / "fluxd.json").exists()


async def test_one_peer_suffices_on_regtest(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    # No peer reports an address: none is decided.
    assert await decided(node) == {"address": "", "peers": 0, "changed": 0}

    conns = await connect_reporting(node, "1.2.3.4", 1)
    await wait_decided(node, "1.2.3.4", 1)

    # Two peers for another address outvote the one.
    conns += await connect_reporting(node, "5.6.7.8", 2)
    await wait_decided(node, "5.6.7.8", 2)
    peers = await node.rpc.getpeerinfo()
    assert sorted(p["addrlocal"].rsplit(":", 1)[0] for p in peers) == [
        "1.2.3.4",
        "5.6.7.8",
        "5.6.7.8",
    ]


async def test_new_majority_changes_the_address(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    first = await node.advance_mocktime(10)
    conns = await connect_reporting(node, "1.2.3.4", PEERS)
    assert (await wait_decided(node, "1.2.3.4", PEERS))["changed"] == first

    # Three newer peers for another address tie the decided one, which keeps its place.
    await node.advance_mocktime(10)
    conns += await connect_reporting(node, "5.6.7.8", PEERS)
    assert len(await node.rpc.getpeerinfo()) == 2 * PEERS
    assert await decided(node) == {"address": "1.2.3.4", "peers": PEERS, "changed": first}

    # A fourth peer for the new address gives it the majority.
    second = await node.advance_mocktime(10)
    conns += await connect_reporting(node, "5.6.7.8", 1)
    assert (await wait_decided(node, "5.6.7.8", PEERS + 1))["changed"] == second


async def test_regtest_reads_the_default_fluxos_port(node_factory: NodeFactory) -> None:
    # No FluxOS runs here, so /run/fluxos/fluxos.json is absent and regtest assumes 16127.
    node = await node_factory(0, extra_args=POW_ARGS)
    port = (await node.rpc.getnetworkinfo())["fluxos_port"]
    assert port["port"] == 16127
    assert port["source"] == "default"
    assert "/run/fluxos/fluxos.json" in port["reason"]


async def test_confirm_rpc_needs_the_decided_address(
    node_factory: NodeFactory, fluxd_binary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = await start_fluxnode(node_factory, fluxd_binary, tmp_path, monkeypatch)

    # The port reads as regtest's default; no peer reports an address.
    info = await node.rpc.getnetworkinfo()
    assert info["fluxos_port"]["port"] == 16127
    assert info["decided_address"]["address"] == ""
    with pytest.raises(JSONRPCError) as missing:
        await node.rpc.createconfirmationtransaction()
    assert "No confirmation sent" in str(missing.value)
    assert "no decided address" in str(missing.value)
    assert "no FluxOS port" not in str(missing.value)

    # With an address decided the RPC goes on to build the confirm; the made-up
    # collateral has no fluxnode record, so signing fails and nothing is sent.
    _conns = await connect_reporting(node, "1.2.3.4", 1)
    await wait_decided(node, "1.2.3.4", 1)
    with pytest.raises(JSONRPCError) as unsigned:
        await node.rpc.createconfirmationtransaction()
    assert "No confirmation sent" not in str(unsigned.value)
