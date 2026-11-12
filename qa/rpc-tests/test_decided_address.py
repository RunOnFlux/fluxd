"""The node's decided address: the IPv4 address its peers report in their version
messages, by a vote of the peers that are answering.

Each mininode peer reports an address of its choosing as the version message's
addrMe. On regtest inbound peers vote, each peer is a netgroup of its own, one
vote decides, and any valid IPv4 counts, so the addresses need not be routable.
Mainnet's rules (only dialled peers vote, one vote per /16, half the outbound
slots voting) and the early confirm on an address change, which needs a
confirmed fluxnode, are covered by the DecidedAddress gtests.
"""

import asyncio
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
from conftest import POW_ARGS, NodeFactory
from fluxtest.mininode import NodeConn, NodeConnCB, msg_ping
from fluxtest.node import FluxNode
from fluxtest.rpc import JSONRPCError

PEERS = 3
UNDECIDED = {"address": "", "votes": 0, "voters": 0, "changed": 0, "other": [], "inbound": []}


class QuietableCB(NodeConnCB):
    """A peer that stops answering pings once ``quiet`` is set, and so sends nothing."""

    quiet = False

    def on_ping(self, conn: NodeConn, message: msg_ping) -> None:
        if not self.quiet:
            super().on_ping(conn, message)


async def connect_reporting(
    node: FluxNode, addr_me: str, count: int, cb_class: type[NodeConnCB] = NodeConnCB
) -> list[NodeConn]:
    """Open ``count`` peers that each report the node at ``addr_me``. The caller
    keeps the returned connections for as long as the peers must stay: a
    connection that is garbage-collected closes."""
    conns = []
    for _ in range(count):
        cb = cb_class()
        conn = NodeConn("127.0.0.1", node.p2p_port, cb, addr_me=addr_me)
        await conn.connect()
        await cb.wait_for_verack()
        await cb.sync_with_ping()
        conns.append(conn)
    return conns


async def decided(node: FluxNode) -> dict[str, Any]:
    return (await node.rpc.getnetworkinfo())["decided_address"]


async def wait_decided(
    node: FluxNode, address: str, votes: int, timeout: float = 30
) -> dict[str, Any]:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        info = await decided(node)
        if info["address"] == address and info["votes"] == votes:
            return info
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(f"decided_address is {info}, want {address} with {votes} votes")
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
    assert await decided(node) == UNDECIDED

    now = await node.advance_mocktime(10)
    conns = await connect_reporting(node, "1.2.3.4", PEERS)
    info = await wait_decided(node, "1.2.3.4", PEERS)
    assert info["changed"] == now
    assert info["voters"] == PEERS

    # A decided address stands when its voters leave.
    await node.advance_mocktime(10)
    for conn in conns:
        await conn.disconnect_node()
    info = await wait_decided(node, "1.2.3.4", 0)
    assert info["changed"] == now

    # Not a fluxnode: nothing is published.
    assert not (node.datadir / "run").exists()


async def test_fluxnode_publishes_the_decided_address(
    node_factory: NodeFactory, fluxd_binary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = await start_fluxnode(node_factory, fluxd_binary, tmp_path, monkeypatch)
    assert node._proc is not None
    pid = node._proc.pid
    assert published(node) == {"address": "", "pid": pid, "rpcport": node.rpc_port}

    conns = await connect_reporting(node, "1.2.3.4", PEERS)
    await wait_decided(node, "1.2.3.4", PEERS)
    assert published(node) == {"address": "1.2.3.4", "pid": pid, "rpcport": node.rpc_port}

    # A peer more behind the same address leaves the file as it is.
    path = node.datadir / "run" / "fluxd.json"
    path.write_text("untouched")
    conns += await connect_reporting(node, "1.2.3.4", 1)
    await wait_decided(node, "1.2.3.4", PEERS + 1)
    assert path.read_text() == "untouched"

    # With every voter gone the address stands, and so does the file.
    for conn in conns:
        await conn.disconnect_node()
    await wait_decided(node, "1.2.3.4", 0)
    assert path.read_text() == "untouched"

    # Voters for another address move it, and the file with it.
    conns = await connect_reporting(node, "5.6.7.8", 1)
    await wait_decided(node, "5.6.7.8", 1)
    assert published(node) == {"address": "5.6.7.8", "pid": pid, "rpcport": node.rpc_port}

    # A clean stop removes the file.
    await node.stop_daemon()
    assert not (node.datadir / "run" / "fluxd.json").exists()


async def test_one_peer_suffices_on_regtest(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    # No peer reports an address: none is decided.
    assert await decided(node) == UNDECIDED

    _conns = await connect_reporting(node, "1.2.3.4", 1)
    info = await wait_decided(node, "1.2.3.4", 1)
    assert info["voters"] == 1
    assert info["other"] == []


async def test_three_quarters_of_the_vote_changes_the_address(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    first = await node.advance_mocktime(10)
    conns = await connect_reporting(node, "1.2.3.4", PEERS)
    assert (await wait_decided(node, "1.2.3.4", PEERS))["changed"] == first

    # Eight of eleven votes for another address are a majority and change nothing.
    await node.advance_mocktime(10)
    conns += await connect_reporting(node, "5.6.7.8", 8)
    assert len(await node.rpc.getpeerinfo()) == PEERS + 8
    assert await decided(node) == {
        "address": "1.2.3.4",
        "votes": PEERS,
        "voters": PEERS + 8,
        "changed": first,
        "other": [{"address": "5.6.7.8", "votes": 8}],
        "inbound": [],
    }

    # A ninth makes it nine of twelve: three quarters.
    second = await node.advance_mocktime(10)
    conns += await connect_reporting(node, "5.6.7.8", 1)
    info = await wait_decided(node, "5.6.7.8", 9)
    assert info["changed"] == second
    assert info["other"] == [{"address": "1.2.3.4", "votes": PEERS}]


async def test_voters_that_stop_answering_lose_their_votes(node_factory: NodeFactory) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    conns = await connect_reporting(node, "1.2.3.4", 2, QuietableCB)
    await wait_decided(node, "1.2.3.4", 2)

    # The node's address changes: the peers that saw the old one answer nothing
    # more, and a new peer reports the new one. Its report sends a ping to the
    # old address's voters; unanswered, their votes go and the one live vote decides.
    for conn in conns:
        assert isinstance(conn.cb, QuietableCB)
        conn.cb.quiet = True
    conns += await connect_reporting(node, "5.6.7.8", 1)
    assert (await decided(node))["address"] == "1.2.3.4"
    info = await wait_decided(node, "5.6.7.8", 1, timeout=20)
    assert info["voters"] == 1


async def test_silent_voters_are_dropped_while_the_address_lacks_votes(
    node_factory: NodeFactory,
) -> None:
    node = await node_factory(0, extra_args=POW_ARGS)
    conns = await connect_reporting(node, "1.2.3.4", 2, QuietableCB)
    await wait_decided(node, "1.2.3.4", 2)

    for conn in conns:
        assert isinstance(conn.cb, QuietableCB)
        conn.cb.quiet = True
    await node.rpc.ping()

    # Long before the ping timeout would close them, the silent peers are
    # disconnected; the address stands with no votes.
    deadline = asyncio.get_running_loop().time() + 20
    while await node.rpc.getpeerinfo():
        assert asyncio.get_running_loop().time() < deadline, "silent voters still connected"
        await asyncio.sleep(0.2)
    assert (await wait_decided(node, "1.2.3.4", 0))["voters"] == 0


async def test_fluxnode_refuses_a_proxy(
    node_factory: NodeFactory, fluxd_binary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = await start_fluxnode(node_factory, fluxd_binary, tmp_path, monkeypatch)
    args = list(node.extra_args)
    await node.stop_daemon()

    # Through a proxy every peer would see the proxy's address, not the node's.
    with pytest.raises(AssertionError, match="Fluxnodes cannot use -proxy"):
        await node.restart([*args, "-proxy=127.0.0.1:9"])

    # -onion alone leaves clearnet peers direct.
    await node.restart([*args, "-onion=127.0.0.1:9"])
    assert (await node.rpc.getnetworkinfo())["decided_address"]["address"] == ""


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
