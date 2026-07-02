"""The RPC server binds to exactly the interfaces -rpcbind selects, and
-rpcallowip gates which client IPs may connect.

Two behaviours are covered against a real regtest fluxd:

* Bind matrix: launched with ``-rpcallowip``/``-rpcbind`` combinations, the
  process's listening sockets (read from ``/proc`` via netutil) must equal the
  expected (address, port) set -- default loopback, an explicit IPv4 address, an
  alternate port, multiple ports on one host, IPv6, IPv4+IPv6 together, and a
  non-loopback interface.
* Allow matrix: a node started with ``-rpcallowip=<non-loopback-ip>`` answers an
  RPC GET arriving on that interface, while a node that allows only an unrelated
  IP refuses the same request.

When ``-rpcallowip`` is given without ``-rpcbind`` the server binds to any: it
pushes both ``0.0.0.0`` and ``::`` (httpserver.cpp HTTPBindAddresses), but the
dual-stack ``::`` socket already accepts IPv4, so the ``0.0.0.0`` bind is
redundant and only ``::`` ends up listening -- the set the legacy matrix
asserts. Every expected set matches the legacy matrix.

Linux-only: discovering the bound sockets reads ``/proc/net/tcp``/``tcp6`` and
``/proc/<pid>/fd``.
"""

import asyncio
import sys
from pathlib import Path

import aiohttp
import pytest
from conftest import NodeFactory
from netutil import addr_to_hex, all_interfaces, get_bind_addrs

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="reads /proc/net/tcp and /proc/<pid>/fd, which only exist on Linux",
)

# Ports for the bind matrix. The base/alt ports must not collide with the
# node_factory fixture's range (12000 + pid%990, plus 500 for p2p) or with each
# other across the two alternate-port cases.
_RPC_PORT = 19444
_ALT_PORT_A = 32171
_ALT_PORT_B = 32172
_P2P_PORT = 19555

# The framework's RPC credentials (flux.conf rpcuser/rpcpassword).
_RPC_USER = "rt"
_RPC_PASSWORD = "rt"

HTTP_OK = 200
# fluxd answers an RPC request from a non-allowed client IP with a 403 rather
# than closing the connection (httpserver.cpp http_request_cb -> ClientAllowed).
HTTP_FORBIDDEN = 403


def _first_non_loopback_ip() -> str | None:
    for _name, ip in all_interfaces():
        if ip != "127.0.0.1":
            return ip
    return None


def _expected(*pairs: tuple[str, int]) -> set[tuple[str, int]]:
    """Build a comparable bound-set from (address, port) pairs.

    get_bind_addrs returns kernel hex addresses, so the expected addresses are
    run through addr_to_hex to match.
    """
    return {(addr_to_hex(addr), port) for addr, port in pairs}


def _write_conf(datadir: Path) -> None:
    """Write the base regtest flux.conf (mirrors fluxtest.node._write_conf).

    Per-case ``-rpcbind``/``-rpcallowip``/``-nolisten`` flags are passed on the
    command line, not written here: the ``-no<flag>`` negation form is only
    honoured as an argv option, and a conf file cannot express it.
    """
    datadir.mkdir(parents=True, exist_ok=True)
    (datadir / "flux.conf").write_text(
        "regtest=1\n"
        "showmetrics=0\n"
        f"rpcuser={_RPC_USER}\n"
        f"rpcpassword={_RPC_PASSWORD}\n"
        f"port={_P2P_PORT}\n"
        f"rpcport={_RPC_PORT}\n"
        "listenonion=0\n"
    )


async def _read_listen_addrs(
    binary: str, datadir: Path, extra: list[str], settle: float = 8.0
) -> set[tuple[str, int]]:
    """Launch fluxd directly, let it open its listening sockets, read the bound set.

    node_factory cannot be used for bind cases that do not expose RPC on
    127.0.0.1, so this drives the process itself: write the conf, spawn the
    binary with the per-case flags on the command line, poll /proc for the
    daemon's listening sockets until they settle (a process binding several ports
    opens them within a short window), then terminate. ``-nolisten`` (passed by
    every case) drops the p2p listener so the bound set is exactly the RPC binds;
    ``-rest`` is omitted as it adds no listener beyond the RPC bind set.
    """
    _write_conf(datadir)
    stderr_path = datadir / "node_stderr.log"
    with open(stderr_path, "w+") as stderr:
        proc = await asyncio.create_subprocess_exec(
            binary,
            f"-datadir={datadir}",
            "-keypool=1",
            "-discover=0",
            *extra,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=stderr,
        )
        try:
            pid = proc.pid
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 40.0
            stable: set[tuple[str, int]] = set()
            stable_since: float | None = None
            while True:
                if proc.returncode is not None:
                    raise AssertionError(
                        f"fluxd exited with code {proc.returncode} during startup:\n"
                        f"{stderr_path.read_text().strip() or '(no output captured)'}"
                    )
                try:
                    current = set(get_bind_addrs(pid))
                except FileNotFoundError:
                    current = set()
                now = loop.time()
                if current and current == stable:
                    if stable_since is not None and now - stable_since >= settle:
                        return current
                else:
                    stable = current
                    stable_since = now
                if now > deadline:
                    raise AssertionError(
                        f"fluxd listening sockets did not settle within 40s; last={stable}"
                    )
                await asyncio.sleep(0.25)
        finally:
            if proc.returncode is None:
                proc.terminate()
                try:
                    await asyncio.wait_for(proc.wait(), timeout=30)
                except TimeoutError:
                    proc.kill()
                    await proc.wait()


# Each case: (id, rpcallowip args, rpcbind args, expected (addr, port) pairs).
# A None for non-loopback is filled in at collection time; cases needing a
# non-loopback interface are skipped when the host has none.
_NON_LOOPBACK = _first_non_loopback_ip()

_BIND_CASES: list[tuple[str, list[str], list[str], list[tuple[str, int]]]] = [
    # No -rpcallowip: default to IPv4 + IPv6 loopback, -rpcbind ignored.
    ("default_loopback", [], [], [("127.0.0.1", _RPC_PORT), ("::1", _RPC_PORT)]),
    # -rpcallowip with no -rpcbind: bind to any. The dual-stack IPv6 :: socket
    # also accepts IPv4, so the redundant 0.0.0.0 bind drops out: only :: remains.
    ("allowip_any", ["127.0.0.1"], [], [("::", _RPC_PORT)]),
    # Explicit IPv4 loopback only.
    ("ipv4_explicit", ["127.0.0.1"], ["127.0.0.1"], [("127.0.0.1", _RPC_PORT)]),
    # Explicit IPv4 loopback on an alternate port.
    (
        "ipv4_alt_port",
        ["127.0.0.1"],
        [f"127.0.0.1:{_ALT_PORT_A}"],
        [("127.0.0.1", _ALT_PORT_A)],
    ),
    # Two ports on the same host.
    (
        "ipv4_multi_port",
        ["127.0.0.1"],
        [f"127.0.0.1:{_ALT_PORT_A}", f"127.0.0.1:{_ALT_PORT_B}"],
        [("127.0.0.1", _ALT_PORT_A), ("127.0.0.1", _ALT_PORT_B)],
    ),
    # Explicit IPv6 loopback only.
    ("ipv6_explicit", ["[::1]"], ["[::1]"], [("::1", _RPC_PORT)]),
    # Both IPv4 and IPv6 loopback, explicit.
    (
        "ipv4_and_ipv6",
        ["127.0.0.1"],
        ["127.0.0.1", "[::1]"],
        [("127.0.0.1", _RPC_PORT), ("::1", _RPC_PORT)],
    ),
]

if _NON_LOOPBACK is not None:
    _BIND_CASES.append(
        (
            "non_loopback",
            [_NON_LOOPBACK],
            [_NON_LOOPBACK],
            [(_NON_LOOPBACK, _RPC_PORT)],
        )
    )


@pytest.mark.parametrize(
    ("allow_ips", "binds", "expected"),
    [(c[1], c[2], c[3]) for c in _BIND_CASES],
    ids=[c[0] for c in _BIND_CASES],
)
async def test_rpcbind(
    fluxd_binary: str,
    tmp_path: Path,
    allow_ips: list[str],
    binds: list[str],
    expected: list[tuple[str, int]],
) -> None:
    """The RPC server's listening sockets equal the expected (addr, port) set."""
    args = ["-disablewallet", "-nolisten"]
    args += [f"-rpcallowip={ip}" for ip in allow_ips]
    args += [f"-rpcbind={addr}" for addr in binds]
    bound = await _read_listen_addrs(fluxd_binary, tmp_path / "bind", args)
    assert bound == _expected(*expected)


async def _rpc_get(ip: str, port: int) -> int:
    """Issue an authenticated getinfo to ``ip:port`` and return the HTTP status.

    FluxRPC targets 127.0.0.1, so this small ad-hoc request reaches a
    non-loopback bind. fluxd answers an RPC from a non-allowed source IP with a
    403 (not a closed connection), so the deny case surfaces as a status code.
    """
    payload = '{"jsonrpc":"1.1","method":"getinfo","params":[],"id":1}'
    headers = {
        "Authorization": aiohttp.encode_basic_auth(_RPC_USER, _RPC_PASSWORD),
        "Content-Type": "application/json",
    }
    async with (
        aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15)) as session,
        session.post(f"http://{ip}:{port}", data=payload, headers=headers) as resp,
    ):
        await resp.read()
        return resp.status


@pytest.mark.skipif(
    _NON_LOOPBACK is None,
    reason="requires at least one non-loopback IPv4 interface",
)
async def test_rpcallowip_allows_non_loopback(node_factory: NodeFactory) -> None:
    """A node allowing the non-loopback IP answers an RPC arriving on it."""
    assert _NON_LOOPBACK is not None
    node = await node_factory(
        0,
        extra_args=["-disablewallet", "-nolisten", f"-rpcallowip={_NON_LOOPBACK}"],
    )
    assert await _rpc_get(_NON_LOOPBACK, node.rpc_port) == HTTP_OK


@pytest.mark.skipif(
    _NON_LOOPBACK is None,
    reason="requires at least one non-loopback IPv4 interface",
)
async def test_rpcallowip_denies_unlisted(node_factory: NodeFactory) -> None:
    """A node allowing only an unrelated IP rejects an RPC on the real one.

    The daemon binds to any when -rpcallowip is set, so the connection is
    accepted, but the connecting IP is not in the allow list (and is not
    loopback), so fluxd answers 403 Forbidden instead of serving the request.
    """
    assert _NON_LOOPBACK is not None
    node = await node_factory(
        0,
        extra_args=["-disablewallet", "-nolisten", "-rpcallowip=1.1.1.1"],
    )
    assert await _rpc_get(_NON_LOOPBACK, node.rpc_port) == HTTP_FORBIDDEN
    # Loopback is always allowed, so the node still serves RPC there.
    assert isinstance(await node.rpc.getblockcount(), int)
