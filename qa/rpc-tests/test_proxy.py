"""The ``-proxy``/``-onion``/``-proxyrandomize`` SOCKS5 outbound paths.

Flux's Tor support relies on routing outbound connections through a SOCKS5
proxy. This drives the same proxy combinations the daemon offers -- proxy
everything, proxy onions separately, randomize per-connection credentials, and
a proxy bound on IPv6 -- against three mock SOCKS5 servers (one
unauthenticated; one Tor-style supporting both auth and unauth; one on
``::1``).

For each combination the test issues ``addnode <host> onetry`` for an IPv4,
IPv6, .onion and plain-DNS target and reads back the resulting CONNECT request
the daemon made to the proxy. Two behaviours are asserted: the daemon always
presents the target as a DOMAINNAME (it never resolves the name itself, even
for literal IPv4/IPv6), and ``-proxyrandomize`` produces a unique
username/password per connection (Tor stream isolation). Finally
``getnetworkinfo`` is checked to report each per-network proxy, its randomize
flag, and onion reachability matching the daemon's configuration.

No wallet funding or mining is needed: the connection attempts go through the
mock proxy, which records and then drops them.
"""

import asyncio
import socket
from collections.abc import Iterator

import pytest
from conftest import NodeFactory, claim_free_port
from fluxtest.node import FluxNode
from socks5 import AddressType, Socks5Command, Socks5Configuration, Socks5Server

# Distinct free ports from the shared allocator, so the mock proxies never
# collide with a node's ports or with each other.
UNAUTH_PORT = claim_free_port()
AUTH_PORT = claim_free_port()
IPV6_PORT = claim_free_port()

# A short bound on the blocking queue read so a proxy that never receives the
# expected CONNECT fails the test instead of hanging the suite.
QUEUE_TIMEOUT = 30.0

# The framework config sets connect=0 to keep nodes from redialing addrman
# peers on their own; the daemon treats that "0" as a hostname to dial and,
# with a proxy configured, keeps asking the proxy for it. Those CONNECTs are
# harness noise, not addnode traffic, and the queue reader skips them.
CONNECT_SENTINEL = "0"

# Targets the daemon is asked to reach; the proxy reports back what it saw.
IPV4_TARGET = "15.61.23.23"
IPV4_PORT = 1234
IPV6_TARGET = "1233:3432:2434:2343:3234:2345:6546:4534"
IPV6_TARGET_PORT = 5443
# A v2 (OnionCat, 16-char) onion address -- the only form master's
# CNetAddr::SetSpecial accepts (it requires a 10-byte decode). Swap to a 56-char
# v3 address once BIP155/torv3 lands on master, where v2 is dropped.
ONION_TARGET = "bitcoinostk4e4re.onion"
ONION_TARGET_PORT = 8333
DNS_TARGET = "node.noumenon"
DNS_TARGET_PORT = 8333


def _ipv6_available() -> bool:
    """Whether ``::1`` can be bound, so the IPv6 proxy/node can run."""
    try:
        s = socket.socket(socket.AF_INET6)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


HAS_IPV6 = _ipv6_available()


async def _next_command(server: Socks5Server) -> Socks5Command:
    """Drain the next observed CONNECT, failing on timeout or a handler error.

    The proxy's queue read is blocking, so it runs in a worker thread to keep
    the event loop free; a handler that hit an error puts the exception on the
    queue, which is re-raised here. CONNECTs for the connect=0 sentinel are
    skipped.
    """
    while True:
        item = await asyncio.wait_for(asyncio.to_thread(server.queue.get), QUEUE_TIMEOUT)
        if isinstance(item, Exception):
            raise item
        if item.addr in (CONNECT_SENTINEL, CONNECT_SENTINEL.encode()):
            continue
        return item


async def _expect_connect(
    node: FluxNode,
    server: Socks5Server,
    target: str,
    addr: str,
    port: int,
    *,
    auth: bool,
) -> Socks5Command:
    """addnode a target and assert the CONNECT the daemon sent to the proxy.

    The daemon's SOCKS5 client always sends atyp DOMAINNAME, even for a literal
    IPv4/IPv6 target, so ``addr`` is the unbracketed host string. With no auth
    the proxy must observe no credentials.
    """
    await node.rpc.addnode(target, "onetry")
    cmd = await _next_command(server)
    assert isinstance(cmd, Socks5Command)
    assert cmd.atyp == AddressType.DOMAINNAME
    assert cmd.addr == addr
    assert cmd.port == port
    if not auth:
        assert cmd.username is None
        assert cmd.password is None
    return cmd


async def _node_test(
    node: FluxNode,
    proxies: list[Socks5Server],
    *,
    auth: bool,
    test_onion: bool = True,
) -> list[Socks5Command]:
    """Drive the four target kinds through ``node`` and collect the CONNECTs.

    ``proxies`` names which mock server each target kind is expected to reach,
    matching the node's proxy configuration.
    """
    rv: list[Socks5Command] = []
    rv.append(
        await _expect_connect(
            node, proxies[0], f"{IPV4_TARGET}:{IPV4_PORT}", IPV4_TARGET, IPV4_PORT, auth=auth
        )
    )
    rv.append(
        await _expect_connect(
            node,
            proxies[1],
            f"[{IPV6_TARGET}]:{IPV6_TARGET_PORT}",
            IPV6_TARGET,
            IPV6_TARGET_PORT,
            auth=auth,
        )
    )
    if test_onion:
        rv.append(
            await _expect_connect(
                node,
                proxies[2],
                f"{ONION_TARGET}:{ONION_TARGET_PORT}",
                ONION_TARGET,
                ONION_TARGET_PORT,
                auth=auth,
            )
        )
    rv.append(
        await _expect_connect(
            node,
            proxies[3],
            f"{DNS_TARGET}:{DNS_TARGET_PORT}",
            DNS_TARGET,
            DNS_TARGET_PORT,
            auth=auth,
        )
    )
    return rv


def _networks(info: dict) -> dict[str, dict]:
    return {entry["name"]: entry for entry in info["networks"]}


@pytest.fixture(scope="module")
def proxies() -> Iterator[list[Socks5Server]]:
    """The three mock SOCKS5 servers, started before any node, stopped after.

    Created once for the module (matching the legacy test's __init__ ordering)
    so the listening sockets are not torn down and rebound on the same ports
    between the per-node tests. Each test reads only the CONNECTs its own
    addnode calls produce. The IPv6 server is omitted when ``::1`` cannot be
    bound; tests needing it skip.
    """
    # Unauthenticated proxy (a non-Tor SOCKS5).
    conf1 = Socks5Configuration()
    conf1.addr = ("127.0.0.1", UNAUTH_PORT)
    conf1.unauth = True
    conf1.auth = False

    # Tor-style proxy supporting both authenticated and unauthenticated.
    conf2 = Socks5Configuration()
    conf2.addr = ("127.0.0.1", AUTH_PORT)
    conf2.unauth = True
    conf2.auth = True

    servers = [Socks5Server(conf1), Socks5Server(conf2)]

    if HAS_IPV6:
        conf3 = Socks5Configuration()
        conf3.af = socket.AF_INET6
        conf3.addr = ("::1", IPV6_PORT)
        conf3.unauth = True
        conf3.auth = True
        servers.append(Socks5Server(conf3))

    for server in servers:
        server.start()
    try:
        yield servers
    finally:
        for server in servers:
            server.stop()


async def test_proxy_everything(node_factory: NodeFactory, proxies: list[Socks5Server]) -> None:
    """``-proxy`` with ``-proxyrandomize`` routes every network through one proxy."""
    serv1 = proxies[0]
    assert serv1.conf.addr is not None
    host, port = serv1.conf.addr
    node = await node_factory(
        0,
        extra_args=[
            "-listen",
            "-debug=net",
            "-debug=proxy",
            f"-proxy={host}:{port}",
            "-proxyrandomize=1",
        ],
    )
    # Localhost is NET_UNROUTABLE so the proxy is not used for local peers; an
    # unauthenticated proxy reports no credentials.
    await _node_test(node, [serv1, serv1, serv1, serv1], auth=False)

    nets = _networks(await node.rpc.getnetworkinfo())
    for net in ("ipv4", "ipv6", "onion"):
        assert nets[net]["proxy"] == f"{host}:{port}"
        assert nets[net]["proxy_randomize_credentials"] is True
    assert nets["onion"]["reachable"] is True


async def test_proxy_plus_onion(node_factory: NodeFactory, proxies: list[Socks5Server]) -> None:
    """``-proxy`` plus a separate ``-onion`` proxy splits onion traffic off."""
    serv1, serv2 = proxies[0], proxies[1]
    assert serv1.conf.addr is not None
    assert serv2.conf.addr is not None
    h1, p1 = serv1.conf.addr
    h2, p2 = serv2.conf.addr
    node = await node_factory(
        1,
        extra_args=[
            "-listen",
            "-debug=net",
            "-debug=proxy",
            f"-proxy={h1}:{p1}",
            f"-onion={h2}:{p2}",
            "-proxyrandomize=0",
        ],
    )
    # IPv4/IPv6/DNS go to the main proxy, onion to the onion proxy.
    await _node_test(node, [serv1, serv1, serv2, serv1], auth=False)

    nets = _networks(await node.rpc.getnetworkinfo())
    for net in ("ipv4", "ipv6"):
        assert nets[net]["proxy"] == f"{h1}:{p1}"
        assert nets[net]["proxy_randomize_credentials"] is False
    assert nets["onion"]["proxy"] == f"{h2}:{p2}"
    assert nets["onion"]["proxy_randomize_credentials"] is False
    assert nets["onion"]["reachable"] is True


async def test_proxy_randomize_credentials(
    node_factory: NodeFactory, proxies: list[Socks5Server]
) -> None:
    """``-proxy`` to a Tor-style proxy with ``-proxyrandomize`` isolates streams."""
    serv2 = proxies[1]
    assert serv2.conf.addr is not None
    host, port = serv2.conf.addr
    node = await node_factory(
        2,
        extra_args=[
            "-listen",
            "-debug=net",
            "-debug=proxy",
            f"-proxy={host}:{port}",
            "-proxyrandomize=1",
        ],
    )
    # The Tor-style proxy authenticates, so every CONNECT carries credentials.
    rv = await _node_test(node, [serv2, serv2, serv2, serv2], auth=True)
    # Stream isolation: each of the four connections used unique credentials.
    credentials = {(cmd.username, cmd.password) for cmd in rv}
    assert len(credentials) == 4

    nets = _networks(await node.rpc.getnetworkinfo())
    for net in ("ipv4", "ipv6", "onion"):
        assert nets[net]["proxy"] == f"{host}:{port}"
        assert nets[net]["proxy_randomize_credentials"] is True
    assert nets["onion"]["reachable"] is True


@pytest.mark.skipif(not HAS_IPV6, reason="::1 is not available")
async def test_proxy_on_ipv6(node_factory: NodeFactory, proxies: list[Socks5Server]) -> None:
    """``-proxy`` bound on IPv6 with ``-noonion`` makes onion unreachable."""
    serv3 = proxies[2]
    assert serv3.conf.addr is not None
    host, port = serv3.conf.addr[0], serv3.conf.addr[1]
    node = await node_factory(
        3,
        extra_args=[
            "-listen",
            "-debug=net",
            "-debug=proxy",
            f"-proxy=[{host}]:{port}",
            "-proxyrandomize=0",
            "-noonion",
        ],
    )
    # -noonion disables onion entirely, so only IPv4/IPv6/DNS are exercised.
    await _node_test(node, [serv3, serv3, serv3, serv3], auth=False, test_onion=False)

    nets = _networks(await node.rpc.getnetworkinfo())
    for net in ("ipv4", "ipv6"):
        assert nets[net]["proxy"] == f"[{host}]:{port}"
        assert nets[net]["proxy_randomize_credentials"] is False
    assert nets["onion"]["reachable"] is False
