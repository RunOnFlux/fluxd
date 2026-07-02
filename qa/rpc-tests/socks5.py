"""A threaded mock SOCKS5 proxy server used to observe a node's proxy traffic.

The server speaks just enough of RFC 1928 (and the RFC 1929 username/password
auth sub-negotiation) to accept a CONNECT request, record what address/port the
client asked to reach and any credentials it offered, then hand back a canned
success reply before closing. Each accepted request is reported as a
``Socks5Command`` on a thread-safe queue the test drains; any handler exception
is placed on the same queue so a malformed exchange surfaces as a test failure
rather than a silent hang.
"""

import queue
import socket
import threading
import traceback


class Command:
    """SOCKS5 request commands (RFC 1928 section 4)."""

    CONNECT = 0x01


class AddressType:
    """SOCKS5 address types (RFC 1928 section 4)."""

    IPV4 = 0x01
    DOMAINNAME = 0x03
    IPV6 = 0x04


def recvall(s: socket.socket, n: int) -> bytearray:
    """Receive exactly ``n`` bytes from a socket, or raise on short read."""
    rv = bytearray()
    while n > 0:
        d = s.recv(n)
        if not d:
            raise OSError("Unexpected end of stream")
        rv.extend(d)
        n -= len(d)
    return rv


class Socks5Configuration:
    """Bind/auth configuration for a single mock proxy."""

    def __init__(self) -> None:
        self.addr: tuple[str, int] | None = None  # Bind address (must be set)
        self.af: int = socket.AF_INET  # Bind address family
        self.unauth: bool = False  # Support unauthenticated
        self.auth: bool = False  # Support username/password authentication


class Socks5Command:
    """A single CONNECT request observed by the proxy."""

    def __init__(
        self,
        cmd: int,
        atyp: int,
        addr: bytes | str,
        port: int,
        username: str | None,
        password: str | None,
    ) -> None:
        self.cmd = cmd  # Command (one of Command.*)
        self.atyp = atyp  # Address type (one of AddressType.*)
        self.addr = addr  # Requested address
        self.port = port  # Requested port
        self.username = username
        self.password = password

    def __repr__(self) -> str:
        return (
            f"Socks5Command({self.cmd},{self.atyp},{self.addr!r},"
            f"{self.port},{self.username!r},{self.password!r})"
        )


class Socks5Connection:
    """Handles one client connection's SOCKS5 handshake on its own thread."""

    def __init__(self, serv: "Socks5Server", conn: socket.socket, peer: object) -> None:
        self.serv = serv
        self.conn = conn
        self.peer = peer

    def handle(self) -> None:
        """Handle a SOCKS5 request according to RFC 1928."""
        try:
            # Verify socks version.
            ver = recvall(self.conn, 1)[0]
            if ver != 0x05:
                raise OSError(f"Invalid socks version {ver}")
            # Choose an authentication method from those the client offers.
            nmethods = recvall(self.conn, 1)[0]
            methods = bytearray(recvall(self.conn, nmethods))
            method: int | None = None
            if 0x02 in methods and self.serv.conf.auth:
                method = 0x02  # username/password
            elif 0x00 in methods and self.serv.conf.unauth:
                method = 0x00  # unauthenticated
            if method is None:
                raise OSError("No supported authentication method was offered")
            # Send the chosen method back to the client.
            self.conn.sendall(bytearray([0x05, method]))
            # Read the username/password sub-negotiation when authenticating.
            username: str | None = None
            password: str | None = None
            if method == 0x02:
                ver = recvall(self.conn, 1)[0]
                if ver != 0x01:
                    raise OSError(f"Invalid auth packet version {ver}")
                ulen = recvall(self.conn, 1)[0]
                username = str(recvall(self.conn, ulen), "utf-8")
                plen = recvall(self.conn, 1)[0]
                password = str(recvall(self.conn, plen), "utf-8")
                # Acknowledge successful authentication.
                self.conn.sendall(bytearray([0x01, 0x00]))

            # Read the connect request.
            ver, cmd, _rsv, atyp = recvall(self.conn, 4)
            if ver != 0x05:
                raise OSError(f"Invalid socks version {ver} in connect request")
            if cmd != Command.CONNECT:
                raise OSError(f"Unhandled command {cmd} in connect request")

            addr: bytes | str
            if atyp == AddressType.IPV4:
                addr = bytes(recvall(self.conn, 4))
            elif atyp == AddressType.DOMAINNAME:
                n = recvall(self.conn, 1)[0]
                addr = str(recvall(self.conn, n), "utf-8")
            elif atyp == AddressType.IPV6:
                addr = bytes(recvall(self.conn, 16))
            else:
                raise OSError(f"Unknown address type {atyp}")
            port_hi, port_lo = recvall(self.conn, 2)
            port = (port_hi << 8) | port_lo

            # Send a dummy success reply (BND.ADDR 0.0.0.0:0).
            self.conn.sendall(
                bytearray([0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            )

            cmdin = Socks5Command(cmd, atyp, addr, port, username, password)
            self.serv.queue.put(cmdin)
            # Fall through to disconnect.
        except Exception as e:  # noqa: BLE001 - report any failure to the test queue
            traceback.print_exc()
            self.serv.queue.put(e)
        finally:
            self.conn.close()


class Socks5Server:
    """A mock SOCKS5 proxy listening on its own background thread."""

    def __init__(self, conf: Socks5Configuration) -> None:
        if conf.addr is None:
            raise ValueError("Socks5Configuration.addr must be set")
        self.conf = conf
        self.s = socket.socket(conf.af)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(conf.addr)
        self.s.listen(5)
        self.running = False
        self.thread: threading.Thread | None = None
        # Reports observed connections and handler exceptions back to the client.
        self.queue: queue.Queue[Socks5Command | Exception] = queue.Queue()

    def run(self) -> None:
        while self.running:
            (sockconn, peer) = self.s.accept()
            if self.running:
                conn = Socks5Connection(self, sockconn, peer)
                thread = threading.Thread(None, conn.handle)
                thread.daemon = True
                thread.start()

    def start(self) -> None:
        assert not self.running
        self.running = True
        self.thread = threading.Thread(None, self.run)
        self.thread.daemon = True
        self.thread.start()

    def stop(self) -> None:
        self.running = False
        # Connect to ourselves to break out of the blocking accept().
        assert self.conf.addr is not None
        s = socket.socket(self.conf.af)
        s.connect(self.conf.addr)
        s.close()
        if self.thread is not None:
            self.thread.join()
