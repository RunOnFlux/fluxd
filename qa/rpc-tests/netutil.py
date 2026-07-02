"""Linux network introspection helpers used by the rpcbind test.

Reads the kernel's per-process socket inodes from ``/proc/<pid>/fd`` and the
listening-socket table from ``/proc/net/tcp`` + ``/proc/net/tcp6`` to discover
exactly which (address, port) pairs a daemon process is bound to. The address
strings returned by ``get_bind_addrs`` are the kernel's lowercase hex form (the
same form ``addr_to_hex`` produces), so a test can compare a bound set against
an expected set without resolving names.

Linux-only: every function here parses ``/proc`` and uses ``SIOCGIFCONF``.
"""

import array
import binascii
import fcntl
import os
import socket
import struct
import sys
from typing import NamedTuple

# TCP connection states as reported in the kernel's hex ``st`` column; only the
# listening state matters for discovering bind addresses.
STATE_ESTABLISHED = "01"
STATE_SYN_SENT = "02"
STATE_SYN_RECV = "03"
STATE_FIN_WAIT1 = "04"
STATE_FIN_WAIT2 = "05"
STATE_TIME_WAIT = "06"
STATE_CLOSE = "07"
STATE_CLOSE_WAIT = "08"
STATE_LAST_ACK = "09"
STATE_LISTEN = "0A"
STATE_CLOSING = "0B"

# SIOCGIFCONF ioctl request, and the size of a single ``struct ifreq`` entry it
# returns (differs between 32- and 64-bit kernels).
_SIOCGIFCONF = 0x8912
_IS_64BITS = sys.maxsize > 2**32
_IFREQ_SIZE = 40 if _IS_64BITS else 32


def get_socket_inodes(pid: int) -> list[int]:
    """Return the inode numbers of every socket fd held by process ``pid``."""
    base = f"/proc/{pid}/fd"
    inodes: list[int] = []
    for item in os.listdir(base):
        target = os.readlink(os.path.join(base, item))
        if target.startswith("socket:"):
            # target looks like ``socket:[12345]``.
            inodes.append(int(target[8:-1]))
    return inodes


def _remove_empty(fields: list[str]) -> list[str]:
    return [x for x in fields if x != ""]


def _convert_ip_port(field: str) -> tuple[str, int]:
    """Decode a ``/proc/net`` ``hexaddr:hexport`` field to (hex_addr, port).

    The kernel stores the address in host byte order per 4-byte word, so each
    32-bit word is byte-swapped back to a canonical big-endian hex string -- the
    same representation ``addr_to_hex`` returns.
    """
    host, port = field.split(":")
    raw = binascii.unhexlify(host)
    host_out = ""
    for word in range(len(raw) // 4):
        (val,) = struct.unpack("=I", raw[word * 4 : (word + 1) * 4])
        host_out += f"{val:08x}"
    return host_out, int(port, 16)


class Connection(NamedTuple):
    """One row of a ``/proc/net/tcp{,6}`` connection table."""

    tcp_id: str
    local: tuple[str, int]  # (hex_addr, port)
    remote: tuple[str, int]
    state: str
    inode: int


def netstat(typ: str = "tcp") -> list[Connection]:
    """Return one Connection per row in ``/proc/net/<typ>``."""
    with open(f"/proc/net/{typ}") as f:
        content = f.readlines()
        content.pop(0)  # drop the column header line
    result: list[Connection] = []
    for line in content:
        fields = _remove_empty(line.split(" "))
        result.append(
            Connection(
                tcp_id=fields[0],
                local=_convert_ip_port(fields[1]),
                remote=_convert_ip_port(fields[2]),
                state=fields[3],
                inode=int(fields[9]),  # matches a socket inode from get_socket_inodes
            )
        )
    return result


def get_bind_addrs(pid: int) -> list[tuple[str, int]]:
    """Return the listening (hex_addr, port) pairs owned by process ``pid``."""
    inodes = get_socket_inodes(pid)
    bind_addrs: list[tuple[str, int]] = []
    for conn in netstat("tcp") + netstat("tcp6"):
        if conn.state == STATE_LISTEN and conn.inode in inodes:
            bind_addrs.append(conn.local)
    return bind_addrs


def all_interfaces() -> list[tuple[str, str]]:
    """Return (interface_name, IPv4_address) for every interface that is up."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    max_possible = 8  # number of ifreq entries to ask for; doubled until it fits
    while True:
        num_bytes = max_possible * _IFREQ_SIZE
        names = array.array("B", b"\0" * num_bytes)
        outbytes = struct.unpack(
            "iL",
            fcntl.ioctl(
                s.fileno(),
                _SIOCGIFCONF,
                struct.pack("iL", num_bytes, names.buffer_info()[0]),
            ),
        )[0]
        if outbytes == num_bytes:
            max_possible *= 2
        else:
            break
    namestr = names.tobytes()
    return [
        (
            namestr[i : i + 16].split(b"\0", 1)[0].decode(),
            socket.inet_ntoa(namestr[i + 20 : i + 24]),
        )
        for i in range(0, outbytes, _IFREQ_SIZE)
    ]


def addr_to_hex(addr: str) -> str:
    """Convert a string IPv4/IPv6 address to the hex form ``get_bind_addrs`` returns.

    Naive: handles the IPv6 forms this test uses (full, and a single ``::``),
    not every RFC 4291 abbreviation.
    """
    parts: list[int]
    if "." in addr:  # IPv4
        parts = [int(x) for x in addr.split(".")]
    elif ":" in addr:  # IPv6
        sub: list[list[int]] = [[], []]  # bytes before / after a ``::``
        x = 0
        comps = addr.split(":")
        for i, comp in enumerate(comps):
            if comp == "":
                if i == 0 or i == (len(comps) - 1):
                    continue  # leading/trailing empty component from ``::``
                x += 1  # ``::`` switches accumulation to the suffix
                assert x < 2
            else:  # two bytes per component
                val = int(comp, 16)
                sub[x].append(val >> 8)
                sub[x].append(val & 0xFF)
        nullbytes = 16 - len(sub[0]) - len(sub[1])
        assert (x == 0 and nullbytes == 0) or (x == 1 and nullbytes > 0)
        parts = sub[0] + ([0] * nullbytes) + sub[1]
    else:
        raise ValueError(f"Could not parse address {addr}")
    return binascii.hexlify(bytearray(parts)).decode()
