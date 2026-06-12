#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Header-serving storm: walk the entire header chain over P2P, hard.

N concurrent connections each sweep the full chain from genesis in
2000-header getheaders strides, parsing and validating every header on the
wire. This drives the pruned-entry header-serving path (disk header-prefix
reads) at sustained rate. Validation asserts the fields that the pre-fix
code served as zeroes for pruned entries:

  - PoW headers (version < 100): non-zero nNonce, non-empty nSolution,
    non-zero hashMerkleRoot
  - PON headers (version >= 100): non-zero hashMerkleRoot, non-empty
    vchBlockSig
  - PON-VRF headers (version >= 101): additionally a non-zero nodesVrfOutput

A ping round-trip is interleaved between strides as a responsiveness probe;
the max observed ping RTT is reported (a serving-side cs_main stall shows up
here).

Usage:
  python3 header_storm.py --host <node> [--port 16125] [--workers 4]
                          [--max-batches N] [--rtt-budget 5.0]

stdlib only; no external deps.
"""

import argparse
import hashlib
import io
import random
import socket
import struct
import sys
import threading
import time

MAINNET_MAGIC = bytes([0x24, 0xE9, 0x27, 0x64])
GENESIS_HASH_HEX = "00052461a5006c2e3b74ce48992a08695607912d5604c3eb8da25749b0900444"
PROTOCOL_VERSION = 170022
PON_VERSION = 100
PON_VRF_VERSION = 101
HEADERS_PER_REQUEST = 2000


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def ser_varint(n):
    if n < 0xFD:
        return struct.pack("<B", n)
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def read_varint(f):
    b = f.read(1)
    if not b:
        raise EOFError("varint")
    n = b[0]
    if n < 0xFD:
        return n
    if n == 0xFD:
        return struct.unpack("<H", f.read(2))[0]
    if n == 0xFE:
        return struct.unpack("<I", f.read(4))[0]
    return struct.unpack("<Q", f.read(8))[0]


class Peer:
    def __init__(self, host, port, timeout=120):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""

    def send_msg(self, command, payload):
        msg = MAINNET_MAGIC
        msg += command.encode() + b"\x00" * (12 - len(command))
        msg += struct.pack("<I", len(payload))
        msg += sha256d(payload)[:4]
        msg += payload
        self.sock.sendall(msg)

    def recv_msg(self):
        # header: magic(4) command(12) length(4) checksum(4)
        while len(self.buf) < 24:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("connection closed")
            self.buf += chunk
        if self.buf[:4] != MAINNET_MAGIC:
            raise ValueError(f"bad magic {self.buf[:4].hex()}")
        command = self.buf[4:16].rstrip(b"\x00").decode()
        length = struct.unpack("<I", self.buf[16:20])[0]
        while len(self.buf) < 24 + length:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError("connection closed mid-message")
            self.buf += chunk
        payload = self.buf[24 : 24 + length]
        self.buf = self.buf[24 + length :]
        return command, payload

    def handshake(self):
        now = int(time.time())
        addr = struct.pack("<Q", 0) + b"\x00" * 16 + struct.pack(">H", 0)
        payload = struct.pack("<iQq", PROTOCOL_VERSION, 0, now)
        payload += addr + addr
        payload += struct.pack("<Q", random.getrandbits(64))
        ua = b"/header-storm:0.1/"
        payload += ser_varint(len(ua)) + ua
        payload += struct.pack("<i", 0)
        payload += b"\x01"
        self.send_msg("version", payload)
        got_verack = got_version = False
        while not (got_verack and got_version):
            cmd, pl = self.recv_msg()
            if cmd == "version":
                got_version = True
                self.send_msg("verack", b"")
            elif cmd == "verack":
                got_verack = True
            elif cmd == "ping":
                self.send_msg("pong", pl)

    def ping_rtt(self):
        nonce = struct.pack("<Q", random.getrandbits(64))
        t0 = time.monotonic()
        self.send_msg("ping", nonce)
        while True:
            cmd, pl = self.recv_msg()
            if cmd == "pong" and pl == nonce:
                return time.monotonic() - t0
            if cmd == "ping":
                self.send_msg("pong", pl)

    def get_headers(self, locator_hash_le):
        payload = struct.pack("<I", PROTOCOL_VERSION)
        payload += ser_varint(1) + locator_hash_le
        payload += b"\x00" * 32
        self.send_msg("getheaders", payload)
        while True:
            cmd, pl = self.recv_msg()
            if cmd == "headers":
                return pl
            if cmd == "ping":
                self.send_msg("pong", pl)
            # ignore inv/addr/etc.


def parse_and_validate_headers(payload):
    """Returns (count, last_hash_le, max_version). Raises on a zeroed field."""
    f = io.BytesIO(payload)
    count = read_varint(f)
    last_hash = None
    max_version = 0
    for _ in range(count):
        start = f.tell()
        version = struct.unpack("<i", f.read(4))[0]
        max_version = max(max_version, version)
        f.read(32)  # hashPrevBlock
        merkle = f.read(32)
        f.read(32)  # hashFinalSaplingRoot
        f.read(4 + 4)  # nTime, nBits
        if version >= PON_VERSION:
            f.read(32 + 4)  # nodesCollateral (hash+n)
            if version >= PON_VRF_VERSION:
                vrf_out = f.read(32)
                if vrf_out == b"\x00" * 32:
                    raise AssertionError(f"zeroed nodesVrfOutput at v{version}")
                proof_len = read_varint(f)
                f.read(proof_len)
            sig_len = read_varint(f)
            if sig_len == 0:
                raise AssertionError("empty vchBlockSig on PON header")
            f.read(sig_len)
        else:
            nonce = f.read(32)
            sol_len = read_varint(f)
            solution = f.read(sol_len)
            if nonce == b"\x00" * 32:
                raise AssertionError("zeroed nNonce on PoW header")
            if sol_len == 0 or solution == b"\x00" * sol_len:
                raise AssertionError("missing/zeroed nSolution on PoW header")
        if merkle == b"\x00" * 32:
            raise AssertionError(f"zeroed hashMerkleRoot (v{version})")
        read_varint(f)  # txn count (always 0 in headers msg)
        end = f.tell()
        # block hash = sha256d of the GETHASH serialization; for PoW headers
        # that's the full header incl. solution, for PON it excludes
        # proof/sig. Recompute only for PoW (cheap enough, exact).
        if version < PON_VERSION:
            f.seek(start)
            last_hash = sha256d(f.read(end - start - 1))  # minus txn varint
            f.seek(end)
        else:
            f.seek(start)
            f.read(end - start - 1)
            f.seek(end)
            # PON GETHASH serialization: strip proof+sig (and re-add nothing);
            # easier: ask for the next stride using the PREV hash of the next
            # header — handled by caller via returned payload; fall back to
            # tracking via hashPrevBlock below.
            last_hash = None
    return count, last_hash, max_version


def extract_last_prev_chain(payload):
    """Cheap path to continue the walk: the locator for the next request can
    be the LAST header's hash; for PON headers we don't recompute it, we use
    the fact that header N+1's hashPrevBlock == hash(header N). So request
    strides overlap by one: locator = hashPrevBlock of the LAST header, which
    re-fetches that one header but needs no hashing."""
    f = io.BytesIO(payload)
    count = read_varint(f)
    prev = None
    for _ in range(count):
        version = struct.unpack("<i", f.read(4))[0]
        prev = f.read(32)
        f.read(32 + 32 + 4 + 4)
        if version >= PON_VERSION:
            f.read(32 + 4)
            if version >= PON_VRF_VERSION:
                f.read(32)
                f.read(read_varint(f))
            f.read(read_varint(f))
        else:
            f.read(32)
            f.read(read_varint(f))
        read_varint(f)
    return count, prev


def worker(wid, args, stats, stop_evt):
    peer = Peer(args.host, args.port)
    peer.handshake()
    locator = bytes.fromhex(GENESIS_HASH_HEX)[::-1]  # internal byte order
    batches = 0
    while not stop_evt.is_set():
        payload = peer.get_headers(locator)
        count, last_hash, _ = parse_and_validate_headers(payload)
        if count == 0:
            break
        if last_hash is not None:
            locator = last_hash
        else:
            # PON stride: continue from the last header's prev (one-header
            # overlap, no PON hashing client-side)
            _, prev = extract_last_prev_chain(payload)
            if prev == locator:
                break  # no forward progress => at tip
            locator = prev
        batches += 1
        rtt = peer.ping_rtt()
        with stats["lock"]:
            stats["headers"] += count
            stats["batches"] += 1
            stats["max_rtt"] = max(stats["max_rtt"], rtt)
        if rtt > args.rtt_budget:
            raise AssertionError(f"ping RTT {rtt:.2f}s exceeded budget {args.rtt_budget:.2f}s (serving stall?)")
        if args.max_batches and batches >= args.max_batches:
            break
    with stats["lock"]:
        stats["done"] += 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=16125)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--max-batches", type=int, default=0, help="0 = walk to tip")
    ap.add_argument("--rtt-budget", type=float, default=5.0)
    args = ap.parse_args()

    stats = {"headers": 0, "batches": 0, "max_rtt": 0.0, "done": 0, "lock": threading.Lock()}
    stop_evt = threading.Event()
    threads = []
    errors = []

    def run(wid):
        try:
            worker(wid, args, stats, stop_evt)
        except Exception as e:
            errors.append(f"worker {wid}: {e!r}")
            stop_evt.set()

    t0 = time.monotonic()
    for i in range(args.workers):
        t = threading.Thread(target=run, args=(i,), daemon=True)
        t.start()
        threads.append(t)
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(10)
            with stats["lock"]:
                el = time.monotonic() - t0
                rate = stats["headers"] / el if el else 0
                print(
                    f"[{el:6.0f}s] headers={stats['headers']} batches={stats['batches']} "
                    f"rate={rate:.0f} hdr/s max_ping={stats['max_rtt']:.3f}s",
                    flush=True,
                )
    except KeyboardInterrupt:
        stop_evt.set()
    for t in threads:
        t.join(timeout=30)
    if errors:
        print("FAILED:\n" + "\n".join(errors))
        sys.exit(1)
    print(
        f"OK: {stats['headers']} headers validated across {stats['batches']} batches, "
        f"max ping RTT {stats['max_rtt']:.3f}s"
    )


if __name__ == "__main__":
    main()
