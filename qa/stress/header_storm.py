#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Header-serving storm: walk the entire header chain over P2P, hard.

N concurrent connections each sweep the full chain from genesis in
2000-header getheaders strides, parsing and validating every header on the
wire. This drives the pruned-entry header-serving path (disk header-prefix
reads) at sustained rate.

The server picks the reply format by peer protocol version, and the script
exercises both:

  - default (legacy mode): advertise a pre-CMPHEADERS protocol version, so
    every stride is a full `headers` message — PoW headers ship their entire
    equihash solution (the heaviest serving path)
  - --compact: advertise the current protocol version, so checkpointed
    history arrives as `cmpheaders` (solution omitted, explicit block hash)
    and the post-checkpoint tail as regular `headers`

Validation asserts the fields the pre-fix code served as zeroes for pruned
entries: non-zero merkle root everywhere; PoW: non-zero nonce (+ non-empty
solution in legacy mode); PON: non-empty block signature. Chain continuity
is asserted via each header's hashPrevBlock.

A ping round-trip is interleaved between strides as a responsiveness probe;
a serving-side cs_main stall shows up as ping RTT.

Usage:
  python3 header_storm.py --host <node> [--port 16125] [--workers 4]
                          [--compact] [--max-batches N] [--rtt-budget 5.0]

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
CURRENT_PROTOCOL_VERSION = 170021  # >= CMPHEADERS_VERSION: server sends cmpheaders
LEGACY_PROTOCOL_VERSION = 170020  # < CMPHEADERS_VERSION: server sends full headers
PON_VERSION = 100


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
    def __init__(self, host, port, protocol_version, timeout=120):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        self.protocol_version = protocol_version

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
        payload = struct.pack("<iQq", self.protocol_version, 0, now)
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
        payload = struct.pack("<I", self.protocol_version)
        payload += ser_varint(1) + locator_hash_le
        payload += b"\x00" * 32
        self.send_msg("getheaders", payload)
        while True:
            cmd, pl = self.recv_msg()
            if cmd in ("headers", "cmpheaders"):
                return cmd, pl
            if cmd == "ping":
                self.send_msg("pong", pl)
            # ignore inv/addr/sendheaders/sendcmpct/etc.


def _read_common(f):
    """version, hashPrev, merkle through nBits — shared by both formats."""
    version = struct.unpack("<i", f.read(4))[0]
    prev = f.read(32)
    merkle = f.read(32)
    sapling = f.read(32)
    time_bits = f.read(8)
    return version, prev, merkle, sapling, time_bits


def _pon_gethash(version, prev, merkle, sapling, time_bits, collateral):
    """PON block hash = sha256d over the GETHASH serialization (sig excluded)."""
    data = struct.pack("<i", version) + prev + merkle + sapling + time_bits + collateral
    return sha256d(data)


def _validate_common(version, merkle, prev, expect_prev):
    if merkle == b"\x00" * 32:
        raise AssertionError(f"zeroed hashMerkleRoot (v{version})")
    if expect_prev is not None and prev != expect_prev:
        raise AssertionError("non-continuous header chain")


def parse_headers_msg(payload, expect_prev):
    """Full `headers` message: CBlock-serialized headers + txn-count varint.
    Returns (count, last_hash)."""
    f = io.BytesIO(payload)
    count = read_varint(f)
    last_hash = expect_prev
    for _ in range(count):
        start = f.tell()
        version, prev, merkle, sapling, time_bits = _read_common(f)
        _validate_common(version, merkle, prev, last_hash)
        if version >= PON_VERSION:
            collateral = f.read(36)
            sig_len = read_varint(f)
            if sig_len == 0:
                raise AssertionError("empty vchBlockSig on PON header")
            f.read(sig_len)
            read_varint(f)  # txn count (0)
            last_hash = _pon_gethash(version, prev, merkle, sapling, time_bits, collateral)
        else:
            nonce = f.read(32)
            sol_len = read_varint(f)
            solution = f.read(sol_len)
            if nonce == b"\x00" * 32:
                raise AssertionError("zeroed nNonce on PoW header")
            if sol_len == 0 or solution == b"\x00" * sol_len:
                raise AssertionError("missing/zeroed nSolution on PoW header")
            end = f.tell()
            f.seek(start)
            raw = f.read(end - start)  # GETHASH form == wire form for PoW
            read_varint(f)  # txn count (0)
            last_hash = sha256d(raw)
    return count, last_hash


def parse_cmpheaders_msg(payload, expect_prev):
    """`cmpheaders`: vector<CCompactBlockHeader> — PoW entries omit the
    solution and carry the block hash explicitly; PON entries are full
    (collateral, then sig). Returns (count, last_hash)."""
    f = io.BytesIO(payload)
    count = read_varint(f)
    last_hash = expect_prev
    for _ in range(count):
        version, prev, merkle, sapling, time_bits = _read_common(f)
        _validate_common(version, merkle, prev, last_hash)
        if version >= PON_VERSION:
            collateral = f.read(36)
            sig_len = read_varint(f)
            if sig_len == 0:
                raise AssertionError("empty vchBlockSig on PON cmpheader")
            f.read(sig_len)
            last_hash = _pon_gethash(version, prev, merkle, sapling, time_bits, collateral)
        else:
            nonce = f.read(32)
            hash_block = f.read(32)
            if nonce == b"\x00" * 32:
                raise AssertionError("zeroed nNonce on PoW cmpheader")
            if hash_block == b"\x00" * 32:
                raise AssertionError("zeroed hashBlock on PoW cmpheader")
            last_hash = hash_block
    return count, last_hash


def worker(args, stats, stop_evt):
    proto = CURRENT_PROTOCOL_VERSION if args.compact else LEGACY_PROTOCOL_VERSION
    peer = Peer(args.host, args.port, proto)
    peer.handshake()
    locator = bytes.fromhex(GENESIS_HASH_HEX)[::-1]  # internal byte order
    batches = 0
    while not stop_evt.is_set():
        kind, payload = peer.get_headers(locator)
        parse = parse_cmpheaders_msg if kind == "cmpheaders" else parse_headers_msg
        count, last_hash = parse(payload, locator)
        if count == 0 or last_hash == locator:
            break  # at tip
        locator = last_hash
        batches += 1
        rtt = peer.ping_rtt()
        with stats["lock"]:
            stats["headers"] += count
            stats["batches"] += 1
            stats["max_rtt"] = max(stats["max_rtt"], rtt)
            stats["kinds"].add(kind)
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
    ap.add_argument("--compact", action="store_true", help="advertise current protocol (cmpheaders path)")
    ap.add_argument("--max-batches", type=int, default=0, help="0 = walk to tip")
    ap.add_argument("--rtt-budget", type=float, default=5.0)
    args = ap.parse_args()

    stats = {"headers": 0, "batches": 0, "max_rtt": 0.0, "done": 0, "kinds": set(), "lock": threading.Lock()}
    stop_evt = threading.Event()
    threads = []
    errors = []

    def run():
        try:
            worker(args, stats, stop_evt)
        except Exception as e:
            errors.append(repr(e))
            stop_evt.set()

    t0 = time.monotonic()
    for _ in range(args.workers):
        t = threading.Thread(target=run, daemon=True)
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
        f"OK: {stats['headers']} headers validated across {stats['batches']} batches "
        f"({'/'.join(sorted(stats['kinds']))}), max ping RTT {stats['max_rtt']:.3f}s"
    )


if __name__ == "__main__":
    main()
