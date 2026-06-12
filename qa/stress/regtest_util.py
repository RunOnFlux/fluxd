#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""Minimal self-contained regtest harness for the stress suite.

Deliberately independent of qa/rpc-tests' python2-era framework: nodes are
driven through flux-cli subprocess calls against throwaway datadirs.

The fluxnode node runs with -zelnode=1 (flips fFluxnode before
LoadBlockIndex, enabling the arena + load-time HeaderData prune). Fluxnode
mode demands a non-null outpoint and a parseable WIF privkey at init; the
harness fabricates both (regtest WIF prefix 0xEF).
"""

import contextlib
import hashlib
import os
import shutil
import subprocess
import tempfile
import time

BITCOIND = os.environ.get("BITCOIND", "fluxd")
BITCOINCLI = os.environ.get("BITCOINCLI", "flux-cli")

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check(payload):
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload + chk, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    for b in payload + chk:
        if b == 0:
            s = "1" + s
        else:
            break
    return s


def regtest_wif():
    """Valid compressed-key WIF for regtest (prefix 0xEF), fixed secret."""
    secret = bytes([0x11] * 32)
    return _b58check(b"\xef" + secret + b"\x01")


FLUXNODE_ARGS = [
    "-zelnode=1",
    "-zelnodeoutpoint=" + "11" * 32,
    "-zelnodeindex=0",
    "-zelnodeprivkey=" + regtest_wif(),
]


class Node:
    def __init__(self, name, base_dir, rpcport, p2pport, extra_args=None):
        self.name = name
        self.datadir = os.path.join(base_dir, name)
        self.rpcport = rpcport
        self.p2pport = p2pport
        self.extra_args = list(extra_args or [])
        self.proc = None
        os.makedirs(os.path.join(self.datadir, "regtest"), exist_ok=True)
        with open(os.path.join(self.datadir, "flux.conf"), "w") as f:
            f.write(
                "regtest=1\nserver=1\nlisten=1\ndiscover=0\n"
                "rpcuser=stress\nrpcpassword=stress\n"
                f"rpcport={rpcport}\nport={p2pport}\nrpcallowip=127.0.0.1\n"
                "fallbackfee=0.0001\n"
            )

    @property
    def debug_log(self):
        return os.path.join(self.datadir, "regtest", "debug.log")

    def start(self, extra=None, wait=True):
        args = [BITCOIND, "-datadir=" + self.datadir, "-daemon=0", *self.extra_args, *list(extra or [])]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        if wait:
            self.wait_rpc()
        return self.proc

    def wait_rpc(self, timeout=120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                err = self.proc.stderr.read() if self.proc.stderr else ""
                raise RuntimeError(f"{self.name} exited at init: {(err or '')[-2000:]}")
            try:
                self.cli("getblockcount")
                return
            except subprocess.CalledProcessError:
                time.sleep(0.5)
        raise TimeoutError(f"{self.name}: RPC not up after {timeout}s")

    def cli(self, *args):
        out = subprocess.run(
            [BITCOINCLI, "-datadir=" + self.datadir] + [str(a) for a in args],
            capture_output=True,
            text=True,
            check=True,
            timeout=120,
        )
        return out.stdout.strip()

    def stop(self, timeout=120):
        with contextlib.suppress(subprocess.CalledProcessError):
            self.cli("stop")
        if self.proc:
            self.proc.wait(timeout=timeout)
            self.proc = None

    def kill9(self):
        if self.proc:
            self.proc.kill()
            self.proc.wait(timeout=30)
            self.proc = None

    def log_tail(self, n=400):
        with open(self.debug_log, "rb") as f:
            return b"\n".join(f.read().split(b"\n")[-n:]).decode("utf-8", "replace")

    def log_offset(self):
        return os.path.getsize(self.debug_log)

    def log_since(self, offset):
        with open(self.debug_log, "rb") as f:
            f.seek(offset)
            return f.read().decode("utf-8", "replace")


def make_chain(prefix):
    base = tempfile.mkdtemp(prefix=prefix)
    miner = Node("miner", base, 28232, 28233)
    fluxnode = Node("fluxnode", base, 28234, 28235, extra_args=FLUXNODE_ARGS)
    return base, miner, fluxnode


def connect(a, b):
    a.cli("addnode", f"127.0.0.1:{b.p2pport}", "onetry")


def wait_sync(a, b, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        ha, hb = a.cli("getbestblockhash"), b.cli("getbestblockhash")
        if ha == hb:
            return ha
        time.sleep(1)
    raise TimeoutError(f"nodes did not sync: {ha} vs {hb}")


def cleanup(base, *nodes):
    for n in nodes:
        try:
            if n.proc:
                n.kill9()
        except Exception:
            pass
    shutil.rmtree(base, ignore_errors=True)
