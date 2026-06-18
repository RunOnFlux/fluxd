# Copyright (c) 2014 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://www.opensource.org/licenses/mit-license.php.

"""Helper routines for the RPC integration tests."""

import json
import logging
import os
import random
import re
import shutil
import subprocess
import time
from base64 import b64encode
from binascii import hexlify, unhexlify
from collections.abc import Callable
from decimal import ROUND_DOWN, Decimal
from typing import Any, NoReturn

from .authproxy import HTTP_TIMEOUT, AuthServiceProxy

logger = logging.getLogger("TestFramework")

# fluxd subprocesses, keyed by node index.
bitcoind_processes: dict[int, subprocess.Popen] = {}


def p2p_port(n: int) -> int:
    return 11000 + n + os.getpid() % 999


def rpc_port(n: int) -> int:
    return 12000 + n + os.getpid() % 999


def check_json_precision() -> None:
    """Make sure the json library does not lose precision converting FLUX values."""
    n = Decimal("20000000.00000003")
    satoshis = int(json.loads(json.dumps(float(n))) * 1.0e8)
    if satoshis != 2000000000000003:
        raise RuntimeError("JSON encode/decode loses precision")


def bytes_to_hex_str(byte_str: bytes) -> str:
    return hexlify(byte_str).decode("ascii")


def hex_str_to_bytes(hex_str: str) -> bytes:
    return unhexlify(hex_str.encode("ascii"))


def str_to_b64str(string: str) -> str:
    return b64encode(string.encode("utf-8")).decode("ascii")


def sync_blocks(rpc_connections: list[AuthServiceProxy], wait: float = 1) -> None:
    """Wait until everybody has the same block count."""
    while True:
        counts = [x.getblockcount() for x in rpc_connections]
        if counts == [counts[0]] * len(counts):
            break
        time.sleep(wait)


def sync_mempools(rpc_connections: list[AuthServiceProxy], wait: float = 1) -> None:
    """Wait until everybody has the same transactions in their memory pools."""
    while True:
        pool = set(rpc_connections[0].getrawmempool())
        num_match = 1
        for i in range(1, len(rpc_connections)):
            if set(rpc_connections[i].getrawmempool()) == pool:
                num_match += 1
        if num_match == len(rpc_connections):
            break
        time.sleep(wait)

    # Now that the mempools are in sync, wait for the internal notifications to finish.
    while True:
        notified = [x.getmempoolinfo()["fullyNotified"] for x in rpc_connections]
        if notified == [True] * len(notified):
            break
        time.sleep(wait)


def initialize_datadir(dirname: str, n: int) -> str:
    datadir = os.path.join(dirname, f"node{n}")
    if not os.path.isdir(datadir):
        os.makedirs(datadir)
    with open(os.path.join(datadir, "flux.conf"), "w") as f:
        f.write("regtest=1\n")
        f.write("showmetrics=0\n")
        f.write("rpcuser=rt\n")
        f.write("rpcpassword=rt\n")
        f.write(f"port={p2p_port(n)}\n")
        f.write(f"rpcport={rpc_port(n)}\n")
        f.write("listenonion=0\n")
    return datadir


def _node_url(i: int, rpchost: str | None = None) -> str:
    return f"http://rt:rt@{rpchost or '127.0.0.1'}:{rpc_port(i)}"


def _wait_for_rpc(
    i: int,
    process: subprocess.Popen,
    log_path: str,
    url: str,
    timeout: float = 60,
) -> None:
    """Block until node *i* answers RPC, failing fast if the daemon exits first.

    Polls the process while waiting, so a daemon that dies during init raises
    immediately with its captured stderr instead of hanging until an external
    timeout fires (the classic "silent daemon death hangs forever").

    A fresh connection is opened per attempt: a connection refused during
    warmup otherwise wedges a reused http.client connection in the
    request-started state, so every later attempt fails with CannotSendRequest.
    """
    deadline = time.time() + timeout
    while True:
        if process.poll() is not None:
            try:
                with open(log_path) as f:
                    output = f.read().strip()
            except OSError:
                output = ""
            raise AssertionError(
                f"fluxd node {i} exited with code {process.returncode} during "
                f"startup:\n{output or '(no output captured)'}"
            )
        try:
            AuthServiceProxy(url, timeout=30).getblockcount()
            return
        except Exception:
            if time.time() > deadline:
                raise AssertionError(f"fluxd node {i} RPC did not respond within {timeout}s")
            time.sleep(0.25)


def initialize_chain(test_dir: str) -> None:
    """Create (or copy from cache) a 200-block chain and 4 wallets.

    fluxd and flux-cli must be in the search path.
    """
    if not os.path.isdir(os.path.join("cache", "node0")):
        # Create the cache directories and run fluxds.
        for i in range(4):
            datadir = initialize_datadir("cache", i)
            args = [
                os.getenv("BITCOIND", "fluxd"),
                "-keypool=1",
                f"-datadir={datadir}",
                "-discover=0",
            ]
            if i > 0:
                args.append(f"-connect=127.0.0.1:{p2p_port(0)}")
            log_path = os.path.join(datadir, "node_stderr.log")
            node_log = open(log_path, "w+")
            process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=node_log)
            bitcoind_processes[i] = process
            _wait_for_rpc(i, process, log_path, _node_url(i))

        rpcs = [AuthServiceProxy(_node_url(i)) for i in range(4)]

        # Create a 200-block chain; each of the 4 nodes gets 25 mature blocks
        # and 25 immature. Blocks are timestamped 10 minutes apart, starting at
        # 1 Jan 2014.
        block_time = 1388534400
        for _ in range(2):
            for peer in range(4):
                for _ in range(25):
                    set_node_times(rpcs, block_time)
                    rpcs[peer].generate(1)
                    block_time += 10 * 60
                # Must sync before the next peer starts generating blocks.
                sync_blocks(rpcs)

        # Shut them down, and clean up the cache directories.
        stop_nodes(rpcs)
        wait_bitcoinds()
        for i in range(4):
            os.remove(log_filename("cache", i, "debug.log"))
            os.remove(log_filename("cache", i, "db.log"))
            os.remove(log_filename("cache", i, "peers.dat"))
            os.remove(log_filename("cache", i, "fee_estimates.dat"))

    for i in range(4):
        from_dir = os.path.join("cache", f"node{i}")
        to_dir = os.path.join(test_dir, f"node{i}")
        shutil.copytree(from_dir, to_dir)
        initialize_datadir(test_dir, i)  # Overwrite port/rpcport in flux.conf


def initialize_chain_clean(test_dir: str, num_nodes: int) -> None:
    """Create an empty blockchain and *num_nodes* wallets.

    Useful when a test wants complete control over initialization.
    """
    for i in range(num_nodes):
        initialize_datadir(test_dir, i)


def _rpchost_to_args(rpchost: str | None) -> list[str]:
    """Convert an optional IP:port spec to rpcconnect/rpcport args."""
    if rpchost is None:
        return []

    match = re.match(r"(\[[0-9a-fA-f:]+\]|[^:]+)(?::([0-9]+))?$", rpchost)
    if not match:
        raise ValueError(f"Invalid RPC host spec {rpchost}")

    rpcconnect = match.group(1)
    rpcport = match.group(2)

    if rpcconnect.startswith("["):  # remove IPv6 [...] wrapping
        rpcconnect = rpcconnect[1:-1]

    rv = [f"-rpcconnect={rpcconnect}"]
    if rpcport:
        rv.append(f"-rpcport={rpcport}")
    return rv


def start_node(
    i: int,
    dirname: str,
    extra_args: list[str] | None = None,
    rpchost: str | None = None,
    timewait: float | None = None,
    binary: str | None = None,
) -> AuthServiceProxy:
    """Start a fluxd and return an RPC connection to it."""
    datadir = os.path.join(dirname, f"node{i}")
    if binary is None:
        binary = os.getenv("BITCOIND", "fluxd")
    args = [binary, f"-datadir={datadir}", "-keypool=1", "-discover=0", "-rest"]
    if extra_args is not None:
        args.extend(extra_args)

    # Capture the daemon's stderr to a per-node file so a fatal init error is
    # preserved for diagnosis instead of being swallowed by the runner streams.
    # stdout goes to /dev/null: fluxd's own logs go to debug.log, and its
    # metrics/console thread blocks when stdout is a regular file (not a tty).
    log_path = os.path.join(datadir, "node_stderr.log")
    node_log = open(log_path, "w+")
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=node_log)
    bitcoind_processes[i] = process

    url = _node_url(i, rpchost)
    _wait_for_rpc(i, process, log_path, url, timeout=timewait if timewait is not None else 60)
    return AuthServiceProxy(url, timeout=timewait if timewait is not None else HTTP_TIMEOUT)


def start_nodes(
    num_nodes: int,
    dirname: str,
    extra_args: list[list[str] | None] | None = None,
    rpchost: str | None = None,
    binary: list[str | None] | None = None,
) -> list[AuthServiceProxy]:
    """Start multiple fluxds and return their RPC connections."""
    if extra_args is None:
        extra_args = [None] * num_nodes
    if binary is None:
        binary = [None] * num_nodes
    return [
        start_node(i, dirname, extra_args[i], rpchost, binary=binary[i]) for i in range(num_nodes)
    ]


def log_filename(dirname: str, n_node: int, logname: str) -> str:
    return os.path.join(dirname, f"node{n_node}", "regtest", logname)


def check_node(i: int) -> int | None:
    bitcoind_processes[i].poll()
    return bitcoind_processes[i].returncode


def stop_node(node: AuthServiceProxy, i: int) -> None:
    try:
        node.stop()
    except Exception:
        pass  # node may already be down; still reap the process below
    bitcoind_processes[i].wait()
    del bitcoind_processes[i]


def stop_nodes(nodes: list[AuthServiceProxy]) -> None:
    for node in nodes:
        try:
            node.stop()
        except Exception:
            pass  # a dead node must not mask the test's primary error
    del nodes[:]  # emptying the list closes connections as a side effect


def set_node_times(nodes: list[AuthServiceProxy], t: int) -> None:
    for node in nodes:
        node.setmocktime(t)


def wait_bitcoinds() -> None:
    """Wait for all fluxds to exit, terminating any that overstay a grace period.

    Nodes are normally RPC-stopped first and exit promptly; the terminate path
    is a safety net so a straggler (e.g. one left running by a failed setup)
    cannot hang teardown forever.
    """
    for bitcoind in bitcoind_processes.values():
        try:
            bitcoind.wait(timeout=60)
        except subprocess.TimeoutExpired:
            bitcoind.terminate()
            bitcoind.wait()
    bitcoind_processes.clear()


def connect_nodes(from_connection: AuthServiceProxy, node_num: int) -> None:
    ip_port = f"127.0.0.1:{p2p_port(node_num)}"
    from_connection.addnode(ip_port, "onetry")
    # Poll until the version handshake completes, to avoid a race with
    # transaction relaying.
    while any(peer["version"] == 0 for peer in from_connection.getpeerinfo()):
        time.sleep(0.1)


def connect_nodes_bi(nodes: list[AuthServiceProxy], a: int, b: int) -> None:
    connect_nodes(nodes[a], b)
    connect_nodes(nodes[b], a)


def find_output(node: AuthServiceProxy, txid: str, amount: Decimal) -> int:
    """Return the index of the txid output with value *amount*, or raise."""
    txdata = node.getrawtransaction(txid, 1)
    for i in range(len(txdata["vout"])):
        if txdata["vout"][i]["value"] == amount:
            return i
    raise RuntimeError(f"find_output txid {txid} : {amount} not found")


def gather_inputs(
    from_node: AuthServiceProxy,
    amount_needed: Decimal,
    confirmations_required: int = 1,
) -> tuple[Decimal, list[dict[str, Any]]]:
    """Return a random set of unspent txouts that cover *amount_needed*."""
    assert confirmations_required >= 0
    utxo = from_node.listunspent(confirmations_required)
    random.shuffle(utxo)
    inputs: list[dict[str, Any]] = []
    total_in = Decimal("0.00000000")
    while total_in < amount_needed and len(utxo) > 0:
        t = utxo.pop()
        total_in += t["amount"]
        inputs.append({"txid": t["txid"], "vout": t["vout"], "address": t["address"]})
    if total_in < amount_needed:
        raise RuntimeError(f"Insufficient funds: need {amount_needed}, have {total_in}")
    return (total_in, inputs)


def make_change(
    from_node: AuthServiceProxy,
    amount_in: Decimal,
    amount_out: Decimal,
    fee: Decimal,
) -> dict[str, Any]:
    """Create change output(s) and return them."""
    outputs: dict[str, Any] = {}
    amount = amount_out + fee
    change = amount_in - amount
    if change > amount * 2:
        # Create an extra change output to break up big inputs.
        change_address = from_node.getnewaddress()
        # Split change in two, being careful of rounding.
        outputs[change_address] = Decimal(change / 2).quantize(
            Decimal("0.00000001"), rounding=ROUND_DOWN
        )
        change = amount_in - amount - outputs[change_address]
    if change > 0:
        outputs[from_node.getnewaddress()] = change
    return outputs


def send_zeropri_transaction(
    from_node: AuthServiceProxy,
    to_node: AuthServiceProxy,
    amount: Decimal,
    fee: Decimal,
) -> tuple[str, str]:
    """Create and broadcast a zero-priority transaction.

    Returns (txid, hex-encoded-txdata). Ensures the transaction is
    zero-priority by first creating a send-to-self, then spending its output.
    """
    # Create a send-to-self with confirmed inputs.
    self_address = from_node.getnewaddress()
    (total_in, inputs) = gather_inputs(from_node, amount + fee * 2)
    outputs = make_change(from_node, total_in, amount + fee, fee)
    outputs[self_address] = float(amount + fee)

    self_rawtx = from_node.createrawtransaction(inputs, outputs)
    self_signresult = from_node.signrawtransaction(self_rawtx)
    self_txid = from_node.sendrawtransaction(self_signresult["hex"], True)

    vout = find_output(from_node, self_txid, amount + fee)
    # Now immediately spend the output to create a 1-input, 1-output
    # zero-priority transaction.
    inputs = [{"txid": self_txid, "vout": vout}]
    outputs = {to_node.getnewaddress(): float(amount)}

    rawtx = from_node.createrawtransaction(inputs, outputs)
    signresult = from_node.signrawtransaction(rawtx)
    txid = from_node.sendrawtransaction(signresult["hex"], True)

    return (txid, signresult["hex"])


def random_zeropri_transaction(
    nodes: list[AuthServiceProxy],
    amount: Decimal,
    min_fee: Decimal,
    fee_increment: Decimal,
    fee_variants: int,
) -> tuple[str, str, Decimal]:
    """Create a random zero-priority transaction.

    Returns (txid, hex-encoded-transaction-data, fee).
    """
    from_node = random.choice(nodes)
    to_node = random.choice(nodes)
    fee = min_fee + fee_increment * random.randint(0, fee_variants)
    (txid, txhex) = send_zeropri_transaction(from_node, to_node, amount, fee)
    return (txid, txhex, fee)


def random_transaction(
    nodes: list[AuthServiceProxy],
    amount: Decimal,
    min_fee: Decimal,
    fee_increment: Decimal,
    fee_variants: int,
) -> tuple[str, str, Decimal]:
    """Create a random transaction.

    Returns (txid, hex-encoded-transaction-data, fee).
    """
    from_node = random.choice(nodes)
    to_node = random.choice(nodes)
    fee = min_fee + fee_increment * random.randint(0, fee_variants)

    (total_in, inputs) = gather_inputs(from_node, amount + fee)
    outputs = make_change(from_node, total_in, amount, fee)
    outputs[to_node.getnewaddress()] = float(amount)

    rawtx = from_node.createrawtransaction(inputs, outputs)
    signresult = from_node.signrawtransaction(rawtx)
    txid = from_node.sendrawtransaction(signresult["hex"], True)

    return (txid, signresult["hex"], fee)


def assert_equal(expected: Any, actual: Any, message: str = "") -> None:
    if expected != actual:
        if message:
            message = f"; {message}"
        raise AssertionError(f"(left == right){message}\n  left: <{expected}>\n right: <{actual}>")


def assert_true(condition: bool, message: str = "") -> None:
    if not condition:
        raise AssertionError(message)


def assert_false(condition: bool, message: str = "") -> None:
    assert_true(not condition, message)


def assert_greater_than(thing1: Any, thing2: Any) -> None:
    if thing1 <= thing2:
        raise AssertionError(f"{thing1} <= {thing2}")


def assert_raises(
    exc: type[BaseException], fun: Callable[..., Any], *args: Any, **kwds: Any
) -> None:
    try:
        fun(*args, **kwds)
    except exc:
        pass
    except Exception as e:
        raise AssertionError(f"Unexpected exception raised: {type(e).__name__}")
    else:
        raise AssertionError("No exception raised")


def fail(message: str = "") -> NoReturn:
    raise AssertionError(message)


def wait_and_assert_operationid_status_result(
    node: AuthServiceProxy,
    myopid: str,
    in_status: str = "success",
    in_errormsg: str | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """Poll an async operation to completion and assert its status."""
    logger.debug("waiting for async operation %s", myopid)
    result = None
    for _ in range(1, timeout):
        results = node.z_getoperationresult([myopid])
        if len(results) > 0:
            result = results[0]
            break
        time.sleep(1)

    if result is None:
        raise AssertionError("timeout occurred waiting for async operation")
    status = result["status"]
    logger.debug("...returned status: %s", status)

    errormsg = None
    if status == "failed":
        errormsg = result["error"]["message"]
        logger.debug("...returned error: %s", errormsg)
        assert_equal(in_errormsg, errormsg)

    assert_equal(
        in_status, status, f"Operation returned mismatched status. Error Message: {errormsg}"
    )
    return result


def wait_and_assert_operationid_status(
    node: AuthServiceProxy,
    myopid: str,
    in_status: str = "success",
    in_errormsg: str | None = None,
    timeout: int = 300,
) -> str | None:
    """Return the txid if the operation succeeded, else None."""
    result = wait_and_assert_operationid_status_result(
        node, myopid, in_status, in_errormsg, timeout
    )
    if result["status"] == "success":
        return result["result"]["txid"]
    return None


def get_coinbase_address(node: AuthServiceProxy, expected_utxos: int | None = None) -> str:
    """Return a coinbase address on the node, filtered by UTXO count.

    With no filter, returns the coinbase address holding the most spendable
    UTXOs. The default cached chain has one address per coinbase output.
    """
    addrs = [utxo["address"] for utxo in node.listunspent() if utxo["generated"]]
    assert len(set(addrs)) > 0

    if expected_utxos is None:
        counted = [(addrs.count(a), a) for a in set(addrs)]
        return sorted(counted, reverse=True)[0][1]

    filtered = [a for a in set(addrs) if addrs.count(a) == expected_utxos]
    assert len(filtered) > 0
    return filtered[0]
