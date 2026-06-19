"""Asyncio management of a single regtest fluxd process."""

import asyncio
from pathlib import Path

import aiohttp

from .rpc import FluxRPC, JSONRPCError

# All nodes start with their clock frozen near this time so that mined chains
# stay in a consistent era: a node will not download blocks for a chain whose
# tip is far older than its own clock, so mixing a mocktime chain with a
# real-time node breaks cross-node sync.
DEFAULT_MOCKTIME = 1600000000


class FluxNode:
    """A single regtest fluxd, started and stopped over asyncio."""

    def __init__(
        self,
        index: int,
        datadir: Path,
        binary: str,
        rpc_port: int,
        p2p_port: int,
        extra_args: list[str] | None = None,
    ) -> None:
        self.index = index
        self.datadir = datadir
        self.binary = binary
        self.rpc_port = rpc_port
        self.p2p_port = p2p_port
        self.extra_args = list(extra_args or [])
        self._proc: asyncio.subprocess.Process | None = None
        self._stderr_path = datadir / "node_stderr.log"
        self._stderr = None
        # Per-node offset so independent chains diverge (regtest mining is
        # otherwise deterministic and two nodes produce identical chains).
        self._mocktime = DEFAULT_MOCKTIME + index
        self._session = aiohttp.ClientSession(
            headers={"Authorization": aiohttp.encode_basic_auth("rt", "rt")},
            timeout=aiohttp.ClientTimeout(total=600),
        )
        self.rpc = FluxRPC(f"http://127.0.0.1:{rpc_port}", self._session)

    def _write_conf(self) -> None:
        self.datadir.mkdir(parents=True, exist_ok=True)
        (self.datadir / "flux.conf").write_text(
            "regtest=1\n"
            "showmetrics=0\n"
            "rpcuser=rt\n"
            "rpcpassword=rt\n"
            f"port={self.p2p_port}\n"
            f"rpcport={self.rpc_port}\n"
            "listenonion=0\n"
        )

    async def start(self, timeout: float = 60) -> None:
        self._write_conf()
        args = [
            self.binary,
            f"-datadir={self.datadir}",
            "-keypool=1",
            "-discover=0",
            "-rest",
            *self.extra_args,
        ]
        # stdout -> DEVNULL: fluxd's own logs go to debug.log, and its
        # metrics/console thread blocks on a non-tty file. stderr is captured to
        # diagnose a fatal init error.
        self._stderr = open(self._stderr_path, "w+")
        self._proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.DEVNULL, stderr=self._stderr
        )
        await self._wait_for_rpc(timeout)
        # Freeze the clock in a consistent era for deterministic, sync-able chains.
        await self.rpc.setmocktime(self._mocktime)

    async def _wait_for_rpc(self, timeout: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        assert self._proc is not None
        while True:
            if self._proc.returncode is not None:
                raise AssertionError(
                    f"fluxd node {self.index} exited with code {self._proc.returncode} "
                    f"during startup:\n{self._read_stderr() or '(no output captured)'}"
                )
            try:
                await self.rpc.getblockcount()
                return
            except (aiohttp.ClientError, JSONRPCError):
                # Connection refused (warming up) or RPC-in-warmup; keep polling.
                if loop.time() > deadline:
                    raise AssertionError(
                        f"fluxd node {self.index} RPC did not respond within {timeout}s"
                    )
                await asyncio.sleep(0.25)

    async def mine(self, count: int, interval: int = 30) -> list[str]:
        """Mine ``count`` blocks with strictly increasing timestamps.

        Each block's time advances from the node's mocktime, kept ahead of the
        current tip, so blocks mined after adopting a peer's (later) chain stay
        valid. The per-node starting offset keeps independent chains divergent.
        The interval is small so a long chain's tip stays within the
        future-block window of a peer's (frozen) clock and can still be synced.
        """
        hashes: list[str] = []
        for _ in range(count):
            besthash = await self.rpc.getbestblockhash()
            tip_time = (await self.rpc.getblock(besthash))["time"]
            # + index keeps this block distinct from another node's same-height
            # block; without it a node re-mining over an invalidated block would
            # deterministically reproduce that exact (rejected) block.
            self._mocktime = max(self._mocktime, tip_time) + interval + self.index
            await self.rpc.setmocktime(self._mocktime)
            hashes.extend(await self.rpc.generate(1))
        return hashes

    async def advance_mocktime(self, seconds: int) -> int:
        """Push this node's frozen clock forward by ``seconds`` and return it.

        Keeps mine()'s clock source of truth in step, so callers can satisfy
        time-gated daemon behaviour without real-time waiting.
        """
        self._mocktime += seconds
        await self.rpc.setmocktime(self._mocktime)
        return self._mocktime

    async def set_mocktime_at_least(self, when: int) -> int:
        """Pull this node's frozen clock up to at least ``when`` and return it.

        Used to bring a non-mining node's clock up to a peer's tip time before
        syncing a long chain, which the daemon would otherwise reject as
        timed too far in the future.
        """
        self._mocktime = max(self._mocktime, when)
        await self.rpc.setmocktime(self._mocktime)
        return self._mocktime

    def _read_stderr(self) -> str:
        try:
            return self._stderr_path.read_text().strip()
        except OSError:
            return ""

    async def _stop_process(self) -> None:
        if self._proc is not None:
            try:
                if self._proc.returncode is None:
                    await self.rpc.stop()
            except Exception:
                pass  # a dead node must not mask the test's primary error
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=60)
            except TimeoutError:
                self._proc.terminate()
                await self._proc.wait()
            self._proc = None
        if self._stderr is not None:
            self._stderr.close()
            self._stderr = None

    async def stop_daemon(self) -> None:
        """Stop the daemon process but keep the datadir and RPC session open.

        Lets a caller swap on-disk wallet/chain files between a stop and a fresh
        start() -- something restart() cannot wrap around external file ops.
        """
        await self._stop_process()

    async def restart(self, extra_args: list[str] | None = None) -> None:
        """Restart the daemon on the same datadir, optionally replacing its args."""
        await self._stop_process()
        if extra_args is not None:
            self.extra_args = list(extra_args)
        await self.start()

    async def stop(self) -> None:
        await self._stop_process()
        await self._session.close()
