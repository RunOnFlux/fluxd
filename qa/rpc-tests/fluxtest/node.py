"""Asyncio management of a single regtest fluxd process."""

import asyncio
from pathlib import Path

import aiohttp

from .rpc import FluxRPC, JSONRPCError


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

    def _read_stderr(self) -> str:
        try:
            return self._stderr_path.read_text().strip()
        except OSError:
            return ""

    async def stop(self) -> None:
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
        await self._session.close()
        if self._stderr is not None:
            self._stderr.close()
