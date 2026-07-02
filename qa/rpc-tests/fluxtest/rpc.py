"""Asyncio JSON-RPC client for talking to a regtest fluxd over HTTP."""

import json
from collections.abc import Awaitable, Callable
from decimal import Decimal
from typing import Any

import aiohttp


class JSONRPCError(Exception):
    """A JSON-RPC error response returned by fluxd."""

    def __init__(self, error: dict[str, Any]) -> None:
        super().__init__(error.get("message", "JSON-RPC error"))
        self.code: int | None = error.get("code")
        self.error = error


def _encode(obj: Any) -> float:
    if isinstance(obj, Decimal):
        return float(round(obj, 8))
    raise TypeError(f"{obj!r} is not JSON serializable")


class FluxRPC:
    """Awaitable JSON-RPC proxy: ``await rpc.getblockcount()``.

    Every JSON number is parsed as Decimal so satoshi amounts stay exact.
    """

    def __init__(self, url: str, session: aiohttp.ClientSession) -> None:
        self._url = url
        self._session = session
        self._id = 0

    async def call(self, method: str, *params: Any) -> Any:
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "1.1", "method": method, "params": list(params), "id": self._id},
            default=_encode,
        )
        async with self._session.post(
            self._url, data=payload, headers={"Content-Type": "application/json"}
        ) as response:
            text = await response.text()
        data = json.loads(text, parse_float=Decimal)
        if data.get("error") is not None:
            raise JSONRPCError(data["error"])
        return data["result"]

    def __getattr__(self, method: str) -> Callable[..., Awaitable[Any]]:
        if method.startswith("__") and method.endswith("__"):
            raise AttributeError(method)

        async def call(*params: Any) -> Any:
            return await self.call(method, *params)

        return call
