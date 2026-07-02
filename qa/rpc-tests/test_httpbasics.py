"""Basic HTTP behaviour of the JSON-RPC interface: keep-alive across requests."""

import aiohttp
from conftest import NodeFactory


async def test_http_keepalive(node_factory: NodeFactory) -> None:
    node = await node_factory(0)
    url = f"http://127.0.0.1:{node.rpc_port}"
    headers = {"Authorization": aiohttp.encode_basic_auth("rt", "rt")}

    def rpc(method: str) -> str:
        return f'{{"method": "{method}", "params": [], "id": 1}}'

    async with aiohttp.ClientSession(headers=headers) as session:
        async with session.post(url, data=rpc("getbestblockhash")) as r1:
            assert (await r1.json())["error"] is None
            assert r1.headers.get("Connection", "").lower() != "close"

        # A second request succeeds over the kept-alive connection.
        async with session.post(url, data=rpc("getchaintips")) as r2:
            assert (await r2.json())["error"] is None
