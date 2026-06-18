# Flux RPC integration tests

Asyncio + pytest integration tests in `rpc-tests/` that drive a regtest `fluxd`
over JSON-RPC.

## Running

Dependencies and the interpreter are managed with [uv](https://docs.astral.sh/uv/):

```sh
cd qa
uv run pytest --fluxd=../src/fluxd
```

`--fluxd` points at the built `fluxd` binary (defaults to the `BITCOIND`
environment variable, else `fluxd` on `PATH`). uv resolves the environment from
`pyproject.toml` / `uv.lock` on first run.

Run a single module or test:

```sh
uv run pytest rpc-tests/test_generate_no_wallet.py --fluxd=../src/fluxd
uv run pytest rpc-tests/test_generate_no_wallet.py::test_generate_with_wallet_mints --fluxd=../src/fluxd
```

## Writing tests

Tests are `async def` functions in `test_*.py` modules. The `node_factory`
fixture starts regtest nodes and tears them down automatically:

```python
async def test_something(node_factory):
    node = await node_factory(0)
    assert await node.rpc.getblockcount() == 0
```

`node.rpc.<method>(...)` is an awaitable JSON-RPC call. Building blocks live in
the `fluxtest` package: `fluxtest.node.FluxNode` (asyncio subprocess
management) and `fluxtest.rpc.FluxRPC` (aiohttp JSON-RPC client, Decimal-exact).

## Linting / type checking

```sh
cd qa
uvx ruff check rpc-tests/
uvx ruff format --check rpc-tests/
uv run --with ty ty check rpc-tests/
```

## Modernization status

The suite is migrating to python3 + uv + pytest + asyncio. New tests use the
`fluxtest` async framework and are named `test_*.py`. The legacy python2
`test_framework` scripts (named `<feature>.py`) are not collected by pytest and
are being converted incrementally.
