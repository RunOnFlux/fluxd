# Flux RPC integration tests

Python integration tests in `rpc-tests/` that drive a regtest `fluxd` over RPC.

## Running

Dependencies and the interpreter are managed with [uv](https://docs.astral.sh/uv/):

```sh
cd qa
uv run rpc-tests/generate_no_wallet.py --srcdir=../src
```

`--srcdir` points at the directory containing the built `fluxd` / `flux-cli`
(default `../../src`). uv resolves the environment from `pyproject.toml` /
`uv.lock` on first run.

## Linting / type checking (converted files)

```sh
cd qa
uv run ruff check rpc-tests/generate_no_wallet.py
uv run ruff format --check rpc-tests/generate_no_wallet.py
```

## Modernization status

The suite is migrating from a python2 framework to python3 + uv + ruff + ty.
Most scripts still begin with `assert sys.version_info < (3,)` and are not yet
converted; new tests are written in python3 and pass ruff/ty.
