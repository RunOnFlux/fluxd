# Flux State Validator

Production validation tool that continuously monitors FluxNode ZMQ events and validates state consistency using async architecture.

## Architecture

- **Async event processing**: Uses `zmq.asyncio` for efficient, non-blocking ZMQ message handling
- **Direct RPC calls**: Makes JSON-RPC calls to fluxd via `aiohttp` (no flux-cli subprocess overhead)
- **Single event loop**: Proper async/await patterns with one event loop for all operations
- **Periodic validation**: Compares incrementally-built state against RPC snapshots at configurable intervals

## What It Validates

- Delta messages chain correctly (from_hash matches previous to_hash)
- Snapshots are atomic (height and blockhash from same block)
- State can be reconstructed from deltas
- Chain reorganizations are handled correctly
- No race conditions or state inconsistencies

## Installation

```bash
# Install to /opt
sudo mkdir -p /opt/flux-state-validator
sudo cp -r . /opt/flux-state-validator/
cd /opt/flux-state-validator

# Install dependencies
sudo uv sync

# Install systemd service
sudo cp flux-state-validator.service /etc/systemd/system/
# Edit to set correct RPC conf path for your system
sudo nano /etc/systemd/system/flux-state-validator.service

sudo systemctl daemon-reload
sudo systemctl enable flux-state-validator
sudo systemctl start flux-state-validator
```

## Usage

```bash
# Run directly
flux-state-validator --help

# Run with custom options
flux-state-validator \
  --zmq tcp://127.0.0.1:16123 \
  --rpc-conf /dat/var/lib/fluxd/flux.conf \
  --log /var/log/flux-state-validator/validation.log \
  --interval 100
```

### Options

- `--zmq`: ZMQ endpoint (default: `tcp://127.0.0.1:16123`)
- `--rpc-conf`: Path to flux.conf (default: `/dat/var/lib/fluxd/flux.conf`)
- `--log`: Log file path (default: `/var/log/flux-state-validator/validation.log`)
- `--interval`: Validation interval in blocks (default: 100)

## What It Detects

- ✗ Delta hash chain breaks (from_hash doesn't match previous to_hash)
- ✗ Snapshot inconsistencies (hash doesn't match height)
- ✗ State divergence (delta-based state vs snapshot state)
- ✗ Missing or out-of-order messages
- ✗ Chain reorg handling issues
- ✗ Node count mismatches
- ✗ Individual node field mismatches

## Dependencies

- Python 3.13+
- `pyzmq>=27.1.0` - Async ZMQ support
- `aiohttp>=3.13.3` - Async HTTP for RPC calls
- `typer>=0.22.0` - CLI framework

## See Also

- Main documentation: `../README.md`
- Systemd service: `flux-state-validator.service`
- Monitor tool: `../flux-zmq-monitor/`
