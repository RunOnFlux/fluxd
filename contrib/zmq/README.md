# Flux ZMQ Tools

This directory contains production-ready tools for monitoring and validating Flux ZMQ events.

## Tools

### flux-zmq-monitor

Real-time monitoring package that subscribes to FluxD ZMQ events and displays them in a human-readable format.

**Events monitored:**
- `hashblockheight` - New block notifications with hash and height
- `chainreorg` - Chain reorganization events
- `fluxnodelistdelta` - FluxNode list changes (added, removed, updated nodes per block)
- `fluxnodestatus` - Local fluxnode status changes (confirmed, paid, expired, etc.)

**Installation:**
```bash
# Install to /opt
sudo mkdir -p /opt/flux-zmq-monitor
sudo cp -r flux-zmq-monitor/* /opt/flux-zmq-monitor/
cd /opt/flux-zmq-monitor

# Install dependencies with uv
sudo uv sync

# Install systemd service
sudo cp flux-zmq-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable flux-zmq-monitor
sudo systemctl start flux-zmq-monitor
```

**Usage:**
```bash
# Run directly
flux-zmq-monitor --help

# Run with custom endpoint
flux-zmq-monitor --endpoint tcp://127.0.0.1:16123

# Run with log file
flux-zmq-monitor --log-file /var/log/flux-zmq-monitor/events.log
```

**Example output:**
```
🚀 FluxD ZMQ Event Monitor
============================================================
✓ Subscribed to hashblockheight on tcp://127.0.0.1:16123
✓ Subscribed to chainreorg on tcp://127.0.0.1:16123
✓ Subscribed to fluxnodelistdelta on tcp://127.0.0.1:16123
✓ Subscribed to fluxnodestatus on tcp://127.0.0.1:16123

👂 Listening for events... (Ctrl+C to stop)

[14:32:15] hashblockheight (seq #42)
  Block #12345: 00000abc123def456...

[14:32:16] fluxnodelistdelta (seq #43)
  📊 FluxNode Delta: height 12344 → 12345
  From hash: 00000def456abc123...
  To hash:   00000abc123def456...
  Summary: 0 added, 0 removed, 2 updated

  🔄 UPDATED (2):
     • CUMULUS  @ 192.168.1.100      | Outpoint: abc123...
       Confirmed:   12300 | LastPaid:   12250 | Status: CONFIRMED
```

### flux-state-validator

Production validation package that continuously monitors ZMQ events and validates FluxNode state consistency using async architecture.

**What it validates:**
- Delta messages chain correctly (from_hash matches previous to_hash)
- Snapshots are atomic (height and blockhash from same block)
- State can be reconstructed from deltas
- Chain reorganizations are handled correctly
- No race conditions or state inconsistencies

**Architecture:**
- Uses `zmq.asyncio` for efficient event processing
- Direct JSON-RPC calls to fluxd via `aiohttp` (no flux-cli subprocess)
- Single event loop with proper async/await patterns
- Periodic validation against RPC snapshots

**Installation:**
```bash
# Install to /opt
sudo mkdir -p /opt/flux-state-validator
sudo cp -r flux-state-validator/* /opt/flux-state-validator/
cd /opt/flux-state-validator

# Install dependencies with uv
sudo uv sync

# Install systemd service
sudo cp flux-state-validator.service /etc/systemd/system/
# Edit service to set correct RPC conf path for your system
sudo nano /etc/systemd/system/flux-state-validator.service

sudo systemctl daemon-reload
sudo systemctl enable flux-state-validator
sudo systemctl start flux-state-validator
```

**Usage:**
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

**What it detects:**
- ✗ Delta hash chain breaks (from_hash doesn't match previous to_hash)
- ✗ Snapshot inconsistencies (hash doesn't match height)
- ✗ State divergence (delta-based state vs snapshot state)
- ✗ Missing or out-of-order messages
- ✗ Chain reorg handling issues

**Example output:**
```
============================================================
FluxNode State Validator Starting
ZMQ Endpoint: tcp://127.0.0.1:16123
RPC Config: /dat/var/lib/fluxd/flux.conf
Validation Interval: 100 blocks
============================================================
✓ Subscribed to ZMQ events
Initializing state...
Fetching snapshot from RPC...
Snapshot received: height 2332031, blockhash 3d6b2b3a0c71567a..., 7614 nodes
Initialization complete!

Applied delta 2332031 → 2332032 (hash: c33521087dd9bd0e...): +0 -0 ~13 (total: 7614)

============================================================
VALIDATION CHECKPOINT
============================================================
Node count - Local: 7614, Snapshot: 7614
✓ VALIDATION PASSED - State matches snapshot perfectly!
```

## Dependencies

Both tools require:
- Python 3.13+
- `uv` package manager
- `pyzmq>=27.1.0`
- `typer>=0.22.0`

Validator additionally requires:
- `aiohttp>=3.13.3` for async RPC calls

## FluxD Configuration

To use these tools, FluxD must be started with ZMQ publishing enabled:

```bash
fluxd \
  -zmqpubhashblockheight=tcp://127.0.0.1:16123 \
  -zmqpubchainreorg=tcp://127.0.0.1:16123 \
  -zmqpubfluxnodelistdelta=tcp://127.0.0.1:16123 \
  -zmqpubfluxnodestatus=tcp://127.0.0.1:16123
```

Or add to `flux.conf`:
```
zmqpubhashblockheight=tcp://127.0.0.1:16123
zmqpubchainreorg=tcp://127.0.0.1:16123
zmqpubfluxnodelistdelta=tcp://127.0.0.1:16123
zmqpubfluxnodestatus=tcp://127.0.0.1:16123
```

**Note:** `zmqpubfluxnodestatus` is only useful on fluxnodes (`fluxnode=1`). It publishes the local node's status on each block where a change is detected (e.g. confirmed, paid, expired). Non-fluxnodes skip it with a single bool check.

## Systemd Services

Both packages include hardened systemd service files with:
- `Wants=fluxd.service` - Soft dependency so ZMQ auto-reconnects survive daemon restarts
- `NoNewPrivileges=true` - Prevents privilege escalation
- `PrivateTmp=true` - Isolated /tmp directory
- `ProtectSystem=strict` - Read-only filesystem
- `ProtectHome=true` - Home directory protection
- Automatic log directory creation via `LogsDirectory`
- UV cache directory management via `CacheDirectory`

**Monitor service:**
```bash
sudo systemctl status flux-zmq-monitor
sudo journalctl -u flux-zmq-monitor -f
tail -f /var/log/flux-zmq-monitor/events.log
```

**Validator service:**
```bash
sudo systemctl status flux-state-validator
sudo journalctl -u flux-state-validator -f
tail -f /var/log/flux-state-validator/validation.log
```

## Use Cases

**Development:**
- Monitor ZMQ events during development
- Debug state transitions
- Verify delta messages are correct

**Testing:**
- Validate state consistency during testing
- Detect race conditions and edge cases
- Verify reorg handling

**Production:**
- Continuous validation of FluxNode state
- Early detection of inconsistencies
- Monitoring and alerting

## Message Formats

### hashblockheight (36 bytes)
```
[hash: 32 bytes reversed][height: 4 bytes little-endian]
```

### fluxnodelistdelta (73+ bytes)
```
[from_height: 4][to_height: 4]
[from_hash: 32 reversed][to_hash: 32 reversed]
[flags: 1 (bit 0 = is_reorg)]
[added_nodes: CompactSize + node data]
[removed_nodes: CompactSize + outpoints]
[updated_nodes: CompactSize + node data]
```

### fluxnodestatus (54+ bytes)
```
[block_height: 4][status: 1][tier: 1]
[confirmed_height: 4][last_confirmed_height: 4][last_paid_height: 4]
[txhash: 32 reversed][outidx: 4]
[ip: CompactSize + string bytes]
```

Status values: 0=ERROR, 1=STARTED, 2=DOS_PROTECTION, 3=CONFIRMED, 4=MISS_CONFIRMED, 5=EXPIRED.
Only published when a field changes (or on first block after startup).

### chainreorg (108 bytes)
```
[old_tip_hash: 32 reversed][old_tip_height: 4]
[new_tip_hash: 32 reversed][new_tip_height: 4]
[fork_hash: 32 reversed][fork_height: 4]
```

**Note:** All hashes are in display byte order. Heights are little-endian uint32.

## Related Documentation

- Integration test: `qa/rpc-tests/fluxnode_zmq_test.py`
- Test documentation: `qa/rpc-tests/FLUXNODE_ZMQ_TEST.md`
- Source implementation: `src/zmq/zmqpublishnotifier.cpp`
- Monitor package: `flux-zmq-monitor/README.md`
- Validator package: `flux-state-validator/README.md`

## Troubleshooting

**Connection refused:**
- Verify FluxD is running with ZMQ enabled
- Check the port matches your configuration
- Verify firewall allows connections

**No messages received:**
- Verify blocks are being generated
- Check ZMQ subscriptions are correct
- Ensure FluxD ZMQ is publishing to the correct endpoint

**State validation failures:**
- Check FluxD logs for errors
- Verify no data corruption
- Check for network issues or RPC connectivity
- Report as a bug if reproducible

**Service fails to start:**
- Check `journalctl -u <service-name> -n 50` for errors
- Verify RPC configuration path is correct
- Ensure uv dependencies are installed (`uv sync`)
- Check systemd security settings aren't blocking required access

## License

Distributed under the MIT software license, see the accompanying file COPYING or https://www.opensource.org/licenses/mit-license.php.
