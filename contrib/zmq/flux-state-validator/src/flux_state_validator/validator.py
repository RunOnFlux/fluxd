#!/usr/bin/env python3
# /// script
# dependencies = [
#   "pyzmq>=26.0.0",
# ]
# ///
"""
FluxNode State Validator

This script validates that applying FluxNode deltas incrementally produces
the same result as fetching fresh snapshots from the RPC.

It subscribes to ZMQ events, maintains local state by applying deltas,
and periodically (every 100 blocks) compares the local state against
a fresh RPC snapshot to verify correctness.

This is a critical validation tool for the delta system.
"""

import zmq
import zmq.asyncio
import struct
import json
import time
import sys
import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, Optional, Set, List, Any
from dataclasses import dataclass
from typing import ClassVar
from pathlib import Path


def read_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    """Read Bitcoin-style compact size integer"""
    if offset >= len(data):
        raise ValueError(f"read_compact_size: offset {offset} >= data length {len(data)}")

    first_byte = data[offset]
    offset += 1

    if first_byte < 0xFD:
        return first_byte, offset
    elif first_byte == 0xFD:
        if offset + 2 > len(data):
            raise ValueError(f"read_compact_size: insufficient data for uint16 at offset {offset}")
        value = struct.unpack('<H', data[offset:offset+2])[0]
        return value, offset + 2
    elif first_byte == 0xFE:
        if offset + 4 > len(data):
            raise ValueError(f"read_compact_size: insufficient data for uint32 at offset {offset}")
        value = struct.unpack('<I', data[offset:offset+4])[0]
        return value, offset + 4
    else:  # 0xFF
        if offset + 8 > len(data):
            raise ValueError(f"read_compact_size: insufficient data for uint64 at offset {offset}")
        value = struct.unpack('<Q', data[offset:offset+8])[0]
        return value, offset + 8


@dataclass
class Outpoint:
    """Bitcoin COutPoint (txid + index)"""
    txhash: str  # Hex string (display order)
    index: int

    SIZE: ClassVar[int] = 36  # 32 bytes txid + 4 bytes index

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple['Outpoint', int]:
        """Parse from binary data"""
        if offset + cls.SIZE > len(data):
            raise ValueError(f"Insufficient data for Outpoint at offset {offset}")

        # Daemon now sends hash in display byte order (matches RPC snapshots)
        txhash = data[offset:offset+32].hex()
        index = struct.unpack_from('<I', data, offset + 32)[0]

        return cls(txhash=txhash, index=index), offset + cls.SIZE

    def __str__(self) -> str:
        return f"{self.txhash}:{self.index}"


@dataclass
class FluxNodeDeltaEntry:
    """FluxNode data as it appears in ZMQ delta messages"""
    outpoint: Outpoint
    confirmed_height: int
    last_paid_height: int
    tier: str
    status: str
    ip_address: str

    TIER_MAP: ClassVar[dict] = {1: "CUMULUS", 2: "NIMBUS", 3: "STRATUS"}
    STATUS_MAP: ClassVar[dict] = {
        0: "ERROR",
        1: "STARTED",
        2: "DOS_PROTECTION",
        3: "CONFIRMED",
        4: "MISS_CONFIRMED",
        5: "EXPIRED"
    }

    @classmethod
    def from_bytes(cls, data: bytes, offset: int) -> tuple['FluxNodeDeltaEntry', int]:
        """Parse FluxNode data from binary format

        Format:
        - Outpoint (36 bytes)
        - Pubkey length (compact) + pubkey data
        - Pubkey2 length (compact) + pubkey2 data
        - Confirmed height (4 bytes)
        - Last paid height (4 bytes)
        - Tier (1 byte)
        - Status (1 byte)
        - IP length (compact) + IP string
        """
        # Parse outpoint
        outpoint, offset = Outpoint.from_bytes(data, offset)

        # Skip pubkey 1
        pubkey_len, offset = read_compact_size(data, offset)
        offset += pubkey_len

        # Skip pubkey 2
        pubkey2_len, offset = read_compact_size(data, offset)
        offset += pubkey2_len

        # Parse heights
        if offset + 8 > len(data):
            raise ValueError(f"Insufficient data for heights at offset {offset}")
        confirmed_height, last_paid_height = struct.unpack_from('<II', data, offset)
        offset += 8

        # Parse tier
        if offset >= len(data):
            raise ValueError(f"Insufficient data for tier at offset {offset}")
        tier_byte = data[offset]
        tier = cls.TIER_MAP.get(tier_byte, f"UNKNOWN({tier_byte})")
        offset += 1

        # Parse status
        if offset >= len(data):
            raise ValueError(f"Insufficient data for status at offset {offset}")
        status_byte = data[offset]
        status = cls.STATUS_MAP.get(status_byte, f"UNKNOWN({status_byte})")
        offset += 1

        # Parse IP address
        ip_len, offset = read_compact_size(data, offset)
        if offset + ip_len > len(data):
            raise ValueError(f"Insufficient data for IP at offset {offset}")
        ip_address = data[offset:offset+ip_len].decode('utf-8', errors='replace')
        offset += ip_len

        return cls(
            outpoint=outpoint,
            confirmed_height=confirmed_height,
            last_paid_height=last_paid_height,
            tier=tier,
            status=status,
            ip_address=ip_address
        ), offset


@dataclass
class FluxNodeData:
    """Represents a FluxNode's state - normalized for comparison"""
    tier: str
    ip_address: str
    confirmed_height: int
    last_paid_height: int
    collateral_outpoint: str
    status: str
    rank: int = -1

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for comparison"""
        return {
            'tier': self.tier,
            'ip_address': self.ip_address,
            'confirmed_height': self.confirmed_height,
            'last_paid_height': self.last_paid_height,
            'outpoint': self.collateral_outpoint,
            'status': self.status,
        }

    @classmethod
    def from_rpc(cls, node_data: Dict[str, Any]) -> 'FluxNodeData':
        """Create from RPC snapshot format"""
        return cls(
            tier=node_data.get('tier', ''),
            ip_address=node_data.get('ip', ''),
            confirmed_height=node_data.get('confirmed_height', 0),
            last_paid_height=node_data.get('last_paid_height', 0),
            collateral_outpoint=node_data.get('txhash', ''),
            status='CONFIRMED',  # RPC doesn't return status
            rank=node_data.get('rank', -1),
        )

    @classmethod
    def from_delta_entry(cls, entry: FluxNodeDeltaEntry) -> 'FluxNodeData':
        """Create from delta entry"""
        return cls(
            tier=entry.tier,
            ip_address=entry.ip_address,
            confirmed_height=entry.confirmed_height,
            last_paid_height=entry.last_paid_height,
            collateral_outpoint=entry.outpoint.txhash,
            status=entry.status,
        )


class FluxNodeStateValidator:
    def __init__(self, zmq_endpoint: str, rpc_conf: str, log_file: str, validation_interval: int = 100):
        self.zmq_endpoint = zmq_endpoint
        self.rpc_conf = rpc_conf
        self.log_file = log_file
        self.validation_interval = validation_interval

        # State tracking
        self.current_height: Optional[int] = None
        self.current_blockhash: Optional[str] = None
        self.node_list: Dict[str, FluxNodeData] = {}  # outpoint -> FluxNodeData
        self.pending_deltas: List[Dict] = []
        self.initialized = False
        self.last_validation_height = 0

        # Statistics
        self.deltas_applied = 0
        self.validations_performed = 0
        self.validations_passed = 0
        self.validations_failed = 0
        self.reorgs_handled = 0

    def log(self, message: str, level: str = "INFO"):
        """Log message to file and stdout"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)
        with open(self.log_file, 'a') as f:
            f.write(log_entry + '\n')

    def parse_flux_conf(self) -> dict:
        """Parse flux.conf to extract RPC credentials"""
        conf = {}
        conf_path = Path(self.rpc_conf)
        if not conf_path.exists():
            raise FileNotFoundError(f"flux.conf not found at {self.rpc_conf}")

        with open(conf_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        conf[key.strip()] = value.strip()

        return conf

    async def rpc_call(self, method: str, params: list = None) -> Any:
        """Make JSON-RPC call to fluxd"""
        if not hasattr(self, '_rpc_config'):
            self._rpc_config = self.parse_flux_conf()

        rpc_user = self._rpc_config.get('rpcuser', '')
        rpc_password = self._rpc_config.get('rpcpassword', '')
        rpc_port = self._rpc_config.get('rpcport', '16124')

        url = f"http://127.0.0.1:{rpc_port}/"
        headers = {'content-type': 'application/json'}
        payload = {
            'jsonrpc': '2.0',
            'id': 'flux-state-validator',
            'method': method,
            'params': params or []
        }

        auth = aiohttp.BasicAuth(rpc_user, rpc_password)

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, headers=headers, auth=auth) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise Exception(f"RPC HTTP error {response.status}: {error_text}")

                    result = await response.json()

                    if 'error' in result and result['error'] is not None:
                        raise Exception(f"RPC error: {result['error']}")

                    return result.get('result')
        except Exception as e:
            self.log(f"RPC call failed: {e}", "ERROR")
            raise

    async def get_snapshot(self) -> tuple[int, str, Dict[str, FluxNodeData]]:
        """Fetch current FluxNode snapshot from RPC"""
        self.log("Fetching snapshot from RPC...")
        snapshot = await self.rpc_call('getfluxnodesnapshot')

        height = snapshot.get('height', 0)
        blockhash = snapshot.get('blockhash', '')
        nodes = {}

        for node_data in snapshot.get('nodes', []):
            txhash = node_data.get('txhash', '')
            outidx = node_data.get('outidx', '')
            if txhash and outidx:
                # Use txhash:outidx as key to handle multiple outputs from same tx
                key = f"{txhash}:{outidx}"
                nodes[key] = FluxNodeData.from_rpc(node_data)

        self.log(f"Snapshot received: height {height}, blockhash {blockhash[:16]}..., {len(nodes)} nodes")
        return height, blockhash, nodes

    def parse_delta(self, data: bytes) -> Dict[str, Any]:
        """Parse fluxnodelistdelta ZMQ message (binary format with block hashes)"""
        if len(data) < 72:
            raise ValueError(f"Delta too short: {len(data)} bytes (need at least 72 for header)")

        # Parse header: from_height (4) + to_height (4) + from_hash (32) + to_hash (32)
        from_height, to_height = struct.unpack_from('<II', data, 0)

        # Daemon sends hashes in big-endian (display byte order) on wire
        # RPC GetBlockHash().GetHex() also returns big-endian
        # So we don't reverse - just take the bytes as-is
        from_blockhash = data[8:40].hex()
        to_blockhash = data[40:72].hex()

        offset = 72

        try:
            # Parse added nodes
            num_added, offset = read_compact_size(data, offset)
            added = []
            for i in range(num_added):
                try:
                    entry, offset = FluxNodeDeltaEntry.from_bytes(data, offset)
                    added.append(entry)
                except Exception as e:
                    raise ValueError(f"Error parsing added node {i+1}/{num_added} at offset {offset}: {e}")

            # Parse removed nodes
            num_removed, offset = read_compact_size(data, offset)
            removed = []
            for i in range(num_removed):
                try:
                    outpoint, offset = Outpoint.from_bytes(data, offset)
                    removed.append(str(outpoint))  # Use full txhash:index format
                except Exception as e:
                    raise ValueError(f"Error parsing removed node {i+1}/{num_removed} at offset {offset}: {e}")

            # Parse updated nodes
            num_updated, offset = read_compact_size(data, offset)
            updated = []
            for i in range(num_updated):
                try:
                    entry, offset = FluxNodeDeltaEntry.from_bytes(data, offset)
                    updated.append(entry)
                except Exception as e:
                    raise ValueError(f"Error parsing updated node {i+1}/{num_updated} at offset {offset}, data_len={len(data)}: {e}")

            return {
                'from_height': from_height,
                'to_height': to_height,
                'from_blockhash': from_blockhash,
                'to_blockhash': to_blockhash,
                'added': added,
                'removed': removed,
                'updated': updated,
            }
        except Exception as e:
            raise ValueError(f"Delta parse error (from={from_height}, to={to_height}, size={len(data)}): {e}")

    def parse_chainreorg(self, data: bytes) -> Dict[str, Any]:
        """Parse chainreorg ZMQ message (108 bytes)"""
        if len(data) != 108:
            raise ValueError(f"Invalid chainreorg size: {len(data)} bytes (expected 108)")

        # Daemon sends hashes in big-endian (display byte order) on wire
        # Don't reverse - take as-is to match RPC GetHex() format
        old_hash = data[0:32].hex()
        old_height = struct.unpack('<I', data[32:36])[0]
        new_hash = data[36:68].hex()
        new_height = struct.unpack('<I', data[68:72])[0]
        fork_hash = data[72:104].hex()
        fork_height = struct.unpack('<I', data[104:108])[0]

        return {
            'old_hash': old_hash,
            'old_height': old_height,
            'new_hash': new_hash,
            'new_height': new_height,
            'fork_hash': fork_hash,
            'fork_height': fork_height,
        }

    async def apply_delta(self, delta: Dict[str, Any]) -> bool:
        """Apply delta to local state. Returns True if applied, False if skipped."""
        from_height = delta['from_height']
        to_height = delta['to_height']
        from_blockhash = delta.get('from_blockhash', '')
        to_blockhash = delta.get('to_blockhash', '')

        # Validate delta
        if self.current_height is None:
            self.log(f"Cannot apply delta {from_height}→{to_height}: not initialized", "WARN")
            return False

        if from_height != self.current_height:
            if from_height < self.current_height:
                self.log(f"Skipping old delta: {from_height}→{to_height} (current: {self.current_height})", "WARN")
                return False
            else:
                self.log(f"GAP DETECTED! Current: {self.current_height}, Delta: {from_height}→{to_height}", "ERROR")
                self.log(f"  Current hash: {self.current_blockhash[:16] if self.current_blockhash else 'None'}...", "ERROR")
                self.log(f"  Delta from:   {from_blockhash[:16]}...", "ERROR")
                self.log(f"  Delta to:     {to_blockhash[:16]}...", "ERROR")
                self.log("Re-syncing from RPC...", "ERROR")
                await self.resync()
                return False

        # Validate block hash (reorg/fork detection)
        # Only validate if we have both hashes (skip for backward compat with old daemons)
        if self.current_blockhash and from_blockhash:
            if from_blockhash != self.current_blockhash:
                self.log(f"BLOCK HASH MISMATCH! Delta {from_height}→{to_height}", "ERROR")
                self.log(f"  Current  hash: {self.current_blockhash}", "ERROR")
                self.log(f"  Delta from:    {from_blockhash}", "ERROR")
                self.log(f"  Delta to:      {to_blockhash}", "ERROR")
                self.log("Fork/reorg detected - re-syncing!", "ERROR")
                await self.resync()
                return False

        # Apply changes
        added_count = 0
        for entry in delta['added']:
            # Use full outpoint (txhash:index) as key
            key = str(entry.outpoint)
            self.node_list[key] = FluxNodeData.from_delta_entry(entry)
            added_count += 1

        removed_count = 0
        for outpoint_str in delta['removed']:
            # outpoint_str is in format "txhash:index"
            if outpoint_str in self.node_list:
                del self.node_list[outpoint_str]
                removed_count += 1

        updated_count = 0
        for entry in delta['updated']:
            # Use full outpoint (txhash:index) as key
            key = str(entry.outpoint)
            self.node_list[key] = FluxNodeData.from_delta_entry(entry)
            updated_count += 1

        self.current_height = to_height
        self.current_blockhash = to_blockhash  # Update to the new block's hash
        self.deltas_applied += 1

        direction = "→" if to_height >= from_height else "←"
        self.log(f"Applied delta {from_height} {direction} {to_height} (hash: {to_blockhash[:16]}...): "
                f"+{added_count} -{removed_count} ~{updated_count} (total: {len(self.node_list)})")

        return True

    async def validate_state(self) -> bool:
        """Validate local state against RPC snapshot"""
        self.log("=" * 60)
        self.log("VALIDATION CHECKPOINT")
        self.log("=" * 60)

        try:
            snapshot_height, snapshot_blockhash, snapshot_nodes = await self.get_snapshot()

            # Check if height changed during validation
            if snapshot_height != self.current_height:
                self.log(f"Height mismatch: local={self.current_height}, snapshot={snapshot_height}", "WARN")
                self.log("New blocks arrived during validation - skipping", "WARN")
                return False

            # Check if block hash matches (reorg detection)
            if self.current_blockhash and snapshot_blockhash != self.current_blockhash:
                self.log(f"Block hash mismatch at height {snapshot_height} - reorg during validation!", "WARN")
                self.log(f"  Expected: {self.current_blockhash[:16]}...", "WARN")
                self.log(f"  Snapshot: {snapshot_blockhash[:16]}...", "WARN")
                self.log("Skipping validation - will retry after reorg delta applied", "WARN")
                return False

            self.validations_performed += 1

            # Compare node counts
            local_count = len(self.node_list)
            snapshot_count = len(snapshot_nodes)

            self.log(f"Node count - Local: {local_count}, Snapshot: {snapshot_count}")

            if local_count != snapshot_count:
                self.log(f"NODE COUNT MISMATCH!", "ERROR")
                self.validations_failed += 1
                self.log_discrepancy(snapshot_nodes)
                return False

            # Compare each node
            mismatches = []
            for outpoint, local_node in self.node_list.items():
                if outpoint not in snapshot_nodes:
                    mismatches.append(f"Node {outpoint[:16]}... exists locally but NOT in snapshot")
                    continue

                snapshot_node = snapshot_nodes[outpoint]
                local_dict = local_node.to_dict()
                snapshot_dict = snapshot_node.to_dict()

                # Compare fields
                for field in local_dict.keys():
                    if local_dict[field] != snapshot_dict[field]:
                        mismatches.append(
                            f"Node {outpoint[:16]}... field '{field}': "
                            f"local={local_dict[field]}, snapshot={snapshot_dict[field]}"
                        )

            # Check for nodes in snapshot but not local
            for outpoint in snapshot_nodes.keys():
                if outpoint not in self.node_list:
                    mismatches.append(f"Node {outpoint[:16]}... exists in snapshot but NOT locally")

            if mismatches:
                self.log(f"VALIDATION FAILED! Found {len(mismatches)} discrepancies:", "ERROR")
                for mismatch in mismatches[:20]:  # Log first 20
                    self.log(f"  - {mismatch}", "ERROR")
                if len(mismatches) > 20:
                    self.log(f"  ... and {len(mismatches) - 20} more", "ERROR")
                self.validations_failed += 1
                return False

            self.log("✓ VALIDATION PASSED - State matches snapshot perfectly!", "SUCCESS")
            self.validations_passed += 1
            self.last_validation_height = self.current_height
            return True

        except Exception as e:
            self.log(f"Validation error: {e}", "ERROR")
            self.validations_failed += 1
            return False

    def log_discrepancy(self, snapshot_nodes: Dict[str, FluxNodeData]):
        """Log detailed discrepancy information"""
        local_only = set(self.node_list.keys()) - set(snapshot_nodes.keys())
        snapshot_only = set(snapshot_nodes.keys()) - set(self.node_list.keys())

        if local_only:
            self.log(f"Nodes only in local state ({len(local_only)}):", "ERROR")
            for outpoint in list(local_only)[:10]:
                self.log(f"  - {outpoint}", "ERROR")

        if snapshot_only:
            self.log(f"Nodes only in snapshot ({len(snapshot_only)}):", "ERROR")
            for outpoint in list(snapshot_only)[:10]:
                node = snapshot_nodes.get(outpoint)
                if node:
                    self.log(f"  - {outpoint}  tier={node.tier} ip={node.ip_address} confirmed={node.confirmed_height} last_paid={node.last_paid_height} rank={node.rank}", "ERROR")
                else:
                    self.log(f"  - {outpoint}", "ERROR")

    async def resync(self):
        """Re-sync local state from RPC snapshot"""
        self.log("Re-syncing state from RPC...", "WARN")
        self.current_height, self.current_blockhash, self.node_list = await self.get_snapshot()
        self.last_validation_height = self.current_height
        self.log(f"Re-sync complete: height {self.current_height}, {len(self.node_list)} nodes")

    def handle_reorg(self, reorg_data: Dict[str, Any]):
        """Handle chainreorg event"""
        self.reorgs_handled += 1
        self.log("=" * 60, "REORG")
        self.log("CHAIN REORG DETECTED!", "REORG")
        self.log(f"  Old tip: {reorg_data['old_hash'][:16]}... (height {reorg_data['old_height']})", "REORG")
        self.log(f"  New tip: {reorg_data['new_hash'][:16]}... (height {reorg_data['new_height']})", "REORG")
        self.log(f"  Fork:    {reorg_data['fork_hash'][:16]}... (height {reorg_data['fork_height']})", "REORG")
        depth = reorg_data['old_height'] - reorg_data['fork_height']
        self.log(f"  Reorg depth: {depth} blocks", "REORG")
        self.log("=" * 60, "REORG")

        # The next delta will show the net result of the reorg
        # We just log it and wait for the delta

    async def initialize(self):
        """Initialize by getting snapshot and processing buffered deltas"""
        self.log("Initializing state...")
        self.current_height, self.current_blockhash, self.node_list = await self.get_snapshot()
        self.last_validation_height = self.current_height

        # Process buffered deltas
        if self.pending_deltas:
            self.log(f"Processing {len(self.pending_deltas)} buffered deltas...")
            self.pending_deltas.sort(key=lambda d: d['from_height'])

            applied = 0
            discarded = 0
            for delta in self.pending_deltas:
                if delta['to_height'] <= self.current_height:
                    discarded += 1
                    continue
                if await self.apply_delta(delta):
                    applied += 1

            self.log(f"Buffered deltas: {applied} applied, {discarded} discarded")
            self.pending_deltas = []

        self.initialized = True
        self.log("Initialization complete!")

    def print_stats(self):
        """Print current statistics"""
        self.log("-" * 60)
        self.log("STATISTICS")
        self.log(f"  Current height: {self.current_height}")
        self.log(f"  Nodes tracked: {len(self.node_list)}")
        self.log(f"  Deltas applied: {self.deltas_applied}")
        self.log(f"  Reorgs handled: {self.reorgs_handled}")
        self.log(f"  Validations: {self.validations_performed} "
                f"(✓ {self.validations_passed}, ✗ {self.validations_failed})")
        if self.validations_performed > 0:
            success_rate = (self.validations_passed / self.validations_performed) * 100
            self.log(f"  Success rate: {success_rate:.1f}%")
        self.log("-" * 60)

    async def run(self):
        """Main event loop"""
        self.log("=" * 60)
        self.log("FluxNode State Validator Starting")
        self.log(f"ZMQ Endpoint: {self.zmq_endpoint}")
        self.log(f"RPC Config: {self.rpc_conf}")
        self.log(f"Validation Interval: {self.validation_interval} blocks")
        self.log(f"Log File: {self.log_file}")
        self.log("=" * 60)

        # Set up ZMQ with async context
        context = zmq.asyncio.Context()
        socket = context.socket(zmq.SUB)
        socket.connect(self.zmq_endpoint)
        socket.subscribe(b'fluxnodelistdelta')
        socket.subscribe(b'chainreorg')

        self.log("✓ Subscribed to ZMQ events")

        # Initialize state
        await self.initialize()

        # Main loop
        try:
            while True:
                # Receive ZMQ message (async)
                parts = await socket.recv_multipart()
                topic, data, seq = parts[0], parts[1], parts[2]

                if topic == b'chainreorg':
                    try:
                        reorg_data = self.parse_chainreorg(data)
                        self.handle_reorg(reorg_data)
                    except Exception as e:
                        self.log(f"Error parsing chainreorg: {e}", "ERROR")

                elif topic == b'fluxnodelistdelta':
                    try:
                        delta = self.parse_delta(data)

                        if not self.initialized:
                            self.pending_deltas.append(delta)
                        else:
                            if await self.apply_delta(delta):
                                # Check if we should validate
                                if (self.current_height - self.last_validation_height) >= self.validation_interval:
                                    await self.validate_state()
                                    self.print_stats()
                    except Exception as e:
                        import traceback
                        self.log(f"Error processing delta (size={len(data)}): {e}", "ERROR")
                        self.log(f"Traceback: {traceback.format_exc()}", "ERROR")

        except KeyboardInterrupt:
            self.log("\nShutdown requested")
            self.print_stats()
            self.log("Validator stopped")
        finally:
            socket.close()
            context.term()


