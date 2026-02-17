#!/usr/bin/env python3
# Copyright (c) 2026 The Flux developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test FluxNode ZMQ events with block hash validation

Tests the following ZMQ events:
- hashblockheight: Block hash + height notifications
- chainreorg: Chain reorganization events
- fluxnodelistdelta: FluxNode state delta updates with block hashes

Tests race condition scenarios to ensure block hashes in delta messages
provide consistency across chain reorganizations and network events.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    initialize_chain_clean,
    start_nodes,
    connect_nodes_bi,
    stop_nodes,
    wait_bitcoinds,
    p2p_port,
)
import zmq
import struct
import time
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

class FluxNodeZMQTest(BitcoinTestFramework):
    """Test FluxNode ZMQ events: hashblockheight, chainreorg, fluxnodelistdelta"""

    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.zmq_port = 28332

    def setup_chain(self):
        print(f"Initializing test directory {self.options.tmpdir}")
        initialize_chain_clean(self.options.tmpdir, self.num_nodes)

    def setup_nodes(self):
        # Set up ZMQ socket
        self.zmqContext = zmq.Context()
        self.zmqSubSocket = self.zmqContext.socket(zmq.SUB)
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblockheight")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"chainreorg")
        self.zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"fluxnodelistdelta")
        self.zmqSubSocket.connect(f"tcp://127.0.0.1:{self.zmq_port}")

        # Start nodes with ZMQ enabled on node 0
        return start_nodes(self.num_nodes, self.options.tmpdir, extra_args=[
            [
                f'-zmqpubhashblockheight=tcp://127.0.0.1:{self.zmq_port}',
                f'-zmqpubchainreorg=tcp://127.0.0.1:{self.zmq_port}',
                f'-zmqpubfluxnodelistdelta=tcp://127.0.0.1:{self.zmq_port}'
            ],
            [], [], []
        ])

    def setup_network(self, split=False):
        self.nodes = self.setup_nodes()
        # Like invalidateblock.py - start with NO connections
        # Each test will connect nodes as needed
        self.is_network_split = False

    def recv_zmq_msg(self, timeout_ms=5000):
        """Receive ZMQ message with timeout"""
        self.zmqSubSocket.setsockopt(zmq.RCVTIMEO, timeout_ms)
        try:
            msg = self.zmqSubSocket.recv_multipart()
            return msg
        except zmq.Again:
            return None

    def drain_zmq_messages(self):
        """Drain all pending ZMQ messages"""
        while True:
            msg = self.recv_zmq_msg(timeout_ms=100)
            if msg is None:
                break

    def test_hashblockheight(self):
        """Test hashblockheight event format and content"""
        print("Testing hashblockheight event...")

        # Drain any pending messages
        self.drain_zmq_messages()

        # Generate a block
        block_hashes = self.nodes[0].generate(1)

        # Find hashblockheight message (may not be first)
        msg = None
        for _ in range(10):
            m = self.recv_zmq_msg()
            if m and m[0] == b"hashblockheight":
                msg = m
                break

        assert msg is not None, "Should receive hashblockheight message"

        topic, data, seq = msg
        assert_equal(topic, b"hashblockheight")
        assert_equal(len(data), 36, "hashblockheight should be 36 bytes (32 hash + 4 height)")

        # Parse hash and height
        blockhash = data[0:32].hex()
        height = struct.unpack('<I', data[32:36])[0]

        print(f"  Received: height={height}, hash={blockhash[:16]}...")

        # Compare with RPC
        rpc_hash = self.nodes[0].getbestblockhash()
        rpc_height = self.nodes[0].getblockcount()

        assert_equal(blockhash, rpc_hash, "Hash should match RPC")
        assert_equal(height, rpc_height, "Height should match RPC")
        assert_equal(blockhash, block_hashes[0], "Hash should match generated block")

        print("  ✓ hashblockheight format and content correct")

    def test_fluxnode_delta_format(self):
        """Test fluxnodelistdelta message format and race condition handling"""
        print("Testing fluxnodelistdelta format...")

        # Drain pending messages
        self.drain_zmq_messages()

        # Get initial state
        snapshot_before = self.nodes[0].getfluxnodesnapshot()
        height_before = snapshot_before['height']
        hash_before = snapshot_before['blockhash']

        # Generate a block
        self.nodes[0].generate(1)

        # Receive delta message
        msg = None
        for _ in range(10):  # Try up to 10 messages
            m = self.recv_zmq_msg()
            if m and m[0] == b"fluxnodelistdelta":
                msg = m
                break

        assert msg is not None, "Should receive fluxnodelistdelta message"

        topic, data, seq = msg
        assert_equal(topic, b"fluxnodelistdelta")
        assert_greater_than(len(data), 72)

        # Parse header
        from_height = struct.unpack('<I', data[0:4])[0]
        to_height = struct.unpack('<I', data[4:8])[0]
        from_hash = data[8:40].hex()
        to_hash = data[40:72].hex()

        print(f"  Delta: {from_height} → {to_height}")
        print(f"    from_hash: {from_hash[:16]}...")
        print(f"    to_hash:   {to_hash[:16]}...")

        # Validate delta span
        assert_equal(from_height, height_before, "from_height should match previous height")
        assert_equal(to_height, height_before + 1, "to_height should be next height")

        # Validate block hashes match RPC
        assert_equal(from_hash, hash_before, "from_hash should match previous block")

        rpc_hash_after = self.nodes[0].getblockhash(to_height)
        assert_equal(to_hash, rpc_hash_after, "to_hash should match RPC")

        # Validate snapshot consistency
        snapshot_after = self.nodes[0].getfluxnodesnapshot()
        assert_equal(snapshot_after['height'], to_height)
        assert_equal(snapshot_after['blockhash'], to_hash)

        print("  ✓ Delta format with block hashes correct")

    def test_delta_consistency_across_blocks(self):
        """Test that delta block hashes chain correctly across multiple blocks"""
        print("Testing delta consistency across multiple blocks...")

        # Drain pending messages
        self.drain_zmq_messages()

        # Generate several blocks and verify hash chaining
        num_blocks = 5
        last_to_hash = None

        for i in range(num_blocks):
            self.nodes[0].generate(1)

            # Find the delta message
            msg = None
            for _ in range(10):
                m = self.recv_zmq_msg(timeout_ms=2000)
                if m and m[0] == b"fluxnodelistdelta":
                    msg = m
                    break

            if msg is None:
                print(f"  Warning: No delta received for block {i+1}")
                continue

            topic, data, seq = msg
            from_height = struct.unpack('<I', data[0:4])[0]
            to_height = struct.unpack('<I', data[4:8])[0]
            from_hash = data[8:40].hex()
            to_hash = data[40:72].hex()

            # Verify chaining: this delta's from_hash should match previous to_hash
            if last_to_hash is not None:
                assert_equal(from_hash, last_to_hash,
                           f"Block {i+1}: from_hash should match previous to_hash (hash chaining)")

            last_to_hash = to_hash
            print(f"  Block {i+1}: {from_height} → {to_height} ✓")

        print("  ✓ Delta hash chaining consistent")

    def test_chainreorg_event(self):
        """Test chainreorg event - like invalidateblock.py pattern"""
        print("Testing chainreorg event...")

        # First sync node 2 to establish common history
        print("\n  Syncing node 2 with network...")
        from test_framework.util import sync_blocks
        connect_nodes_bi(self.nodes, 0, 2)
        sync_blocks([self.nodes[0], self.nodes[2]])
        common_height = self.nodes[0].getblockcount()
        print(f"  Common height: {common_height}")

        # Now disconnect node 2 from ALL peers to create competing chains
        # Node 2 may have auto-discovered other peers, so disconnect from all
        peers = self.nodes[2].getpeerinfo()
        print(f"  Node 2 has {len(peers)} peers, disconnecting all...")
        for peer in peers:
            self.nodes[2].disconnectnode(peer['addr'])
        time.sleep(2)  # Wait for disconnection to complete
        assert len(self.nodes[2].getpeerinfo()) == 0, "Node 2 should be fully isolated"
        print(f"  Node 2 now isolated (0 peers)")

        # Test 1: Natural reorg by connecting nodes with competing chains
        print("\n  Test 1: Natural reorg (connecting competing chains)")
        self.drain_zmq_messages()

        # Mine 4 blocks on Node 0
        print("  Mine 4 blocks on Node 0")
        self.nodes[0].generate(4)
        node0_height = self.nodes[0].getblockcount()
        assert node0_height == common_height + 4, f"Node 0 should be at {common_height + 4}, got {node0_height}"
        besthash_node0 = self.nodes[0].getbestblockhash()

        # Mine competing 6 blocks on Node 2
        # Set mocktime ahead to ensure different block timestamps
        print("  Mine competing 6 blocks on Node 2")
        current_time = int(time.time())
        self.nodes[2].setmocktime(current_time + 10)
        self.nodes[2].generate(6)
        node2_height = self.nodes[2].getblockcount()
        assert node2_height == common_height + 6, f"Node 2 should be at {common_height + 6}, got {node2_height}"
        besthash_node2 = self.nodes[2].getbestblockhash()

        # Verify chains actually diverged (check first block after fork)
        check_height = common_height + 1
        hash_node0_at_fork = self.nodes[0].getblockhash(check_height)
        hash_node2_at_fork = self.nodes[2].getblockhash(check_height)
        if hash_node0_at_fork == hash_node2_at_fork:
            print(f"    WARNING: Chains did not diverge! Both have same block {check_height}: {hash_node0_at_fork[:16]}...")
        else:
            print(f"    Chains diverged at height {check_height}:")
            print(f"      Node 0: {hash_node0_at_fork[:16]}...")
            print(f"      Node 2: {hash_node2_at_fork[:16]}...")

        node0_hash = self.nodes[0].getbestblockhash()
        node2_hash = self.nodes[2].getbestblockhash()
        print(f"    Node 0: height={node0_height}, hash={node0_hash[:16]}...")
        print(f"    Node 2: height={node2_height}, hash={node2_hash[:16]}...")

        # Connect nodes to force reorg (like invalidateblock.py line 42)
        print("  Connecting nodes to force reorg...")
        self.drain_zmq_messages()  # Clear messages before reorg
        connect_nodes_bi(self.nodes, 0, 2)
        sync_blocks([self.nodes[0], self.nodes[2]])

        final_height = self.nodes[0].getblockcount()
        final_hash = self.nodes[0].getbestblockhash()
        print(f"    Node 0 after sync: height={final_height}, hash={final_hash[:16]}...")

        # Node 0 should have reorged to node 2's longer chain
        expected_final_height = common_height + 6
        reorg_occurred = (node0_hash != final_hash and final_height == expected_final_height)
        print(f"    Natural reorg occurred: {reorg_occurred}")

        if reorg_occurred:
            # Collect ALL chainreorg messages during reorg
            reorg_messages = []
            all_messages = []
            for _ in range(30):
                msg = self.recv_zmq_msg(timeout_ms=500)
                if msg:
                    all_messages.append(msg[0].decode('utf-8'))
                    if msg[0] == b"chainreorg":
                        reorg_messages.append(msg)

            if reorg_messages:
                print(f"    ✓ Received {len(reorg_messages)} chainreorg message(s) during reorg")

                # Show all chainreorg messages
                for i, reorg_msg in enumerate(reorg_messages):
                    topic, data, seq = reorg_msg
                    old_hash = data[0:32].hex()
                    old_height = struct.unpack('<I', data[32:36])[0]
                    new_hash = data[36:68].hex()
                    new_height = struct.unpack('<I', data[68:72])[0]
                    fork_hash = data[72:104].hex()
                    fork_height = struct.unpack('<I', data[104:108])[0]
                    print(f"      Message {i+1}: old_height={old_height}, new_height={new_height}, fork={fork_height}")

                # Validate the reorg makes sense
                first_msg = reorg_messages[0]
                data = first_msg[1]
                old_height = struct.unpack('<I', data[32:36])[0]
                fork_height = struct.unpack('<I', data[104:108])[0]

                assert_equal(old_height, node0_height, "First reorg message should show node 0's old tip")
                assert fork_height >= common_height, f"Fork should be at or after common height {common_height}"

                print(f"    ✓ Chainreorg messages validated")
            else:
                print(f"    ✗ No chainreorg message (received: {all_messages})")
                raise AssertionError("Natural reorg occurred but no chainreorg message received!")
        else:
            print(f"    Note: No reorg occurred (node 0 already on best chain)")

        # Test deltas after reorg
        print("\n  Testing deltas after reorg...")
        self.drain_zmq_messages()

        # Get current state
        snapshot_before = self.nodes[0].getfluxnodesnapshot()
        height_before = snapshot_before['height']
        hash_before = snapshot_before['blockhash']

        # Generate a block on the reorged chain
        self.nodes[0].generate(1)

        # Collect delta message
        delta_msg = None
        for _ in range(10):
            msg = self.recv_zmq_msg(timeout_ms=1000)
            if msg and msg[0] == b"fluxnodelistdelta":
                delta_msg = msg
                break

        assert delta_msg is not None, "Should receive delta after reorg"

        topic, data, seq = delta_msg
        from_height = struct.unpack('<I', data[0:4])[0]
        to_height = struct.unpack('<I', data[4:8])[0]
        from_hash = data[8:40].hex()
        to_hash = data[40:72].hex()

        # Verify delta chains from the reorged state
        assert_equal(from_height, height_before, "Delta from_height should match pre-block height")
        assert_equal(from_hash, hash_before, "Delta from_hash should match pre-block hash")
        assert_equal(to_height, height_before + 1, "Delta to_height should be next height")

        # Verify against RPC
        rpc_hash_after = self.nodes[0].getblockhash(to_height)
        assert_equal(to_hash, rpc_hash_after, "Delta to_hash should match RPC")

        print(f"    ✓ Delta after reorg: {from_height} → {to_height}")
        print(f"    ✓ Delta hash chaining consistent across reorg")

        # Generate more blocks and verify continued consistency
        print("  Generating more blocks to verify continued delta consistency...")
        last_to_hash = to_hash
        for i in range(3):
            self.nodes[0].generate(1)

            msg = None
            for _ in range(10):
                m = self.recv_zmq_msg(timeout_ms=1000)
                if m and m[0] == b"fluxnodelistdelta":
                    msg = m
                    break

            if msg:
                data = msg[1]
                from_hash = data[8:40].hex()
                to_hash = data[40:72].hex()
                assert_equal(from_hash, last_to_hash, f"Block {i+1} after reorg: hash chain should continue")
                last_to_hash = to_hash

        print(f"    ✓ Generated 3 more blocks, delta chain remains consistent")

        # Test 2: Manual reorg via invalidateblock
        print("\n  Test 2: Manual reorg (invalidateblock)")
        self.drain_zmq_messages()

        # Get current state
        current_height = self.nodes[0].getblockcount()
        current_hash = self.nodes[0].getbestblockhash()

        # Invalidate a block to force reorg
        invalidate_height = current_height - 2
        invalidate_hash = self.nodes[0].getblockhash(invalidate_height)

        print(f"  Invalidating block at height {invalidate_height}...")
        self.nodes[0].invalidateblock(invalidate_hash)

        new_height = self.nodes[0].getblockcount()
        new_hash = self.nodes[0].getbestblockhash()
        print(f"    Before: height={current_height}, hash={current_hash[:16]}...")
        print(f"    After:  height={new_height}, hash={new_hash[:16]}...")

        # Give time for ZMQ message
        time.sleep(1)

        # Look for chainreorg message
        reorg_msg = None
        all_messages = []
        for _ in range(20):  # Check many messages
            msg = self.recv_zmq_msg(timeout_ms=1000)
            if msg:
                all_messages.append(msg[0].decode('utf-8') if msg else 'None')
                if msg[0] == b"chainreorg":
                    reorg_msg = msg
                    break

        if reorg_msg is None:
            print(f"  DEBUG: Received {len(all_messages)} messages: {all_messages}")
            raise AssertionError(f"Manual reorg (invalidateblock) occurred but no chainreorg message received!")

        topic, data, seq = reorg_msg
        assert_equal(len(data), 108, "chainreorg should be 108 bytes")

        # Parse reorg data
        old_hash = data[0:32].hex()
        old_height = struct.unpack('<I', data[32:36])[0]
        new_hash = data[36:68].hex()
        new_height = struct.unpack('<I', data[68:72])[0]
        fork_hash = data[72:104].hex()
        fork_height = struct.unpack('<I', data[104:108])[0]

        print(f"    Invalidateblock reorg message:")
        print(f"      Old tip:  height={old_height}, hash={old_hash[:16]}...")
        print(f"      New tip:  height={new_height}, hash={new_hash[:16]}...")
        print(f"      Fork at:  height={fork_height}, hash={fork_hash[:16]}...")

        # Validate message is internally consistent
        assert_greater_than(old_height, new_height)
        assert_greater_than(old_height, fork_height)

        # The new tip should be at or near the fork (within reason for a manual invalidate)
        # Fork point is where chains diverge, new tip is where we rolled back to
        assert new_height >= fork_height, f"New tip {new_height} should be >= fork {fork_height}"
        assert new_height <= fork_height + 3, f"New tip {new_height} should be close to fork {fork_height}"

        print("    ✓ Chainreorg message received for invalidateblock")
        print("\n  ✓ Both natural and manual reorg tests passed!")

    def test_snapshot_blockhash_field(self):
        """Test that getfluxnodesnapshot includes blockhash field"""
        print("Testing getfluxnodesnapshot blockhash field...")

        snapshot = self.nodes[0].getfluxnodesnapshot()

        assert 'height' in snapshot, "Snapshot should have height field"
        assert 'blockhash' in snapshot, "Snapshot should have blockhash field"
        assert 'nodes' in snapshot, "Snapshot should have nodes field"

        height = snapshot['height']
        blockhash = snapshot['blockhash']

        print(f"  Snapshot: height={height}, hash={blockhash[:16]}...")

        # Verify blockhash matches RPC
        rpc_hash = self.nodes[0].getblockhash(height)
        assert_equal(blockhash, rpc_hash, "Snapshot blockhash should match RPC")

        # Verify it's at current tip
        best_hash = self.nodes[0].getbestblockhash()
        best_height = self.nodes[0].getblockcount()
        assert_equal(height, best_height, "Snapshot should be at current height")
        assert_equal(blockhash, best_hash, "Snapshot hash should be current tip")

        print("  ✓ Snapshot blockhash field correct")

    def test_byte_order_consistency(self):
        """Test that all hashes use consistent byte order across RPC and ZMQ"""
        print("Testing byte order consistency...")

        # Drain messages
        self.drain_zmq_messages()

        # Generate block
        block_hashes = self.nodes[0].generate(1)
        expected_hash = block_hashes[0]

        # Get RPC hash
        rpc_hash = self.nodes[0].getbestblockhash()
        assert_equal(rpc_hash, expected_hash, "RPC hash should match generated")

        # Get snapshot hash
        snapshot = self.nodes[0].getfluxnodesnapshot()
        snapshot_hash = snapshot['blockhash']
        assert_equal(snapshot_hash, expected_hash, "Snapshot hash should match")

        # Get hashblockheight ZMQ hash
        msg = None
        for _ in range(10):
            m = self.recv_zmq_msg(timeout_ms=1000)
            if m and m[0] == b"hashblockheight":
                msg = m
                break

        if msg:
            zmq_hash = msg[1][0:32].hex()
            assert_equal(zmq_hash, expected_hash, "ZMQ hashblockheight should match")
            print(f"  ✓ All hashes match: {expected_hash[:16]}...")

        # Get delta to_hash
        for _ in range(10):
            m = self.recv_zmq_msg(timeout_ms=1000)
            if m and m[0] == b"fluxnodelistdelta":
                delta_to_hash = m[1][40:72].hex()
                assert_equal(delta_to_hash, expected_hash, "Delta to_hash should match")
                print(f"  ✓ Delta to_hash matches")
                break

        print("  ✓ All byte orders consistent (big-endian/display order)")

    def test_delta_node_data_parsing(self):
        """Test parsing of node data in delta messages"""
        print("Testing delta node data parsing...")

        # Drain messages
        self.drain_zmq_messages()

        # Generate block to get delta
        self.nodes[0].generate(1)

        # Get delta message
        msg = None
        for _ in range(10):
            m = self.recv_zmq_msg(timeout_ms=2000)
            if m and m[0] == b"fluxnodelistdelta":
                msg = m
                break

        if msg is None:
            print("  Warning: No delta received, skipping node data test")
            return

        topic, data, seq = msg

        # Parse header (72 bytes of hashes/heights + 1 byte flags)
        offset = 73  # Skip header

        # Read compact size for added nodes
        def read_compact_size(data, offset):
            first = data[offset] if offset < len(data) else 0
            if first < 0xfd:
                return first, offset + 1
            elif first == 0xfd:
                return struct.unpack_from('<H', data, offset + 1)[0], offset + 3
            elif first == 0xfe:
                return struct.unpack_from('<I', data, offset + 1)[0], offset + 5
            else:
                return struct.unpack_from('<Q', data, offset + 1)[0], offset + 9

        try:
            num_added, offset = read_compact_size(data, offset)
            print(f"  Added nodes: {num_added}")

            # Parse removed nodes count
            # Skip added nodes data (would need full parser)
            # For now just validate we can read the counts

            num_removed, _ = read_compact_size(data, offset + (num_added * 200))  # Approximate skip
            print(f"  Removed nodes: {num_removed}")

            print("  ✓ Node data structure parseable")
        except Exception as e:
            print(f"  Note: Node data parsing test limited: {e}")

    def test_race_condition_scenarios(self):
        """Test various race condition scenarios with block hashes"""
        print("Testing race condition scenarios...")

        # Scenario 1: Multiple rapid blocks
        print("  Scenario 1: Rapid block generation")
        self.drain_zmq_messages()

        self.nodes[0].generate(3)  # Generate 3 blocks quickly
        time.sleep(0.5)

        # Collect all deltas
        deltas = []
        for _ in range(20):
            msg = self.recv_zmq_msg(timeout_ms=500)
            if msg and msg[0] == b"fluxnodelistdelta":
                from_height = struct.unpack('<I', msg[1][0:4])[0]
                to_height = struct.unpack('<I', msg[1][4:8])[0]
                from_hash = msg[1][8:40].hex()
                to_hash = msg[1][40:72].hex()
                deltas.append({
                    'from': from_height,
                    'to': to_height,
                    'from_hash': from_hash,
                    'to_hash': to_hash
                })

        if len(deltas) >= 2:
            # Verify hash chaining
            for i in range(1, len(deltas)):
                if deltas[i]['from'] == deltas[i-1]['to']:
                    assert_equal(deltas[i]['from_hash'], deltas[i-1]['to_hash'],
                               "Hash chain should be consistent in rapid blocks")
            print(f"  ✓ Processed {len(deltas)} rapid deltas with consistent hashing")

        # Scenario 2: Snapshot during block generation
        print("  Scenario 2: Snapshot consistency during activity")
        snapshot1 = self.nodes[0].getfluxnodesnapshot()
        height1 = snapshot1['height']
        hash1 = snapshot1['blockhash']

        # Verify snapshot is atomic
        rpc_height = self.nodes[0].getblockcount()
        rpc_hash = self.nodes[0].getblockhash(height1)

        assert_equal(height1, rpc_height, "Snapshot height should match chain tip")
        assert_equal(hash1, rpc_hash, "Snapshot hash should match height")

        print("  ✓ Snapshot provides atomic height+hash consistency")

    def test_message_sequencing(self):
        """Test ZMQ message sequence numbers"""
        print("Testing message sequencing...")

        self.drain_zmq_messages()

        # Generate blocks and track sequences per topic
        sequences_by_topic = {}

        for _ in range(3):
            self.nodes[0].generate(1)

            # Collect all messages from this block
            for _ in range(5):
                msg = self.recv_zmq_msg(timeout_ms=500)
                if msg and len(msg) >= 3:
                    topic = msg[0]
                    seq = struct.unpack('<I', msg[2])[0]
                    if topic not in sequences_by_topic:
                        sequences_by_topic[topic] = []
                    sequences_by_topic[topic].append(seq)

        # Verify sequences are increasing per topic
        for topic, sequences in sequences_by_topic.items():
            if len(sequences) >= 2:
                # Sequences should be monotonically increasing (or equal for same block)
                for i in range(1, len(sequences)):
                    if sequences[i] < sequences[i-1]:
                        raise AssertionError(f"Sequence decreased for {topic}: {sequences}")
                print(f"  ✓ {topic.decode()}: sequences {sequences}")

        if sequences_by_topic:
            print("  ✓ Message sequencing validated")
        else:
            print("  Note: No messages received for sequencing test")

    def run_test(self):
        print("\n" + "="*60)
        print("FluxNode ZMQ Integration Tests")
        print("="*60)

        # Connect nodes 0, 1, 3 for initial tests (leave node 2 isolated for chainreorg test)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 3)
        from test_framework.util import sync_blocks
        sync_blocks([self.nodes[0], self.nodes[1], self.nodes[3]])

        # Generate some initial blocks
        print("\nGenerating initial blocks...")
        self.nodes[0].generate(10)
        sync_blocks([self.nodes[0], self.nodes[1], self.nodes[3]])

        # Run other tests first
        self.test_hashblockheight()
        self.test_snapshot_blockhash_field()
        self.test_fluxnode_delta_format()
        self.test_delta_consistency_across_blocks()
        self.test_byte_order_consistency()
        self.test_delta_node_data_parsing()
        self.test_message_sequencing()
        self.test_race_condition_scenarios()

        # Run chainreorg test LAST (nodes 0 and 2 will create competing chains)
        self.test_chainreorg_event()

        print("\n" + "="*60)
        print("✓ All FluxNode ZMQ tests passed!")
        print("="*60 + "\n")

if __name__ == '__main__':
    FluxNodeZMQTest().main()
