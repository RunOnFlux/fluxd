"""FluxD ZMQ message decoders - Binary protocol parsing for hashblockheight, chainreorg, and fluxnodelistdelta."""

import struct


def read_compact_size(data, offset):
    """Read Bitcoin CompactSize variable-length integer."""
    if offset >= len(data):
        raise ValueError(f"Cannot read CompactSize at offset {offset} (buffer size {len(data)})")

    first = data[offset]
    if first < 0xfd:
        return first, offset + 1
    elif first == 0xfd:
        if offset + 3 > len(data):
            raise ValueError(f"Cannot read 2-byte CompactSize at offset {offset}")
        return struct.unpack_from('<H', data, offset + 1)[0], offset + 3
    elif first == 0xfe:
        if offset + 5 > len(data):
            raise ValueError(f"Cannot read 4-byte CompactSize at offset {offset}")
        return struct.unpack_from('<I', data, offset + 1)[0], offset + 5
    else:  # 0xff
        if offset + 9 > len(data):
            raise ValueError(f"Cannot read 8-byte CompactSize at offset {offset}")
        return struct.unpack_from('<Q', data, offset + 1)[0], offset + 9


def hash_to_hex(hash_bytes, reverse=False):
    """Convert hash bytes to hex string."""
    if reverse:
        hash_bytes = hash_bytes[::-1]
    return hash_bytes.hex()


def decode_hashblockheight(data):
    """Decode hashblockheight message (36 bytes)."""
    if len(data) != 36:
        return f"Invalid size: {len(data)} bytes"

    block_hash = hash_to_hex(data[0:32], reverse=True)
    height = struct.unpack('<I', data[32:36])[0]
    return f"Block #{height}: {block_hash}"


def decode_chainreorg(data):
    """Decode chainreorg message (108 bytes with fork hash)."""
    if len(data) != 108:
        return f"Invalid size: {len(data)} bytes"

    # All hashes are in display byte order (daemon reverses them)
    old_tip_hash = hash_to_hex(data[0:32])
    old_height = struct.unpack('<I', data[32:36])[0]
    new_tip_hash = hash_to_hex(data[36:68])
    new_height = struct.unpack('<I', data[68:72])[0]
    fork_hash = hash_to_hex(data[72:104])
    fork_height = struct.unpack('<I', data[104:108])[0]
    depth = old_height - fork_height

    return (f"\n  🔄 CHAIN REORG DETECTED!\n"
            f"  Old tip: {old_tip_hash[:16]}... (height {old_height})\n"
            f"  New tip: {new_tip_hash[:16]}... (height {new_height})\n"
            f"  Fork:    {fork_hash[:16]}... (height {fork_height})\n"
            f"  Reorg depth: {depth} blocks")


def decode_outpoint(data, offset):
    """Decode COutPoint (36 bytes: txid + index)."""
    if offset + 36 > len(data):
        raise ValueError(f"Not enough data for outpoint at offset {offset}")
    txid = hash_to_hex(data[offset:offset+32])
    index = struct.unpack('<I', data[offset+32:offset+36])[0]
    return f"{txid}:{index}", offset + 36


def decode_fluxnode_data(data, offset):
    """Decode FluxNode data from delta message."""
    try:
        outpoint, offset = decode_outpoint(data, offset)

        pubkey_len, offset = read_compact_size(data, offset)
        if offset + pubkey_len > len(data):
            raise ValueError(f"Not enough data for collateralPubkey (need {pubkey_len} bytes at offset {offset})")
        offset += pubkey_len

        pubkey2_len, offset = read_compact_size(data, offset)
        if offset + pubkey2_len > len(data):
            raise ValueError(f"Not enough data for pubKey (need {pubkey2_len} bytes at offset {offset})")
        offset += pubkey2_len

        if offset + 4 > len(data):
            raise ValueError(f"Not enough data for confirmed_height at offset {offset}")
        confirmed_height = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        if offset + 4 > len(data):
            raise ValueError(f"Not enough data for last_paid_height at offset {offset}")
        last_paid_height = struct.unpack_from('<I', data, offset)[0]
        offset += 4

        if offset + 1 > len(data):
            raise ValueError(f"Not enough data for tier at offset {offset}")
        tier = data[offset]
        tier_name = {1: "CUMULUS", 2: "NIMBUS", 3: "STRATUS"}.get(tier, f"UNKNOWN({tier})")
        offset += 1

        if offset + 1 > len(data):
            raise ValueError(f"Not enough data for status at offset {offset}")
        status = data[offset]
        status_name = {
            0: "ERROR",
            1: "STARTED",
            2: "DOS_PROTECTION",
            3: "CONFIRMED",
            4: "MISS_CONFIRMED",
            5: "EXPIRED"
        }.get(status, f"UNKNOWN({status})")
        offset += 1

        ip_len, offset = read_compact_size(data, offset)
        if offset + ip_len > len(data):
            raise ValueError(f"Not enough data for ip (need {ip_len} bytes at offset {offset})")
        ip = data[offset:offset+ip_len].decode('utf-8', errors='ignore')
        offset += ip_len
    except Exception as e:
        raise ValueError(f"Failed to decode FluxNode data at offset {offset}: {e}")

    return {
        'outpoint': outpoint,
        'tier': tier_name,
        'confirmed_height': confirmed_height,
        'last_paid_height': last_paid_height,
        'ip': ip,
        'status': status_name
    }, offset


def decode_fluxnodestatus(data):
    """Decode fluxnodestatus message (variable length, 54+ bytes)."""
    try:
        if len(data) < 54:
            return f"Invalid size: {len(data)} bytes (expected at least 54)"

        block_height = struct.unpack_from('<I', data, 0)[0]
        status = data[4]
        status_name = {
            0: "ERROR",
            1: "STARTED",
            2: "DOS_PROTECTION",
            3: "CONFIRMED",
            4: "MISS_CONFIRMED",
            5: "EXPIRED"
        }.get(status, f"UNKNOWN({status})")
        tier = data[5]
        tier_name = {1: "CUMULUS", 2: "NIMBUS", 3: "STRATUS"}.get(tier, f"UNKNOWN({tier})")
        confirmed_height = struct.unpack_from('<I', data, 6)[0]
        last_confirmed_height = struct.unpack_from('<I', data, 10)[0]
        last_paid_height = struct.unpack_from('<I', data, 14)[0]
        txhash = hash_to_hex(data[18:50])
        outidx = struct.unpack_from('<I', data, 50)[0]

        ip_len, offset = read_compact_size(data, 54)
        ip = data[offset:offset+ip_len].decode('utf-8', errors='ignore')
    except Exception as e:
        return f"Error decoding fluxnodestatus ({len(data)} bytes): {e}"

    return (f"\n  Status: {status_name} | Tier: {tier_name} | Block: {block_height}"
            f"\n  Outpoint: {txhash}:{outidx}"
            f"\n  IP: {ip}"
            f"\n  Confirmed: {confirmed_height} | LastConfirmed: {last_confirmed_height} | LastPaid: {last_paid_height}")


def decode_fluxnodelistdelta(data):
    """Decode fluxnodelistdelta message with block hashes and flags (73+ bytes)."""
    try:
        if len(data) < 73:
            return f"Invalid size: {len(data)} bytes (expected at least 73 for header)"

        # Parse header: from_height (4) + to_height (4) + from_hash (32) + to_hash (32) + flags (1)
        from_height = struct.unpack('<I', data[0:4])[0]
        to_height = struct.unpack('<I', data[4:8])[0]
        # Hashes are already in display byte order on wire (daemon sends them reversed)
        from_hash = hash_to_hex(data[8:40], reverse=False)
        to_hash = hash_to_hex(data[40:72], reverse=False)
        flags = data[72]
        is_reorg = bool(flags & 0x01)
        offset = 73

        num_added, offset = read_compact_size(data, offset)
        added = []
        for _ in range(num_added):
            node, offset = decode_fluxnode_data(data, offset)
            added.append(node)

        num_removed, offset = read_compact_size(data, offset)
        removed = []
        for _ in range(num_removed):
            outpoint, offset = decode_outpoint(data, offset)
            removed.append(outpoint)

        num_updated, offset = read_compact_size(data, offset)
        updated = []
        for _ in range(num_updated):
            node, offset = decode_fluxnode_data(data, offset)
            updated.append(node)
    except Exception as e:
        return (f"\n  ❌ Error decoding delta message (size={len(data)} bytes): {e}\n"
                f"  This may indicate a protocol mismatch or corrupt data.")

    reorg_label = " [REORG]" if is_reorg else ""
    result = f"\n  📊 FluxNode Delta: height {from_height} → {to_height}{reorg_label}"
    result += f"\n  From hash: {from_hash[:16]}..."
    result += f"\n  To hash:   {to_hash[:16]}..."
    result += f"\n  Summary: {len(added)} added, {len(removed)} removed, {len(updated)} updated"

    if added:
        result += f"\n\n  ✅ ADDED ({len(added)}):"
        for node in added:
            result += f"\n     • {node['tier']:8} @ {node['ip']:20} | Outpoint: {node['outpoint'][:32]}..."
            result += f"\n       Confirmed: {node['confirmed_height']:7} | LastPaid: {node['last_paid_height']:7} | Status: {node['status']}"

    if removed:
        result += f"\n\n  ❌ REMOVED ({len(removed)}):"
        for outpoint in removed:
            result += f"\n     • {outpoint}"

    if updated:
        result += f"\n\n  🔄 UPDATED ({len(updated)}):"
        for node in updated:
            result += f"\n     • {node['tier']:8} @ {node['ip']:20} | Outpoint: {node['outpoint'][:32]}..."
            result += f"\n       Confirmed: {node['confirmed_height']:7} | LastPaid: {node['last_paid_height']:7} | Status: {node['status']}"

    if not (added or removed or updated):
        result += " (no changes)"

    return result
