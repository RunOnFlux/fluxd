"""Shielded keys round-trip through z_exportkey/import and z_exportwallet/import.

A single Sapling spending key exported from one node imports cleanly into
another, and a full wallet dump carries every transparent, Sprout and Sapling
key (with the HD seed header and per-key metadata) so that importing it onto a
fresh node reproduces the same shielded addresses.
"""

from pathlib import Path

from conftest import NodeFactory


def _parse_wallet_section(lines: list[str], i: int) -> tuple[str, int]:
    """Collect one block of key lines, skipping leading blank/comment lines."""
    while i < len(lines) and (lines[i] == "\n" or lines[i].startswith("#")):
        i += 1
    keys: list[str] = []
    while i < len(lines) and not (lines[i] == "\n" or lines[i].startswith("#")):
        keys.append(lines[i])
        i += 1
    return "".join(keys), i


def _parse_wallet_file(dump_path: str) -> tuple[str, str, str]:
    """Split a z_exportwallet dump into (transparent, sprout, sapling) sections."""
    lines = Path(dump_path).read_text().splitlines(keepends=True)
    # The header carries the HD seed and its fingerprint, which must differ.
    assert "HDSeed" in lines[4], "expected HDSeed in dump header"
    assert "fingerprint" in lines[4], "expected fingerprint in dump header"
    seed, fingerprint = lines[4][2:].split()
    assert seed.split("=")[1] != fingerprint.split("=")[1]

    t_keys, i = _parse_wallet_section(lines, 0)
    sprout_keys, i = _parse_wallet_section(lines, i)
    sapling_keys, _ = _parse_wallet_section(lines, i)
    return t_keys, sprout_keys, sapling_keys


async def test_shielded_key_and_wallet_import_export(
    node_factory: NodeFactory, tmp_path: Path
) -> None:
    nodes = [await node_factory(i, extra_args=[f"-exportdir={tmp_path}/node{i}"]) for i in range(3)]

    # A single Sapling key exported from node 2 imports into node 0.
    sapling_address2 = await nodes[2].rpc.z_getnewaddress("sapling")
    privkey2 = await nodes[2].rpc.z_exportkey(sapling_address2)
    await nodes[0].rpc.z_importkey(privkey2)

    sprout_address0 = await nodes[0].rpc.z_getnewaddress("sprout")
    sapling_address0 = await nodes[0].rpc.z_getnewaddress("sapling")

    dump0 = await nodes[0].rpc.z_exportwallet("walletdump")
    _, sprout_keys0, sapling_keys0 = _parse_wallet_file(dump0)

    # Two Sapling keys: the locally generated one (4 params: key, addr, time,
    # HD path) and the imported one (2 params: key, addr).
    sapling_line_lengths = [len(line.split(" #")[0].split()) for line in sapling_keys0.splitlines()]
    assert len(sapling_line_lengths) == 2, "should have 2 sapling keys"
    assert 2 in sapling_line_lengths, "should have a key with 2 parameters"
    assert 4 in sapling_line_lengths, "should have a key with 4 parameters"

    assert sprout_address0 in sprout_keys0
    assert sapling_address0 in sapling_keys0
    assert sapling_address2 in sapling_keys0

    # Node 1 starts without node 0's keys.
    dump1_before = await nodes[1].rpc.z_exportwallet("walletdumpbefore")
    _, sprout_keys1, sapling_keys1 = _parse_wallet_file(dump1_before)
    assert sprout_address0 not in sprout_keys1
    assert sapling_address0 not in sapling_keys1

    # Importing node 0's dump gives node 1 every key, metadata preserved.
    await nodes[1].rpc.z_importwallet(dump0)
    dump1_after = await nodes[1].rpc.z_exportwallet("walletdumpafter")
    _, sprout_keys1, sapling_keys1 = _parse_wallet_file(dump1_after)
    assert sprout_address0 in sprout_keys1
    assert sapling_address0 in sapling_keys1
    assert sapling_address2 in sapling_keys1
    for sapling_key0 in sapling_keys0.splitlines():
        assert sapling_key0 in sapling_keys1
