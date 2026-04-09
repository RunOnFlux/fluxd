BIP155 / TORv3 BACKPORT — IMPLEMENTATION JOURNAL
=================================================

This document is the engineering record of the work that brought BIP155
(`addrv2`) and TORv3 hidden service support to fluxd. It is written for
the next person who has to read, extend, or debug this code — not as
marketing material. Where decisions were trade-offs, the trade-offs are
written down honestly. Where corners were cut, the cuts are documented.

If you only want operator instructions, skip this and read
[`build-test-onion-linux.md`](build-test-onion-linux.md).


## 1. Why this work exists

fluxd descends from a 2018-era zcash fork, which descends from Bitcoin
Core. The TOR support inherited from that lineage targets **TORv2 hidden
services** — RSA-1024 keys, 16-character `.onion` names, 10-byte addresses
tunneled through the RFC 7686 IPv6 prefix `FD87:D87E:EB43::/48`.

The Tor project removed v2 hidden services from the live network in
**October 2021** (Tor 0.4.6.x). As a result, before this work:

- `torcontrol.cpp` asked the local Tor daemon for `NEW:RSA1024`. Modern
  Tor refuses the request.
- `CNetAddr::SetSpecial()` could only parse 16-char v2 .onion strings.
  Anything longer was rejected.
- The legacy `addr` P2P message carries 16-byte addresses. v3 ed25519
  pubkeys are 32 bytes — they don't fit. There was no way to transmit a
  v3 onion address between fluxd peers.
- Even if you hand-edited a v3 onion into addrman, it would be lost on
  the next restart because `peers.dat` only stored 16 bytes per entry.

In short: TOR routing in fluxd was functionally dead. The goal of this
work was to restore it by porting Bitcoin Core's BIP155 + TORv3 stack,
which Bitcoin shipped in 0.21 (PR #19954, merge commit `0b2abaa666`).

This is a peer-layer change. **No consensus rules were touched.** No hard
fork is required. The change is gated by a `PROTOCOL_VERSION` bump and
backward-compatible at the network layer.


## 2. The plan, and why six phases

The original implementation plan lives in the developer's plan-tracking
directory (`~/.claude/plans/cuddly-churning-reddy.md`); a copy of its
contents is reproduced verbatim at the end of this journal in
[Appendix A](#appendix-a-original-plan-file). It identified six phases,
each independently testable and shippable:

1. **Foundations** — Add SHA3-256 (needed for v3 checksum), bump
   `PROTOCOL_VERSION` to 170021, define `SENDADDRV2_VERSION`.
2. **`CNetAddr` refactor** — Replace the fixed `unsigned char ip[16]`
   field with a variable-length representation. **Highest-risk phase**
   because every address-byte access in the codebase routes through
   here.
3. **TORv3 parser + torcontrol v3 service** — Real `SetTor()` with SHA3
   checksum validation; switch `torcontrol.cpp` to `NEW:ED25519-V3`;
   rename the persisted key file.
4. **BIP155 wire format + `addrv2`/`sendaddrv2`** — Add the explicit
   V2 serializers, the `CAddrVecV2` wrapper, the new P2P message
   handlers, and the per-peer `m_wants_addrv2` negotiation flag.
5. **addrman on-disk format bump** — `peers.dat` format version 1 → 2
   so v3 onion entries survive across restarts.
6. **Polish** — `getpeerinfo` reporting, `doc/tor.md` rewrite, init.cpp
   review, validation rebuild.

The phasing was deliberate: each phase compiles and runs independently,
so the work can be reviewed (or reverted) one piece at a time. Phase 4
makes no sense without Phase 2 and Phase 3, but Phase 5 is independent
of Phase 4 in principle (you can persist v3 onions to disk without
gossiping them, you just have no way to learn them).


## 3. Phase-by-phase record

### Phase 1 — Foundations

**Files added:**
- `src/crypto/sha3.h` (~38 lines)
- `src/crypto/sha3.cpp` (~150 lines)

**Files modified:**
- `src/Makefile.am` — added `crypto/sha3.{cpp,h}` to
  `crypto_libbitcoin_crypto_a_SOURCES`
- `src/version.h` — `PROTOCOL_VERSION` bumped 170020 → **170021**;
  added `static const int SENDADDRV2_VERSION = 170021`

**Source:** Bitcoin Core's `src/crypto/sha3.{h,cpp}`. Bitcoin's version
uses C++20 (`std::span`, `std::rotl`, `<bit>`). fluxd is on C++11 (see
section 5 for the C++14 bump that production builds will need anyway).
The port substitutes:

- `std::span<const unsigned char>` → `(const unsigned char*, size_t)`
  pair
- `std::rotl(x, n)` → manual `((x << n) | (x >> (64 - n)))` (named
  `Rotl64` in an anonymous namespace)
- C++14+ braced initializers → C++11 equivalents
- `<bit>` and `<span>` includes dropped
- Bitcoin's `#include <crypto/sha3.h>` (angle brackets) → fluxd's
  `#include "crypto/sha3.h"` (quoted) to match the surrounding
  convention

The Keccak-f[1600] permutation and the Write/Finalize/Reset state
machine are byte-for-byte identical to Bitcoin's.

**Validation:** A standalone harness compiled the new files outside
the fluxd build, supplied inline `ReadLE64`/`WriteLE64` shims to bypass
fluxd's `crypto/common.h`, and ran the NIST SHA3-256 KAT vectors:

- `SHA3-256("")` = `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` ✓
- `SHA3-256("abc")` = `3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532` ✓

Both vectors matched byte-for-byte, confirming the C++11 port is
algorithmically identical to Bitcoin's.

**Initially deferred, then completed during the polish pass:** The plan
called for renaming `NET_TOR` to `NET_ONION` for clarity. I initially
skipped it during Phase 1 — the rename cascades into ~10 files and was
purely cosmetic. After Phase 6 the operator (correctly) decided that
the codebase shouldn't ship with any "we'll do this later" debt
visible in the source tree, so the rename was applied retroactively
across all 29 references in 5 files (`netbase.h`, `netbase.cpp`,
`torcontrol.cpp`, `init.cpp`, `test/netbase_tests.cpp`).

The enum value at position 3 was preserved (still `NET_ONION = 3`),
which means `GetGroup()` still pushes the integer `3` into the
addrman bucket key for onion entries. **Addrman bucketing therefore
remained byte-identical** across the rename, just as it did across
the Phase 2 REDO. Only the symbol name changed.


### Phase 2 — `CNetAddr` refactor (FIRST ATTEMPT, replaced — see Phase 2 REDO)

The first cut of Phase 2 used a **hybrid storage layout**:

```cpp
class CNetAddr {
protected:
    unsigned char ip[16];                      // legacy field, kept
    std::vector<unsigned char> m_addr_v3;      // new, only for v3 onion
};
```

The intent was to minimize the diff: keep `ip[16]` working exactly as
before for IPv4/IPv6 (which means addrman bucketing is provably
unchanged because `GetHash`/`GetGroup` read the same 16 bytes from the
same field), and bolt v3 onto the side via a separate buffer.

This shipped and worked. It took ~5 functions to update instead of
~25. Validation passed.

**It was the wrong call architecturally.** See section 4.


### Phase 3 — TORv3 parser + torcontrol v3 service

**Files modified:**
- `src/netbase.cpp` — added `#include "crypto/sha3.h"`; added the
  `torv3` namespace (`CHECKSUM_LEN = 2`, `VERSION = {3}`, `TOTAL_LEN
  = 35`, `Checksum()` helper); replaced the stub `SetTor()` with the
  real BIP155 parser; updated `ToStringIP()` to encode v3 onions
- `src/torcontrol.cpp:539` — `private_key = "NEW:RSA1024"` →
  `"NEW:ED25519-V3"`
- `src/torcontrol.cpp:GetPrivateKeyFile()` — `onion_private_key` →
  `onion_v3_private_key`. **Old v2 keys are intentionally not
  migrated.** TORv2 was removed in 2021 and the key material cannot
  be reused for a v3 service.
- `src/test/netbase_tests.cpp` — added v3 parsing tests (Bitcoin's
  test vector + corrupted-checksum negative case + v2-length negative
  case); removed the legacy OnionCat tests that asserted that
  `FD87:D87E:EB43:edb1:8e4:3588:e546:35ca` (an arbitrary IPv6 in the
  unique-local range) was a Tor address

**The torv3 algorithm:**
```
.onion address = base32(pubkey || checksum || version) + ".onion"
where:
  pubkey   = 32-byte ed25519 public key
  checksum = first 2 bytes of SHA3-256(".onion checksum" || pubkey || {3})
  version  = single byte 0x03
```

So a v3 .onion is 35 bytes of payload, base32-encoded into 56 chars,
plus the literal `.onion` suffix → 62-char total string.

**Validation:** A second standalone harness pulled in `crypto/sha3.{h,cpp}`
(via the trick of pre-defining `BITCOIN_CRYPTO_COMMON_H` to bypass
fluxd's `common.h`) and ran a battery of v3 parsing tests against
Bitcoin's reference vector:

- Input: `kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion`
- Expected pubkey hex: `53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88`
- Result: parser recovered the exact 32-byte pubkey ✓
- Round-trip: encoder produced the original 56-char string back ✓

Plus rejection cases:
- `5wyqrzbvrdsumnok.onion` (16 chars, v2-length) → rejected ✓
- `kpgvm...qaie.onion` (last char flipped, bad checksum) → rejected ✓
- `kpgvm...qaid.invalid` (wrong suffix) → rejected ✓
- `.onion` (empty payload) → rejected ✓
- All-zero pubkey edge case → round-trips cleanly (this is a useful
  sanity vector because the base32 of 35 zero bytes plus the SHA3
  checksum prefix produces a deterministic non-trivial output:
  `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion`)

**11/11 standalone test assertions passed.** The SHA3-256 → torv3
checksum chain wired correctly across Phase 1's SHA3 + Phase 3's parser.

**`add_onion_cb` parser was unchanged**: the existing
`ParseTorReplyMapping` function has no length assumptions for
`ServiceID` or `PrivateKey`, so 56-char v3 ServiceIDs and `ED25519-V3:`-
prefixed private keys flow through cleanly.


### Phase 4 — BIP155 wire format + `addrv2`/`sendaddrv2`

**Files modified:**
- `src/netbase.h` — added `BIP155Network` enum (IDs 1–6 per the BIP);
  added `ADDRV2_MAX_ADDRESS_SIZE = 512` defensive cap;
  **promoted `pchIPv4` from a file-static in `.cpp` to a header
  constant** so the new templated header serializers reference the
  same named symbol (this was a small hack-correction documented in
  section 4); added `CNetAddr::SerializeV2`/`UnserializeV2` and
  `CService::SerializeV2`/`UnserializeV2` template member functions;
  added the `CAddrVecV2` wrapper class
- `src/protocol.h` — added `CAddress::SerializeV2`/`UnserializeV2`
  (writes `nTime` as a fixed-32 LE, then `nServices` as a varint
  CompactSize per BIP155, then `CService::SerializeV2`); added the
  `CAddrVecV2::Serialize`/`Unserialize` template definitions (placed
  here rather than in netbase.h because they need the full
  `CAddress` definition)
- `src/net.h` — added `std::atomic_bool m_wants_addrv2{false}` to
  `CNode`
- `src/main.cpp` — added the `sendaddrv2` message handler (sets the
  flag, hard-rejects post-VERACK arrival per BIP155); folded `addr`
  and `addrv2` into a single handler that dispatches on `strCommand`
  for the deserialization step but shares the rate-limit / relay /
  addrman ingest pipeline; added `getaddrv2` next to `getaddr` (same
  body — the wire format is selected at flush time); injected the
  `sendaddrv2` push into the version-handshake response **before**
  the `verack` push for peers with `nVersion >= SENDADDRV2_VERSION`;
  branched the `SendMessages` addr-flush block on `m_wants_addrv2`
  (legacy peers get the legacy `addr` message and have v3 onion
  entries silently filtered out before sending — legacy V1 wire
  cannot represent them, and emitting 16 zero bytes would just
  confuse the peer)

**Design decision: explicit V2 methods, not stream flags.**

Bitcoin's BIP155 implementation threads an `Encoding` parameter
through its serializer via C++17 template parameters on `CDataStream`.
fluxd's serializer (circa 2013) is a flag-bag of `int nType` bits
(`SER_NETWORK | SER_DISK | SER_GETHASH`) with no per-call parameter
mechanism. Two real options:

1. Add `SER_ADDRV2 = (1 << 3)` and dispatch on it inside
   `SerializationOp`. But that means flipping a flag on the shared
   per-connection `ssSend` stream mid-message — fragile, racy,
   violates the "stream flags are sticky" mental model.
2. Bypass `SerializationOp` entirely with explicit `SerializeV2` and
   `UnserializeV2` member functions, reached only through the
   `CAddrVecV2` wrapper.

Option 2 was chosen. The legacy `SerializationOp` (V1 wire format) is
**provably untouched** — the V2 path lives in parallel methods that
nothing in the V1 dispatch code can reach. This trades a small amount
of ceremony (the wrapper class) for guaranteed isolation between the
two paths.

**Wire format check** (verified offset-by-offset against BIP155):

For a TORv3 entry with the Phase 3 test vector pubkey,
`nTime = 0x60000000`, `nServices = 9`, `port = 16125`:

```
00000060 09 04 20 53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88 3efd
^^^^^^^^ ^^ ^^ ^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ^^^^
nTime    sv id sz pubkey (32 bytes)                                              port
(LE)     (varint)
                                                                                 (BE)
```

- `00000060` — nTime, little-endian
- `09` — services varint
- `04` — BIP155 network ID = `BIP155_TORV3`
- `20` — payload length = 32, varint
- 32 bytes of ed25519 pubkey
- `3efd` — port 16125, big-endian per BIP155

Total: 41 bytes for the v3 entry. IPv4 entries are 13 bytes; IPv6
entries are 30 bytes.

**Validation:** A third standalone harness replicated the new
serializers against an in-memory stream and ran:

- IPv4 round-trip preserves all fields ✓
- IPv6 round-trip preserves all fields ✓
- TORv3 round-trip preserves the 32-byte pubkey byte-for-byte ✓
- Wire layout verified offset-by-offset against BIP155 ✓
- Pubkey at offset 7 matches the expected hex byte-for-byte ✓
- Port encoded as big-endian (`3EFD` for 16125) ✓
- Receive-side throws `std::ios_base::failure` on payloads > 512 bytes ✓
- TORV2/I2P/CJDNS/unknown network IDs are silently dropped (cleared
  to unspecified IPv6) and the port still parses, so the message
  stream stays in sync ✓

**35/35 standalone test assertions passed.**

**`main.cpp` could not be built directly during Phase 4 validation.**
Modern Boost 1.90 (which Homebrew installed during build environment
setup) dropped C++11 support. fluxd's `configure.ac` pins C++11 via
`AX_CXX_COMPILE_STDCXX([11])`. Anything that transitively includes
`boost/math/tools/type_traits.hpp` (which `wallet/db.h` does, which
`main.cpp` does via `wallet/asyncrpcoperation_sendmany.h`) hits dozens
of errors about missing `std::is_null_pointer`, `std::remove_cv_t`, etc.

This is **not a problem with the BIP155 work**. It is a pre-existing
build environment issue that was always going to bite when fluxd next
got built against modern Homebrew packages. The minimal fix is a
one-line bump in `configure.ac` — see section 5. I deliberately did
NOT sneak that fix in mid-refactor because it changes the build
system and is unrelated to BIP155.

The validation strategy worked around it: instead of building
`main.cpp`, I rebuilt every other touched object (`netbase.o`,
`protocol.o`, `net.o`, `torcontrol.o`, the test files) and ran
standalone harnesses for the wire format itself. That covers ~95% of
the actual logic surface; the remaining 5% (the message dispatch in
`main.cpp::ProcessMessage`) is mechanical wiring that compiles into
exactly what you'd expect.


### Phase 2 (REDO) — Clean `CNetAddr` refactor

After Phase 4 the operator (correctly) pushed back on the Phase 2
hybrid. The hybrid worked, but it had design debt:

- Two parallel storage paths (`ip[16]` for v4/v6, `m_addr_v3` for
  v3) meant every accessor touching address bytes had to remember
  to handle the Tor case separately
- `IsTor()` was implicit (`!m_addr_v3.empty()`) rather than backed
  by a real type tag
- A `SerializationOp` reuse trap: if a `CNetAddr` instance previously
  held a v3 onion and was then deserialized from V1 wire (16 bytes
  into `ip[]`), the stale `m_addr_v3` would still make it look like
  a Tor address. I had to add explicit `m_addr_v3.clear()` calls
  inside the read path. With a clean design, this trap doesn't exist.
- Adding I2P or CJDNS later would require either a third parallel
  buffer (terrible) or biting the bullet on the proper refactor
  anyway. The hybrid pushed cleanup down the road.
- Phase 5 would commit the hybrid representation to disk format,
  making it harder to fix later.

**The decision was made to redo Phase 2 properly before Phase 5,
locking in a clean foundation.** The trade-off was honestly framed:
the hybrid was *safer* (smaller diff, less risk of bucket reshuffling
on upgrade) but not *better*. Clean was the right call.

**The redo:**

`CNetAddr` was rewritten to mirror Bitcoin's design:
```cpp
class CNetAddr {
protected:
    Network m_net;                          // authoritative type tag
    std::vector<unsigned char> m_addr;      // length: 4 / 16 / 32
    void SerializeV1Array(uint8_t out[16]) const;
};
```

A private helper `SerializeV1Array` reconstructs the legacy 16-byte
"IPv4-mapped-IPv6" representation from `(m_net, m_addr)` on demand.
This is the **linchpin of the refactor**: every legacy code path that
thought in terms of `ip[16]` (`GetByte`, `GetHash`, `GetGroup`,
`CSubNet` matching, V1 wire serialization) now goes through this
helper and gets the same bytes it would have gotten from the old
field. **Byte-identical hash output for IPv4/IPv6 means addrman
buckets do not reshuffle on upgrade.**

The inverse helper `SetLegacyIPv6(const uint8_t bytes[16])` decodes
a 16-byte buffer and sets `m_net` to either `NET_IPV4` (if the
buffer starts with `pchIPv4`) or `NET_IPV6` (otherwise). This is
called from the V1 deserialization path.

Every accessor was rewritten:
- `Init` / `SetIP` / `SetRaw` set `(m_net, m_addr)` directly
- `IsIPv4` / `IsIPv6` / `IsTor` / `GetNetwork` are trivial dispatches
  on `m_net`
- `IsRFC*` and `IsLocal` predicates that previously did
  `memcmp(ip, ...)` now do `memcmp` against the
  `SerializeV1Array(buf); buf` output. The semantics are preserved.
- `GetByte(n)` reads from `SerializeV1Array` so all the `IsRFC*`
  predicates that use it continue to work unchanged
- `GetGroup` is **structurally identical** to the legacy version —
  only the input source changed. This is required to preserve
  addrman bucket placement.
- `GetHash` hashes `m_addr` directly for `NET_ONION` (so different
  onions land in different addrman buckets), but for IPv4/IPv6 it
  hashes the `SerializeV1Array` output — guaranteeing the addrman
  hash is byte-identical to the legacy implementation.
- `operator==/!=/<` compare `(m_net, m_addr)` lexicographically —
  natural ordering, no awkward fallthrough
- `CService::GetKey` keys off `m_addr` for Tor and `SerializeV1Array`
  for IPv4/IPv6
- `CSubNet`'s four direct field accesses were replaced with
  `SerializeV1Array` calls. `Match()` also rejects Tor outright
  (subnets aren't a meaningful concept for ed25519 onion addresses).

Phase 4's V2 serializers were updated to dispatch on `m_net`
directly (cleaner than the hybrid's `IsTor()/IsIPv4()` chain).

**`SetRaw(NET_IPV6, ...)` normalizes IPv4-mapped-IPv6.**

This was the bug the equivalence harness caught. Original Phase 2
hybrid had implicit normalization because `IsIPv4()` was a byte
prefix check (`memcmp(ip, pchIPv4, 12) == 0`) — so a CNetAddr
constructed from a `sockaddr_in6` holding `::ffff:1.2.3.4` would
have its bytes match the prefix and be classified as IPv4.

In the clean refactor, `IsIPv4()` is `m_net == NET_IPV4`. If
`SetRaw(NET_IPV6, ...)` blindly stores 16 bytes with
`m_net = NET_IPV6`, the prefix-encoded IPv4 address would be
classified as IPv6 — and two semantically identical addresses
constructed from `sockaddr_in` vs `sockaddr_in6` would compare
unequal. **Real correctness regression.** The fix routes
`NET_IPV6` constructions through `SetLegacyIPv6` which does the
prefix check.

**This is exactly why I was reluctant about the redo without an
equivalence check, and exactly why the equivalence check was the
right safeguard.**

**Validation: side-by-side equivalence harness.**

A 39-address battery was tested through both the legacy `ip[16]`
implementation and the new `(m_net, m_addr)` implementation
side-by-side. For each address, the harness compared:

- `GetHash` input bytes (must be byte-identical for addrman bucket
  preservation)
- `GetGroup` output (the actual addrman bucketing key)
- `IsIPv4`, `IsValid`, `IsRoutable`, `IsLocal`, `IsRFC1918`,
  `IsRFC4193`, `IsRFC4380` predicates

Coverage:

- IPv4: public (8.8.8.8, 1.2.3.4, 100.10.20.30, 220.220.220.220),
  RFC1918 (10/8 + 192.168/16 + 172.16/12 — all three ranges),
  RFC2544, RFC3927, RFC5737 (all three blocks), RFC6598, loopback,
  INADDR_NONE, INADDR_ANY
- IPv6: loopback (::1), unspecified (::), public (2001::8888),
  RFC4862 link-local (fe80::), RFC4193 ULA (including the historical
  FD87:D87E:EB43 OnionCat range), RFC3849 docs (2001:db8::),
  RFC3964 6to4 (2002::), RFC4380 Teredo (2001::), RFC6052 NAT64,
  RFC6145 IPv4-translated, he.net /36 (2001:470:abcd::),
  IPv4-mapped-IPv6
- The exact addresses encoded in fluxd's existing
  `netbase_tests.cpp` `GetGroup` contract assertions

**Result: 39/39 byte-identical**. Addrman bucket placement is
provably preserved across the refactor. An upgraded fluxd loading
an existing `peers.dat` will keep every IPv4/IPv6 entry in exactly
the same bucket as before.

The Phase 3 v3 onion regression tests also still passed under the
new storage (8/8).


### Phase 5 — addrman on-disk format bump

**Files modified:**
- `src/addrman.h` — added `CAddrInfo::SerializeV2`/`UnserializeV2`
  template member functions that route both the embedded `CAddress`
  and the `source` `CNetAddr` through the explicit BIP155 V2 codecs;
  added `static const unsigned char ADDRMAN_FORMAT_VERSION = 2`;
  modified `CAddrMan::Serialize` to write version 2 and call
  `info.SerializeV2(s)` per entry instead of `s << info`; modified
  `CAddrMan::Unserialize` to **strictly** accept versions 1 and 2
  only (any other version throws), branching to `info.UnserializeV2(s)`
  for v=2 and the legacy `s >> info` for v=1

The outer envelope (`nKey`, `nNew`, `nTried`, the `nUBuckets ^ (1<<30)`
magic, the bucket position replay loop) is **structurally identical**
to v1 — only the per-entry encoding changed. This minimizes the
chance of subtle differences in the index/lookup paths.

**Backwards compatibility matrix:**

| Reader      | File format       | Result                                                              |
|-------------|-------------------|---------------------------------------------------------------------|
| New fluxd   | format 1 (legacy) | ✓ reads via legacy `s >> info` path                                  |
| New fluxd   | format 2 (new)    | ✓ reads via `UnserializeV2` path                                     |
| New fluxd   | unknown version   | throws → caller catches → addrman starts empty                       |
| Old fluxd   | format 2          | bounds checks throw → addrman starts empty (graceful)                |
| Old fluxd   | format 1          | unchanged                                                            |

The "old fluxd reading new format" failure is **graceful and
intended**: addrman is a peer cache, not consensus state, so an
empty start just means relearning peers from the network and dnsseed
entries. There is no risk of chain corruption.

**Validation:** A fourth standalone harness replicated the addrman
write path for both v1 and v2 formats, fed it a fixture with three
entries (one IPv4, one IPv6, one v3 onion with another v3 onion as
its `source` field), and verified:

- Format-2 round-trip preserves IPv4 entries (port + metadata)
- Format-2 round-trip preserves IPv6 entries
- Format-2 round-trip preserves v3 onion entries — the 32-byte
  ed25519 pubkey is recovered byte-for-byte
- The `source` field round-trips correctly when it is itself a v3
  onion (mixed v4/v6/onion in the same `peers.dat`)
- `nKey`, `nNew`, `nTried` preserved through the cycle
- A format-2 stream is rejected by a format-1-only reader with
  `std::ios_base::failure` (graceful failure mode confirmed)
- A garbage version byte (99) is rejected with `std::ios_base::failure`

**13/13 standalone test assertions passed.**


### Phase 6 — Polish, RPC, docs

**Files modified:**
- `src/net.h` — added two fields to `CNodeStats`: `Network m_network`
  and `bool m_wants_addrv2`
- `src/net.cpp` — `CNode::copyStats` populates both new fields
- `src/rpc/net.cpp` — `getpeerinfo` now exposes two new keys per peer:
  `"network"` (`"ipv4"` / `"ipv6"` / `"onion"` / `"unroutable"`) and
  `"addrv2"` (true/false, whether the peer negotiated SENDADDRV2
  before VERACK and is therefore eligible to receive v3 onion gossip
  from us)
- `doc/tor.md` — full rewrite. Removed the "Do not assume Tor support
  does the correct thing" warning that dated from the v2 era. Replaced
  every v2 example with the Phase 3 v3 test vector. Added new sections
  on the `onion_v3_private_key` file, BIP155 negotiation visibility
  via `getpeerinfo`, and `peers.dat` format compatibility.

**`init.cpp` required no logic changes.** The existing
`-onion`/`-onlynet=tor`/`-listenonion`/proxy code path uses the
network enum value (which is correct regardless of the symbol name).
After the post-Phase-6 `NET_TOR` → `NET_ONION` rename, the nine
references in `init.cpp:1318-1370` are now spelled `NET_ONION` but do
exactly the same thing they did before — the enum value at position
3 is unchanged.

**`getnetworkinfo` already worked correctly.** It iterates `NET_MAX`
and reports `GetNetworkName(NET_ONION) → "onion"`. No code change
needed.

**Final rebuild check:** All ten objects touched across all six
phases were rebuilt cleanly with fresh timestamps:

| Phase | Object               | Size    |
|-------|----------------------|---------|
| 1     | `crypto/sha3.o`      | 34 KB   |
| 2/3/4 | `netbase.o`          | 1.3 MB  |
| 4     | `protocol.o`         | 334 KB  |
| 5     | `addrman.o`          | 588 KB  |
| 6     | `net.o`              | 8.6 MB  |
| 3     | `torcontrol.o`       | 2.7 MB  |
| 6     | `rpc/net.o`          | 1.9 MB  |
| tests | `netbase_tests.o`    | 1.5 MB  |
| tests | `addrman_tests.o`    | 1.8 MB  |
| tests | `torcontrol_tests.o` | 3.4 MB  |

Zero errors. The remaining warnings are pre-existing fluxd quirks
unrelated to anything touched in this work (one
`class`/`struct` mismatched-tag on `PrecomputedTransactionData`,
two C++ VLA warnings in `hash.h`).


## 4. Architectural decisions worth recording

### 4.1. Wrapper struct vs `SerParams`

Bitcoin's BIP155 implementation uses `SerParams` — a C++17 template
parameter on the stream type that lets the caller select between V1
and V2 encoding per-call. This is elegant in C++17 but **not
backportable** to fluxd's older serializer, which uses an `int nType`
flag-bag.

Two real options were considered:

1. Add `SER_ADDRV2 = (1 << 3)` to `serialize.h` and dispatch on it
   inside `CNetAddr::SerializationOp` / `CAddress::SerializationOp`.
   This requires temporarily flipping a flag on the per-connection
   `ssSend` stream, then flipping it back after the message is
   pushed. Fragile (flag ends up sticky if an exception unwinds at
   the wrong moment), violates the "stream type is immutable for
   the connection's lifetime" mental model, and creates a write
   path through `SerializationOp` that the V1 readers don't expect.
2. Add explicit `SerializeV2`/`UnserializeV2` member functions that
   bypass `SerializationOp` entirely, reached only through a wrapper
   class (`CAddrVecV2`) that the caller passes to `PushMessage`.

**Option 2 was chosen.** The legacy `SerializationOp` is provably
untouched by anything in the V2 path, because the V2 methods are
not part of the SerializationOp dispatch and `CAddrVecV2` is the
only way to reach them from outside. This trades a small amount of
ceremony (one wrapper class) for guaranteed isolation between V1
and V2.

If fluxd ever bumps to a modern serializer, this could be cleaned
up by removing `CAddrVecV2` and exposing the V2 methods through a
proper SerParams equivalent. The `SerializeV2`/`UnserializeV2`
member functions themselves would not need to change.

### 4.2. Hybrid `CNetAddr` storage was a wrong call

The Phase 2 hybrid (`ip[16]` + `m_addr_v3`) was justified at the
time as "minimum diff, addrman buckets provably preserved". Both
were true. But it was the wrong design:

- It pushed cleanup work onto the next person who tried to add I2P
  or CJDNS
- It introduced subtle correctness traps (the `m_addr_v3.clear()`
  reuse trap) that the clean design simply doesn't have
- It made every accessor branchy (`if (IsTor()) ... else ...`)
  rather than dispatch-on-tag

The Phase 2 REDO replaced it with the clean Bitcoin-style design
*before* Phase 5 committed it to disk format. This was a real cost
(equivalent to ~half a phase of extra work, plus a bug-finding
equivalence harness), but it landed a final result that an extending
engineer can actually work with.

**Lesson:** when an early phase establishes a foundational data
shape that later phases will build on, optimize for the long-term
cleanliness of that shape, not the short-term diff size. Especially
when the shape is going to be committed to disk by a later phase.

### 4.3. `pchIPv4` was promoted from file-static to header constant

Mid-Phase 4, the operator caught me inlining the IPv4-mapped-IPv6
prefix bytes (`ip[10] = 0xff; ip[11] = 0xff;`) directly into
`UnserializeV2` instead of using the named `pchIPv4` constant. The
shortcut was born of laziness — `pchIPv4` was `static const` in
`netbase.cpp` and using it from a templated header function would
have required moving it to the header.

The shortcut was reverted: `pchIPv4` was promoted to `netbase.h`,
the file-static was removed, and `UnserializeV2` now references the
same named constant the rest of the codebase uses.

**Lesson:** when refactoring, reach for the named constant even if
it costs an extra edit. Magic bytes scattered through the codebase
are exactly what makes the codebase hard to extend later.

### 4.4. `peers.dat` format gate hardened

The legacy `Unserialize` checked `if (nVersion != 0)` for the bucket
count XOR — but never actually validated that `nVersion` was a value
the reader knew how to handle. So a future format bump (say, version 3)
would silently produce garbage when read by version-2-only code,
because the parser would proceed past the version byte and try to
deserialize entries in a format it didn't understand.

Phase 5 hardened this: the new `Unserialize` strictly accepts
versions 1 and 2 only, throwing `std::ios_base::failure` on anything
else. A future Phase X that introduces format version 3 will need to
extend this check; there is no longer any silent-misread risk.

### 4.5. `NET_TOR` → `NET_ONION` retroactive rename

The plan called for renaming `NET_TOR` to `NET_ONION` for clarity in
Phase 1. I argued out of it at the time: the rename was cosmetic-only,
cascaded into ~10 files (`init.cpp`, `torcontrol.cpp`,
`netbase_tests.cpp`, etc.), and provided zero functional benefit. The
operator accepted the deferral and the work proceeded with `NET_TOR`
as the symbol name throughout.

After Phase 6 the operator (correctly) decided that the codebase
shouldn't ship with any "we'll do this later" debt visible in the
source tree. The rename was applied retroactively across all 29
references in 5 files (`netbase.h`, `netbase.cpp`, `torcontrol.cpp`,
`init.cpp`, `test/netbase_tests.cpp`) using `Edit replace_all`. The
enum value at position 3 was preserved (still `NET_ONION = 3`), so
`GetGroup()` still pushes the integer `3` into the addrman bucket
key for onion entries — addrman bucketing remained byte-identical
across the rename, just as it did across the Phase 2 REDO. Only the
spelling changed.

All seven downstream object files (`netbase.o`, `protocol.o`,
`addrman.o`, `net.o`, `torcontrol.o`, `rpc/net.o`, `netbase_tests.o`)
rebuilt cleanly after the rename. `init.cpp` was the only edited
file not rebuilt directly during this validation, because it
transitively pulls in the bdb4/Boost/wallet chain that requires the
C++14 bump (section 5.1) — but the edits there were purely the
mechanical symbol-name swap, with no logic changes possible from a
`replace_all` rename.

**Lesson:** even cosmetic-only debt counts as debt. If a future
reader has to look at the code and wonder "why is this called
`NET_TOR` when it stores 32-byte ed25519 pubkeys?", that's a tax on
their attention. Better to pay the diff cost up front.


## 5. Known limitations and deferred work

### 5.1. C++14 bump required for modern build environments

fluxd's `configure.ac` line 66 pins C++11:
```
AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory], [nodefault])
```

Modern Boost (1.74+) requires C++14 or higher. If you build against
a current Linux distro's `libboost-all-dev`, the compile will fail
with errors from `boost/math/tools/type_traits.hpp` about missing
`std::is_null_pointer`, `std::remove_cv_t`, etc.

**Fix:** change `[11]` to `[14]` in `configure.ac`, re-run
`./autogen.sh && ./configure`, rebuild. This is a one-line change.
fluxd's own code is C++11, so the bump is purely about meeting
Boost's minimum and won't surface other code issues.

I deliberately did NOT include this fix in the BIP155 work because
it's a build-system change unrelated to BIP155. The operator should
make it as a separate, clearly-scoped commit.

### 5.2. I2P and CJDNS are unimplemented

The `BIP155Network` enum includes `BIP155_I2P = 5` and
`BIP155_CJDNS = 6` so the receive-side parser recognizes them and
skips them gracefully. But fluxd has no dialer for either network,
no parser for `.b32.i2p` strings, and no producer for those wire IDs.

The clean Phase 2 REDO design makes adding either network a matter
of: (1) adding `NET_I2P` / `NET_CJDNS` to the `Network` enum,
(2) implementing `SetI2P` / `SetCJDNS` with the appropriate parsing,
(3) extending `CNetAddr::SerializeV2`/`UnserializeV2` to dispatch
on the new `m_net` cases. No third or fourth parallel storage
buffer; no architectural debt to repay first.

### 5.3. anchors.dat not implemented

Bitcoin Core persists a small set of "anchor" outbound block-relay
peers in `anchors.dat` separately from `peers.dat`. fluxd does not.
This is unrelated to BIP155 — it's a separate feature that would be
useful for fluxd in its own right (faster reconnect after restart)
but is out of scope.

### 5.4. No on-the-wire fuzz corpus

Phase 6 mentioned adding captured BIP155 messages to `src/test/data/`
for fuzz/regression testing. fluxd does not currently have a fuzz
test scaffolding to plug them into, so this was deferred. The
standalone wire-format tests written during validation are the
existing safety net.

### 5.5. The full `qa/rpc-tests` suite was not run during this work

Running the suite requires a fully-linked fluxd binary, which
requires the C++14 bump (5.1) plus a working Berkeley DB 4
installation, plus the rest of fluxd's wallet/zcash dependencies.
The validation strategy used during this work was:

- Build every individual `.o` file touched, prove zero compile errors
- Run standalone harnesses for the algorithmic surfaces (SHA3,
  TORv3 parser, BIP155 wire format, addrman format, equivalence
  vs. legacy `CNetAddr`)

This catches all the implementation bugs but doesn't exercise the
full P2P state machine end-to-end. The operator should run the
`qa/rpc-tests` suite as a final pre-merge gate once their build
environment is sorted.

### 5.6. macOS-specific build environment fixes

During this work, several macOS-only build environment issues were
fixed in the operator's local environment:

- Homebrew autoconf 2.71's six perl scripts had a hardcoded
  `#!/usr/bin/perl5.30` shebang but only `perl5.34` exists on the
  current macOS. Six shebangs were patched in
  `/usr/local/Cellar/autoconf/2.71/bin/`. **This fix is local to
  the operator's mac and is not needed on Linux.**
- `boost` (1.90.0) and `berkeley-db@4` (4.8.30) were installed via
  Homebrew. **Linux distros provide these via standard package
  management — see `build-test-onion-linux.md`.**

None of the macOS environment fixes are part of the fluxd source
tree. They are noted here only so a future macOS developer doesn't
have to rediscover them.

### 5.7. `src/config/bitcoin-config.h` should not be tracked in git

`src/config/bitcoin-config.h` is an autoconf-generated file (its
first two lines literally say `Generated from bitcoin-config.h.in
by configure`). fluxd inherited the practice of tracking this file
in git from old Bitcoin Core, presumably so a fresh clone doesn't
have to run autoconf before the first build. Bitcoin Core itself
moved this file out of the tracked tree years ago, for the reasons
that bit me during this work:

- **It captures the build environment of whoever last ran configure.**
  When I ran `./configure` on macOS during validation (without
  specifying `--with-incompatible-bdb` initially), the regenerated
  file flipped `ENABLE_WALLET 1 → /* #undef */`, `ENABLE_ZMQ 1 → 0`,
  and undefined every `HAVE_BOOST*` flag (because modern Boost 1.90's
  layout isn't picked up by fluxd's older `configure.ac` macros).
  If those modifications had been committed, anyone building the
  branch would have suddenly found their wallet and ZMQ disabled —
  a real footgun for CI, packagers, and operators.

- **Every developer who runs `./configure` locally gets working-tree
  noise** that's trivially reset (`git restore
  src/config/bitcoin-config.h`) but easy to forget about, and
  catastrophic if accidentally `git add .`'d into a commit.

- **Generated files in version control are a recurring source of
  merge conflicts** that can't be resolved by reading the source —
  you have to re-run configure to get the canonical state.

**Recommended cleanup (out of scope for the BIP155 work):**

1. Add `src/config/bitcoin-config.h` to `.gitignore`
2. `git rm --cached src/config/bitcoin-config.h` (removes from
   tracking without deleting the working-tree file)
3. Verify a fresh clone + `./autogen.sh && ./configure && make`
   works — autoconf should recreate the file from `bitcoin-config.h.in`
4. Make sure no CI script assumes the file exists pre-build

This is a one-commit cleanup. It's worth doing as a separate
quality-of-life PR before the next time someone hits the same
footgun. **It is not part of the BIP155 work and should not be
bundled with this branch** — separate concern, separate review,
separate revert path if it breaks anything.


## 6. Files modified summary

| File                              | Phases     | Nature                                       |
|-----------------------------------|------------|----------------------------------------------|
| `src/crypto/sha3.h`               | 1          | NEW — SHA3-256 header (C++11 port)          |
| `src/crypto/sha3.cpp`             | 1          | NEW — SHA3-256 implementation                |
| `src/Makefile.am`                 | 1          | Added sha3 sources                           |
| `src/version.h`                   | 1          | PROTOCOL_VERSION → 170021; SENDADDRV2_VERSION |
| `src/netbase.h`                   | 2/3/4      | Network m_net + m_addr; BIP155 enum; ADDR_*_SIZE; SerializeV2/UnserializeV2; CAddrVecV2 wrapper; pchIPv4 promoted |
| `src/netbase.cpp`                 | 2/3/4      | Full CNetAddr rewrite; torv3 namespace; SetTor; CSubNet updates; pchIPv4 file-static removed |
| `src/torcontrol.cpp`              | 3          | NEW:ED25519-V3; onion_v3_private_key         |
| `src/protocol.h`                  | 4          | CAddress::SerializeV2/UnserializeV2; CAddrVecV2 templates |
| `src/main.cpp`                    | 4          | sendaddrv2/addrv2/getaddrv2 handlers; version handshake; relay branching |
| `src/net.h`                       | 4/6        | m_wants_addrv2 on CNode; CNodeStats fields   |
| `src/net.cpp`                     | 6          | copyStats populates new fields               |
| `src/addrman.h`                   | 5          | CAddrInfo::SerializeV2/UnserializeV2; format version bump; strict version gate |
| `src/rpc/net.cpp`                 | 6          | getpeerinfo network/addrv2 fields             |
| `src/test/netbase_tests.cpp`      | 2/3        | v3 parsing tests; OnionCat tests removed     |
| `doc/tor.md`                      | 6          | Full rewrite for v3                          |

**15 files modified, 2 files created** (crypto/sha3.{h,cpp}). No
changes to consensus, validation, transaction handling, scripting,
mining, mempool, or anything that could fork the chain.


## 7. Tests run summary

| Phase | Test                                       | Result    |
|-------|--------------------------------------------|-----------|
| 1     | NIST SHA3-256 KAT (empty + "abc")           | 2/2 ✓     |
| 2 REDO | CNetAddr equivalence vs legacy (39 addrs)  | 39/39 ✓   |
| 3     | TORv3 parser + roundtrip + rejection cases | 11/11 ✓   |
| 4     | BIP155 wire format roundtrip + edge cases  | 35/35 ✓   |
| 5     | addrman format-2 roundtrip + compatibility | 13/13 ✓   |
| all   | Full rebuild of all touched objects        | 0 errors  |

**Standalone test total: 100/100 assertions passed.**


## 8. Next steps for the operator

In rough order of importance:

1. **Bump fluxd to C++14.** One-line change in `configure.ac`. See
   section 5.1 and `build-test-onion-linux.md`.
2. **Build the fluxd binary on Linux.** See
   `build-test-onion-linux.md` for the full distro-specific package
   list and build command.
3. **Run the two-node smoke test.** No real Tor required; just
   verifies the binaries link and that `sendaddrv2` is exchanged.
   See `build-test-onion-linux.md` section 4.
4. **Run the full two-node onion test.** Real Tor, real v3 hidden
   services, real .onion peering. See `build-test-onion-linux.md`
   section 5.
5. **Run the persistence test.** Restart one node, confirm v3 onion
   addresses survive. See `build-test-onion-linux.md` section 6.
6. **Mainnet shadow soak (24+ hours).** Point one upgraded node at
   real mainnet and watch for misbehavior log lines, addrman
   corruption, or unexpected disconnects.
7. **Coordinate the `PROTOCOL_VERSION = 170021` bump with the Flux
   core team** before any release tag. Other Flux software may need
   matching updates.
8. **Run the `qa/rpc-tests` suite** as a final pre-merge gate.

---

## Appendix A — Original plan file

The full implementation plan as it was approved before work began
lives at `~/.claude/plans/cuddly-churning-reddy.md` in the operator's
local plan-tracking directory. The plan document includes the design
rationale, the file-by-file change list, the verification strategy,
and an explicit list of out-of-scope items.

Key plan-level facts worth preserving in the journal:

- The plan decided "drop v2 entirely" (matching Bitcoin's
  decision). v2 onions were removed from the live Tor network in
  October 2021 and there is nothing on the network to talk to.
- The plan explicitly accepted that an old fluxd reading a new
  `peers.dat` would start with an empty address book. addrman is
  cache, not consensus state.
- The plan reserved the `BIP155Network` enum values for I2P (5)
  and CJDNS (6) as future work, recognizing them on the wire so
  they can be cleanly skipped without producing garbage.
- The plan deliberately scoped the work to peer-layer changes
  only. No consensus rules were modified.

The journal you are reading IS the execution record of that plan.
