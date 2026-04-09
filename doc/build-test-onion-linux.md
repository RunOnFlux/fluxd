BUILDING fluxd ON LINUX AND TESTING TWO-NODE ONION PEERING
===========================================================

This guide takes you from "fresh Linux box" to "two fluxd nodes peering
each other through TORv3 hidden services with BIP155 addrv2 gossip
working." It is the operator-facing companion to
[`build-journal-bip155-torv3.md`](build-journal-bip155-torv3.md), which
documents the implementation work itself.

The end state you're verifying:

  - Both fluxds build cleanly with the BIP155 / TORv3 changes
  - Both negotiate `sendaddrv2` before VERACK during the version
    handshake (the Phase 4 wire change)
  - Both create their own v3 onion hidden service via Tor's control
    port (the Phase 3 torcontrol change)
  - Both can dial each other through .onion addresses
  - `getpeerinfo` reports `"network": "onion"` and `"addrv2": true` for
    each peer (the Phase 6 RPC additions)
  - v3 onion peers persist across a restart via the new `peers.dat`
    format-2 (the Phase 5 disk format bump)

Estimated time: 1–2 hours, most of which is the initial build.


## 1. Install build dependencies

The exact package names vary by distro. Choose your distro and run the
matching block once.

### 1.1 Debian / Ubuntu (22.04 LTS or newer)

```bash
sudo apt update
sudo apt install -y \
    build-essential pkg-config \
    autoconf automake libtool \
    bsdmainutils \
    libssl-dev \
    libevent-dev \
    libboost-all-dev \
    libsodium-dev \
    libgmp-dev \
    libcurl4-openssl-dev \
    libdb4.8-dev libdb4.8++-dev \
    cmake ninja-build \
    git curl wget \
    python3 python3-pip
```

If `libdb4.8-dev` is not in your distro's repos (it's been removed
from recent Ubuntu), the standard workaround is the Bitcoin PPA:

```bash
sudo add-apt-repository ppa:bitcoin/bitcoin
sudo apt update
sudo apt install -y libdb4.8-dev libdb4.8++-dev
```

Or build it from `depends/` (slower but no PPA needed — see section 2.3).

### 1.2 Fedora / RHEL / Rocky / Alma

```bash
sudo dnf install -y \
    gcc-c++ make pkgconf-pkg-config \
    autoconf automake libtool \
    openssl-devel \
    libevent-devel \
    boost-devel \
    libsodium-devel \
    gmp-devel \
    libcurl-devel \
    cmake ninja-build \
    git curl wget \
    python3 python3-pip
```

Berkeley DB 4.8 is not in standard Fedora repos. You'll need to build
it from `depends/` (see section 2.3).

### 1.3 Arch / Manjaro

```bash
sudo pacman -S --needed \
    base-devel \
    autoconf automake libtool \
    openssl libevent boost libsodium gmp curl \
    cmake ninja \
    git wget \
    python python-pip
```

Berkeley DB 4.8 is in AUR (`db4.8`). Either install via your AUR
helper or use `depends/`.

### 1.4 Install Tor

You'll need this for the actual onion test in section 5. Install it
now so it's ready.

```bash
# Debian / Ubuntu:
sudo apt install -y tor

# Fedora:
sudo dnf install -y tor

# Arch:
sudo pacman -S --needed tor
```

Verify Tor is recent enough (≥ 0.3.5 for control protocol; 0.4.7+ recommended):

```bash
tor --version
```

If your distro's Tor is older than 0.4.0, install from the Tor
project's official APT/DNF repos — see https://support.torproject.org/apt/


## 2. Get the source and apply the C++14 bump

### 2.1 Clone

```bash
git clone https://github.com/RunOnFlux/fluxd.git
cd fluxd
git checkout <branch-with-bip155-work>   # whichever branch this is being merged into
```

### 2.2 Bump fluxd to C++14

This is the only build-system change required, and it is the only
change that is **not** part of the BIP155 work itself. Modern Boost
(1.74+) and modern libstdc++ have moved past C++11; fluxd's
`configure.ac` still pins it.

```bash
sed -i 's|AX_CXX_COMPILE_STDCXX(\[11\]|AX_CXX_COMPILE_STDCXX([14]|' configure.ac
grep AX_CXX_COMPILE_STDCXX configure.ac
# Should print:
#   AX_CXX_COMPILE_STDCXX([14], [noext], [mandatory], [nodefault])
```

If `sed` doesn't match (the file changed shape), open `configure.ac`
and find the `AX_CXX_COMPILE_STDCXX` line manually — change `[11]` to
`[14]`.

### 2.3 (Optional) Use the depends/ system instead of distro packages

If you don't want to install Berkeley DB 4.8 from a third-party PPA
(or your distro doesn't have one), use fluxd's vendored dependency
builder. This compiles boost, bdb, libevent, etc. from source into a
sandbox under `depends/`.

```bash
cd depends
make -j$(nproc)              # ~30–60 minutes on a typical machine
cd ..
```

Then in step 3, you'll point `./configure` at the depends prefix
instead of the system prefix.

### 2.4 Generate the build system

```bash
./autogen.sh
```

If this fails with `aclocal: error: ...` or similar, your autotools
versions are mismatched — most often `automake` is from a different
era than `autoconf`. The fix is usually `sudo apt install
automake-1.16` or equivalent.


## 3. Configure and build

### 3.1 Configure (system packages path)

```bash
./configure \
    --with-incompatible-bdb \
    --without-gui \
    CPPFLAGS="-DDEBUG_LOCKORDER" \
    CXXFLAGS="-O2 -g"
```

`--with-incompatible-bdb` accepts any 4.x Berkeley DB version, not
just the exact pinned 4.8.30. This is fine for testing; for a release
build you'd want to match the pinned version exactly to avoid wallet
file divergence between builds.

`--without-gui` skips the Qt GUI. For a node-only test, you don't
need it.

### 3.2 Configure (depends/ path)

If you used section 2.3:

```bash
HOST=$(./depends/config.guess)
./configure --prefix=$PWD/depends/$HOST --without-gui
```

### 3.3 Build

```bash
make -j$(nproc)
```

This takes 10–30 minutes depending on the machine. The output binaries
land at:

```
src/fluxd          # the daemon
src/flux-cli       # the JSON-RPC client
```

### 3.4 Quick sanity check

```bash
src/fluxd --version
src/fluxd --help | grep -i tor
```

You should see the version string printing 9.0.7 (or whatever the
post-bump version is) and the `-listenonion`, `-torcontrol`,
`-torpassword`, `-onion`, `-noonion`, `-onlynet` options listed in
the help output.


## 4. Tier 1 — Two-node smoke test (no Tor required)

This proves the binaries link, two nodes can talk to each other on
regtest, and **`sendaddrv2` is being exchanged before VERACK**. This
is the fastest way to confirm the BIP155 wire-format work is alive.

Estimated time: 5–10 minutes.

### 4.1 Set up two data directories

```bash
mkdir -p ~/fluxtest/{a,b}
```

### 4.2 Write `~/fluxtest/a/flux.conf`

```ini
regtest=1
listen=1
discover=0
dnsseed=0
port=20011
rpcport=20010
rpcuser=t
rpcpassword=t
debug=net
debug=addrman
```

### 4.3 Write `~/fluxtest/b/flux.conf`

```ini
regtest=1
listen=1
discover=0
dnsseed=0
port=20021
rpcport=20020
rpcuser=t
rpcpassword=t
debug=net
debug=addrman
addnode=127.0.0.1:20011
```

### 4.4 Run both nodes (two terminals)

Terminal 1:
```bash
./src/fluxd -datadir=$HOME/fluxtest/a -printtoconsole
```

Wait until it prints `init message: Done loading`, then Terminal 2:
```bash
./src/fluxd -datadir=$HOME/fluxtest/b -printtoconsole
```

### 4.5 Look for the SENDADDRV2 exchange in the logs

Within a few seconds of node B connecting, you should see in node A's
log:

```
receive version message: ... version 170021, ...
```

and somewhere nearby:

```
sending: sendaddrv2 ...
```

Node B's log should show the mirror image (`receive: sendaddrv2`).

### 4.6 Verify with the new RPC fields

In a third terminal:

```bash
./src/flux-cli \
    -datadir=$HOME/fluxtest/a \
    -rpcport=20010 -rpcuser=t -rpcpassword=t \
    getpeerinfo
```

You should see, for the peer entry:

```json
{
    "id": 1,
    "addr": "127.0.0.1:20021",
    "network": "ipv4",        ← Phase 6 reporting
    "addrv2": true,           ← Phase 6, proves SENDADDRV2 negotiated
    "version": 170021,        ← Phase 1 protocol version bump
    "subver": "/...",
    ...
}
```

**The contract for "Tier 1 passed" is:**

  - `version` is `170021`
  - `addrv2` is `true`
  - The two nodes stayed connected

If `addrv2` is `false`, something is wrong with the version-handshake
injection in `main.cpp`. Verify `PROTOCOL_VERSION = 170021` in
`src/version.h` and that the `pfrom->nVersion >= SENDADDRV2_VERSION`
check in `main.cpp` is being reached.

### 4.7 (Optional) Backwards-compatibility check

Grab a stock `9.0.6` fluxd binary (from a Flux release) and run it as
node C with `-addnode=127.0.0.1:20011`. Confirm:

  - Node C connects without misbehavior
  - Node A's `getpeerinfo` for node C shows `"version": 170020,
    "addrv2": false`
  - No `Misbehaving` log lines on either side
  - The nodes stay connected and exchange blocks

This proves the BIP155 work doesn't break legacy peers.

### 4.8 Stop the nodes

`Ctrl-C` in each terminal. Or:

```bash
./src/flux-cli -datadir=$HOME/fluxtest/a -rpcport=20010 -rpcuser=t -rpcpassword=t stop
./src/flux-cli -datadir=$HOME/fluxtest/b -rpcport=20020 -rpcuser=t -rpcpassword=t stop
```


## 5. Tier 2 — Real Tor v3 hidden service test

This is the real test. Two fluxds, each hosting its own v3 onion
service, dialing each other through Tor.

Estimated time: 20–30 minutes.

### 5.1 Configure Tor's control port

Edit `/etc/tor/torrc` (location may differ on Fedora/Arch — check
`man tor`):

```
ControlPort 9051
CookieAuthentication 1
CookieAuthFileGroupReadable 1
```

Restart Tor:

```bash
sudo systemctl restart tor
```

Verify the control port is listening:

```bash
nc -z 127.0.0.1 9051 && echo "control port up"
```

### 5.2 Make sure your user can read the cookie file

The cookie file is typically at `/var/run/tor/control.authcookie` or
`/var/lib/tor/control_auth_cookie`. Find it:

```bash
sudo find /var -name "control_auth_cookie" 2>/dev/null
sudo find /var -name "control.authcookie" 2>/dev/null
```

Check whether you can read it as your normal user:

```bash
ls -la /var/run/tor/control.authcookie  # adjust path
```

If the group is `debian-tor` (or `_tor` on some distros) and the file
is group-readable, add yourself to that group:

```bash
sudo usermod -a -G debian-tor $USER
# Log out and log back in for the group to take effect, OR:
newgrp debian-tor
```

If that doesn't work, the password-auth fallback is:

```bash
# In /etc/tor/torrc, add:
HashedControlPassword <output of: tor --hash-password "yourpassword">
# Then in fluxd's flux.conf:
torpassword=yourpassword
```

### 5.3 Update both fluxd configs to enable the onion service

Add to **both** `~/fluxtest/a/flux.conf` and `~/fluxtest/b/flux.conf`:

```ini
listenonion=1
torcontrol=127.0.0.1:9051
debug=tor
```

And **remove** the `addnode=` line from `~/fluxtest/b/flux.conf` — we
want them to find each other via .onion in this test, not via the
local IP.

### 5.4 Restart both nodes

```bash
# Terminal 1
./src/fluxd -datadir=$HOME/fluxtest/a -printtoconsole

# Terminal 2 (after node A is up)
./src/fluxd -datadir=$HOME/fluxtest/b -printtoconsole
```

### 5.5 Watch the Tor handshake in the logs

In each terminal, you should see:

```
tor: Successfully connected!
tor: Authentication successful
tor: Got service ID kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid,
     advertising service kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion:20011
```

The service ID will be **56 characters long** — that's the v3 marker.
A 16-character ID would mean Phase 3 didn't take effect.

### 5.6 Verify the v3 private key file was created

```bash
ls -la ~/fluxtest/a/regtest/onion_v3_private_key
head -c 20 ~/fluxtest/a/regtest/onion_v3_private_key
```

The file should exist and start with `ED25519-V3:`. If it does,
**Phase 3 is fully wired**.

### 5.7 Manually wire the two nodes via .onion

Regtest doesn't have dnsseed, so we have to give them each other's
.onion address. Grab node A's onion address from its log (or from
`getnetworkinfo` → `localaddresses`):

```bash
NODE_A_ONION=$(./src/flux-cli \
    -datadir=$HOME/fluxtest/a \
    -rpcport=20010 -rpcuser=t -rpcpassword=t \
    getnetworkinfo | grep -oE '[a-z2-7]{56}\.onion' | head -1)

echo "Node A onion: $NODE_A_ONION"
```

Now ask node B to dial it:

```bash
./src/flux-cli \
    -datadir=$HOME/fluxtest/b \
    -rpcport=20020 -rpcuser=t -rpcpassword=t \
    addnode "${NODE_A_ONION}:20011" onetry
```

Wait 5–10 seconds for the Tor circuit to establish.

### 5.8 The moment of truth

```bash
./src/flux-cli \
    -datadir=$HOME/fluxtest/a \
    -rpcport=20010 -rpcuser=t -rpcpassword=t \
    getpeerinfo
```

You should see, for the peer entry:

```json
{
    "addr": "kpgvmscir...nqaid.onion:20011",
    "network": "onion",       ← Phase 6: per-peer network classification
    "addrv2": true,           ← Phase 4: BIP155 negotiated
    "version": 170021,
    ...
}
```

**The contract for "Tier 2 passed" is:**

  - Both nodes' `getpeerinfo` show `"network": "onion"` for the peer
  - Both show `"addrv2": true`
  - Both stay connected (no Misbehaving, no disconnect)

This is the end-to-end "TOR routing works in fluxd" verification.
**All six phases are working together.**


## 6. Tier 3 — Persistence test

Verifies Phase 5: v3 onion peers survive a restart.

Estimated time: 5 minutes.

### 6.1 Confirm a v3 onion is in the address book

While both nodes from Tier 2 are still running and peered:

```bash
./src/flux-cli \
    -datadir=$HOME/fluxtest/a \
    -rpcport=20010 -rpcuser=t -rpcpassword=t \
    getpeerinfo | grep -A1 onion
```

You should see at least one peer with an `.onion` address.

### 6.2 Stop node A cleanly

```bash
./src/flux-cli \
    -datadir=$HOME/fluxtest/a \
    -rpcport=20010 -rpcuser=t -rpcpassword=t \
    stop
```

Wait for it to finish writing `peers.dat`. You'll see in its log:

```
Flushed N addresses to peers.dat ...
```

### 6.3 Verify peers.dat is in the new format

```bash
xxd -l 1 ~/fluxtest/a/regtest/peers.dat
```

You want to see:

```
00000000: 02                                       .
```

A `02` byte at offset 0 means **Phase 5 is active and the file is in
the new BIP155-aware format**. A `01` byte means the new writer didn't
fire — likely because there were no v3 entries to persist (in which
case rerun Tier 2 with the `-debug=addrman` flag and look for the
flush message).

### 6.4 Restart node A and confirm reconnection

```bash
./src/fluxd -datadir=$HOME/fluxtest/a -printtoconsole
```

Within a minute, node A should reconnect to node B's .onion address
*without* you re-running `addnode`. Verify:

```bash
./src/flux-cli \
    -datadir=$HOME/fluxtest/a \
    -rpcport=20010 -rpcuser=t -rpcpassword=t \
    getpeerinfo
```

The v3 onion peer should be back, with the same `"network": "onion",
"addrv2": true` reporting.

**The contract for "Tier 3 passed" is:**

  - `peers.dat` first byte is `02`
  - After restart, the v3 onion peer is loaded from disk and
    reconnected to without manual intervention


## 7. Tier 4 — Mainnet shadow soak (optional, 24+ hours)

Once Tiers 1–3 pass on regtest, point ONE upgraded fluxd at real
mainnet and let it run for at least a day. Watch for problems.

### 7.1 Setup

Use a fresh data directory so you don't disturb your existing node:

```bash
mkdir -p ~/fluxshadow
```

`~/fluxshadow/flux.conf`:
```ini
listen=1
listenonion=1
torcontrol=127.0.0.1:9051
debug=net
debug=tor
```

```bash
./src/fluxd -datadir=$HOME/fluxshadow -printtoconsole 2>&1 | tee ~/fluxshadow/run.log
```

### 7.2 What to watch for

In another terminal:

```bash
tail -f ~/fluxshadow/run.log | grep -iE "misbehav|error|abort|disconnect|corrupt|throw"
```

**You DO NOT want to see:**

  - `Misbehaving peer ...` lines triggered by your node's behavior
  - Other peers disconnecting your node specifically (look for many
    "disconnect" lines tied to the same remote IP shortly after your
    node tries to send addrv2)
  - `Corrupt CAddrMan serialization` (would mean the new writer
    produced something the new reader can't read — should be
    impossible after Tier 3 passed)
  - `tor:` errors after the initial successful service creation
  - Sudden unexplained disconnects after `sendaddrv2` is sent

**You SHOULD see:**

  - Periodic `Flushed N addresses to peers.dat` messages (every
    15 minutes by default)
  - A growing peer count
  - At least some peers eventually showing `"version": 170021`
    (other upgraded nodes) — though this depends on rollout
  - `getpeerinfo` showing a healthy mix of `"network"` values

### 7.3 Spot-check after 24 hours

```bash
./src/flux-cli -datadir=$HOME/fluxshadow getpeerinfo \
    | grep -E '"network"|"addrv2"|"version"' \
    | sort | uniq -c | sort -rn
```

A healthy result looks like (numbers will vary):

```
     6     "version": 170020,
     2     "version": 170021,
     6     "network": "ipv4",
     2     "network": "ipv6",
     2     "addrv2": true,
     6     "addrv2": false,
```

If you see `"network": "onion"` entries, another upgraded fluxd is
already on mainnet — that's the BIP155 gossip channel working in
production.


## 8. Common gotchas

### `tor: Authentication cookie ... could not be opened`

Permissions on the Tor cookie file. Add yourself to the `debian-tor`
or `_tor` group (section 5.2), or fall back to password authentication.

### `tor: Add onion failed; error code 510` or `552`

Your local Tor is too old. Need 0.3.5+ for ed25519 hidden services.
`apt install tor` from your distro may give you a years-old version;
install from https://support.torproject.org/apt/ instead.

### `getpeerinfo` shows `"version": 170020` instead of 170021

You're talking to a peer that wasn't built from the BIP155 branch.
That's expected for legacy peers; just confirm `addrv2` is `false`
for them and they stay connected.

### `getpeerinfo` shows `"addrv2": false` for an upgraded peer

The version handshake injection in `main.cpp` isn't firing. Check:

  - `PROTOCOL_VERSION = 170021` in `src/version.h`
  - The `pfrom->nVersion >= SENDADDRV2_VERSION` check in the
    `version` message handler in `main.cpp`
  - That you're running the actually-built binary (not a stale one
    in `/usr/local/bin`)

### No `.onion` peers ever appear in `getpeerinfo`

Either you're the only upgraded node on the network (likely during
early rollout) or address relay is dropping them. Use `addnode
<onion>` to bypass relay and confirm the dial path works directly
first.

### `peers.dat` first byte is `01` not `02`

Either:
- You're running an old binary (rebuild and check version)
- No v3 entries were ever staged (run Tier 2 first to actually
  populate addrman with an onion peer, then trigger a flush)

### `peers.dat` is empty after restart

Two possibilities:
- Old fluxd reading new format → start the new binary
- New fluxd reading a corrupted file → check the first byte with
  `xxd -l 1 peers.dat`. If it's not `01` or `02`, the file is
  garbage and addrman will start empty (which is fine — it's cache)

### `make` fails with `'std::is_null_pointer' has not been declared`

You forgot the C++14 bump in section 2.2. The error is from
`boost/math/tools/type_traits.hpp` and means Boost is requiring
C++14+. Re-run section 2.2 then `./autogen.sh && ./configure && make`.

### `db_cxx.h: No such file or directory`

Berkeley DB 4.8 is missing. Either install via the Bitcoin PPA
(section 1.1), build via `depends/` (section 2.3), or — if you're
NOT building the wallet — disable wallet support with
`./configure --disable-wallet`.


## 9. The fastest path through everything

If you only have an hour and want maximum coverage:

1. Section 2.2 — bump to C++14 (1 minute)
2. Section 2.4 + 3 — autogen, configure, make (10–30 minutes)
3. Section 4 — Tier 1 smoke test (5 minutes) — confirms BIP155
   negotiation
4. Section 5 — Tier 2 with real Tor (20–30 minutes) — confirms v3
   hidden service end-to-end

That covers ~90% of the validation surface. Tiers 3 and 4 are
nice-to-have but Tier 2 passing is the real "yes, it works" moment.


## 10. Tear down

```bash
./src/flux-cli -datadir=$HOME/fluxtest/a -rpcport=20010 -rpcuser=t -rpcpassword=t stop
./src/flux-cli -datadir=$HOME/fluxtest/b -rpcport=20020 -rpcuser=t -rpcpassword=t stop

# If you ran Tier 4:
./src/flux-cli -datadir=$HOME/fluxshadow stop

# Optionally wipe the test data dirs:
rm -rf ~/fluxtest ~/fluxshadow
```

The Tor service stays running independently. To stop it:

```bash
sudo systemctl stop tor
```

---

## Appendix — Reading list

  - `doc/build-journal-bip155-torv3.md` — engineering record of the
    BIP155 / TORv3 backport. Read this if you need to extend, debug,
    or review the implementation.
  - `doc/tor.md` — operator-facing TOR setup documentation, rewritten
    for v3.
  - BIP155 spec: https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
  - Tor rend-spec-v3: https://gitlab.torproject.org/tpo/core/torspec/-/tree/main/spec/rend-spec
  - Bitcoin Core PR #19954 (the original BIP155 implementation):
    https://github.com/bitcoin/bitcoin/pull/19954
