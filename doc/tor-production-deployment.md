TOR PRODUCTION DEPLOYMENT
=========================

This document describes how FluxOS should configure Tor on production
fluxnodes. It covers the two node types (public IP and NAT), the
security model, and the rationale behind the design.

For manual operator setup and fluxd's Tor command-line options, see
[`tor.md`](tor.md). For the BIP155/TORv3 implementation details, see
[`build-journal-bip155-torv3.md`](build-journal-bip155-torv3.md).


1. Why Tor on fluxnodes
-----------------------

Approximately 80% of fluxnodes are behind NAT. These nodes can only
make outbound connections — they cannot accept inbound. The 20% of
nodes with public IPs ("hub nodes") become de facto hubs, creating a
hub-and-spoke topology with several problems:

  - **Single points of failure.** If hub nodes go down, NAT nodes
    behind them lose their only peers.
  - **Gossip bottleneck.** Block and transaction propagation must
    always route through hubs. A NAT node cannot relay directly to
    another NAT node — the path is always NAT -> hub -> NAT.
  - **Uneven load.** The 20% carry the connection load for the entire
    network.
  - **Eclipse attack surface.** To isolate a NAT node, an attacker
    only needs to control the small set of hubs it connects to.
  - **Poor peer diversity.** NAT nodes can only choose from the ~20%
    that are reachable. If that 20% is geographically or
    AS-concentrated, the whole network's resilience depends on a few
    hosting providers.

Tor hidden services give NAT nodes a globally-reachable inbound
address — regardless of NAT. Two NAT nodes that could never talk
directly can now peer with each other through Tor. This flattens the
hub-and-spoke topology into a mesh.

The goal is NOT privacy — it is **network resilience**.


2. Node types and their Tor roles
---------------------------------

### 2.1 NAT nodes (hidden service + outbound)

NAT nodes run a Tor hidden service so they become reachable. They also
make a small number of outbound Tor connections to other NAT nodes.

  - Creates a v3 hidden service via `ADD_ONION` on the Tor control port
  - Advertises its `.onion` address to peers via `AdvertizeLocal()`
  - Accepts inbound Tor connections from other NAT nodes
  - Makes 2 Tor outbound connections (`maxonionoutbound=2`, the default)
  - Makes 14 clearnet outbound connections to hub nodes for fast block relay

### 2.2 Public IP nodes (hubs — SOCKS only, no hidden service)

Hub nodes do NOT create a hidden service. They are already reachable
on clearnet. They run Tor only as a SOCKS client so they can:

  - **Store** onion addresses in addrman (because `NET_ONION` is
    reachable, `IsReachable()` returns true)
  - **Relay** onion addresses to other peers via `addrv2` gossip
  - **Verify** onion addresses via feeler connections (connect through
    SOCKS, complete version/verack, `addrman.Good()`, disconnect)

Without hub participation, onion address gossip dies — a NAT node
advertises its `.onion` to a hub, but if the hub doesn't store it,
the address cannot be served via `getaddr` responses to other NAT
nodes that could actually use it. Hubs are the connective tissue.

### 2.3 Why hubs must NOT create hidden services

If hubs created hidden services, their `.onion` addresses would enter
the gossip pool alongside NAT node `.onion` addresses. NAT nodes
filling their 2 Tor outbound slots might connect to a hub over Tor —
pointless, since they can already reach that hub on clearnet. With no
hub `.onion` addresses in the pool, every Tor outbound slot connects
to another NAT node, which is exactly the desired behavior.

### 2.4 Why hubs need SOCKS (feeler verification)

If hubs store onion addresses they can never connect to, fake
addresses persist in addrman forever — the normal eviction loop
(connect, fail, penalize) never runs. An attacker can generate
thousands of fake `.onion` addresses (any random 32 bytes is a
syntactically valid pubkey), advertise them via `addrv2`, and poison
hub addrman. NAT nodes pulling `getaddr` from hubs would waste their
limited Tor outbound slots trying to connect to nonexistent addresses,
each attempt taking 5-30 seconds to timeout through Tor.

With SOCKS available, hubs verify onion addresses via feeler
connections. The feeler
connects through SOCKS, completes the version/verack handshake
(proving a real fluxd is listening), calls `addrman.Good()`, then
immediately disconnects. Failed connections increment `nAttempts` and
the address eventually ages out. No permanent Tor peer slots are
consumed — feelers are one-shot probes on a 120-second cycle.


3. Production Tor configuration
-------------------------------

FluxOS ships ONE static `torrc`, identical on every node — the NAT/hub
split lives entirely in `flux.conf`:

    SocksPort 127.0.0.1:9050
    ControlPort 127.0.0.1:9051
    CookieAuthentication 1
    CookieAuthFileGroupReadable 1
    ExitPolicy reject *:*

### 3.1 NAT node

Flux configuration (`flux.conf`):

    onion=127.0.0.1:9050
    torcontrol=127.0.0.1:9051
    listenonion=1

No `torpassword` is needed. fluxd auto-negotiates SAFECOOKIE
authentication with Tor's control port. The fluxd process must be in
the correct group to read the cookie file (`debian-tor` on
Debian/Ubuntu, `_tor` on some other distros).

SAFECOOKIE is preferred over password authentication because:

  - No plaintext password in `flux.conf`
  - No `HashedControlPassword` in `torrc`
  - The cookie file is permission-restricted to the Tor group
  - The SAFECOOKIE protocol uses a challenge-response handshake, so
    even sniffing the control connection does not leak the cookie

### 3.2 Public IP node (hub)

The hub uses the same shared `torrc` as every node (control port
included). Flux configuration (`flux.conf`):

    onion=127.0.0.1:9050
    maxonionoutbound=0
    listenonion=0

`listenonion=0` is mandatory: the shared `torrc` exposes a control port,
so without it fluxd would stand up its own hidden service — putting the
hub's `.onion` into the gossip pool and stealing NAT nodes' onion
outbound slots. The hub never opens a control connection. The `onion=`
line makes `NET_ONION` reachable so onion addresses are stored, relayed,
and feeler-verified. `maxonionoutbound=0` prevents persistent Tor peer
slots; verification happens through feeler connections only.


4. Security analysis
--------------------

### 4.1 No external attack surface

Neither node type exposes any Tor port to the network:

  - `SocksPort` is bound to `127.0.0.1` — not reachable from outside
  - `ControlPort` is bound to `127.0.0.1` (present on every node; only NAT nodes open a control connection)
  - No `ORPort` is configured — the node is NOT a Tor relay
  - `ExitPolicy reject *:*` — the node is NOT a Tor exit
  - No `BridgeRelay` — the node is not a Tor bridge

The Tor daemon is purely a client. It does not accept inbound
connections from the Tor network. (Hidden services work via outbound
connections to rendezvous points, not inbound listeners.)

### 4.2 No open proxy

The `SocksPort 127.0.0.1:9050` binding is critical. If this were
changed to `0.0.0.0:9050`, anyone on the internet could use the node
as a Tor proxy — routing arbitrary traffic through the customer's IP.

**FluxOS must never configure `SocksPort` on `0.0.0.0`.** This should
be validated with a hardcoded check during deployment.

### 4.3 Control port security

The control port (`127.0.0.1:9051`) is present on every node, localhost-only,
and protected by SAFECOOKIE authentication. Hubs set `listenonion=0` and never
open a control connection; only NAT nodes use it (to create their hidden
service). An attacker would need:

  1. Local code execution on the machine, AND
  2. File read access as the fluxd user (to read the cookie file)

If they have both, they could create additional hidden services or
remove fluxd's hidden service (a recoverable DoS). They cannot make
the node a relay or exit via the control port — that requires `torrc`
changes and a Tor daemon restart.

### 4.4 IP reputation

As a Tor client (not relay, not exit), the node's IP does not appear
in any public Tor directory or relay list. IP reputation services will
not flag it.

### 4.5 Addrman poisoning mitigation

Fake `.onion` addresses injected via `addrv2` are mitigated by:

  - **Hub feelers:** hubs verify onion addresses by connecting through
    SOCKS. Unreachable addresses fail, accumulate `nAttempts`, and age
    out of addrman.
  - **NAT node connection failures:** NAT nodes that connect to a fake
    onion address and fail will penalize it locally and stop
    re-advertising it.
  - **Addr rate limiting:** the existing per-peer rate limiter
    (`nAddrTokenBucket`) limits how fast any single peer can push
    addresses.
  - **Addrman bucket structure:** limits entries per source group and
    per address group, preventing a single source from dominating.

### 4.6 Resource usage

Tor as a SOCKS-only client uses minimal resources — a few MB of RAM,
negligible CPU. No relay traffic is carried.


5. Connection balance
---------------------

Each NAT node makes 16 outbound connections:

  - 14 clearnet outbound to hub nodes (fast block relay)
  - 2 Tor outbound to other NAT nodes (mesh connectivity)

Block propagation takes the fastest path. With 14 clearnet connections
to well-connected hubs, a NAT node will almost always hear about new
blocks on clearnet first. The 2 Tor connections (~400ms latency vs
~40-80ms clearnet) add mesh redundancy without impacting block
propagation latency.

The 2:14 ratio is controlled by `maxonionoutbound` (default 2) and
`MAX_OUTBOUND_CONNECTIONS` (16). If network analysis shows the mesh
needs more or fewer Tor edges, `maxonionoutbound` can be adjusted
without code changes.

Hub nodes set `maxonionoutbound=0` — they make no persistent Tor
connections. Feeler verification uses one-shot connections that do not
consume outbound peer slots.


6. Address discovery flow
-------------------------

The end-to-end flow for how a NAT node's onion address reaches other
NAT nodes:

  1. NAT node A starts, creates a hidden service via `ADD_ONION`.
  2. `torcontrol.cpp` calls `AddLocal(service, LOCAL_MANUAL)`,
     registering the `.onion:16125` address.
  3. `AdvertizeLocal()` pushes the address to connected peers.
  4. Hub nodes receive the address via `addrv2`. Because `NET_ONION`
     is reachable (SOCKS is configured), the address passes the
     `IsReachable()` check and enters addrman.
  5. Hub nodes relay the address to other peers via `addrv2` gossip
     and serve it in `getaddr` responses.
  6. NAT node B does `getaddr` to a hub, receives A's `.onion`, adds
     it to addrman.
  7. When filling a Tor outbound slot, B's `ThreadOpenConnections`
     picks A's `.onion` from `addrman.Select()`, connects through
     SOCKS, completes version/verack. A direct NAT-to-NAT connection
     is established.
  8. Hub feelers periodically verify stored onion addresses, evicting
     stale or fake entries.


7. Deployment checklist
-----------------------

For FluxOS integration:

  - [ ] Detect whether the node has a public IP or is behind NAT
  - [ ] Install Tor as a system package (not Docker in production)
  - [ ] Write the single shared `torrc` (section 3)
  - [ ] Write the per-role `flux.conf` lines (section 3.1 / 3.2)
  - [ ] Ensure `SocksPort` is ALWAYS `127.0.0.1:9050`, never `0.0.0.0`
  - [ ] Ensure the fluxd user is in the Tor cookie group (`debian-tor`)
        for control-cookie access
  - [ ] Test NAT-to-NAT connectivity through Tor
