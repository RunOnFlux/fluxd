#!/bin/bash
# Two-node onion smoke test for the BIP155/TORv3 port.
#
# Exercises, end to end on regtest:
#   1. ephemeral v3 hidden service creation via the tor control port (-listenonion)
#   2. outbound onion connection through the SOCKS proxy (-onion)
#   3. sendaddrv2 (BIP155) negotiation during the version handshake
#   4. block propagation across the onion link
#   5. anchors.dat round-trip of a v3 onion address + anchor reconnect after restart
#
# Requirements: a `tor` binary on PATH and outbound access to the Tor network.
# Runs entirely as the invoking user; creates a private tor instance (no system
# tor service involvement). Working directory: $TOR_SMOKE_DIR (default ~/tor-smoke,
# DELETED at start of each run).
#
# Usage: qa/tor-smoke-test.sh   (from any cwd; finds fluxd relative to itself,
#        override with FLUXD=/path/fluxd CLI=/path/flux-cli)
set -u
SRCDIR=$(cd "$(dirname "$0")/../src" && pwd)
FLUXD=${FLUXD:-$SRCDIR/fluxd}
CLI=${CLI:-$SRCDIR/flux-cli}
BASE=${TOR_SMOKE_DIR:-$HOME/tor-smoke}
SOCKS=${TOR_SMOKE_SOCKS:-19050}
CTRL=${TOR_SMOKE_CTRL:-19051}
A_PORT=18555; A_RPC=18556
B_PORT=18557; B_RPC=18558

log() { echo "[$(date +%H:%M:%S)] $*"; }
fail() { log "FAIL: $*"; cleanup; exit 1; }

cleanup() {
  $CLI -datadir=$BASE/nodeA stop >/dev/null 2>&1
  $CLI -datadir=$BASE/nodeB stop >/dev/null 2>&1
  sleep 3
  pkill -F $BASE/tor/tor.pid 2>/dev/null
}

[ -x "$FLUXD" ] || { echo "fluxd not found at $FLUXD (set FLUXD=)"; exit 1; }
command -v tor >/dev/null || { echo "tor binary not on PATH"; exit 1; }

rm -rf $BASE
mkdir -p $BASE/tor $BASE/nodeA $BASE/nodeB
chmod 700 $BASE/tor

# --- 1. private tor instance ---
cat > $BASE/tor/torrc <<EOF
DataDirectory $BASE/tor
PidFile $BASE/tor/tor.pid
SocksPort 127.0.0.1:$SOCKS
ControlPort 127.0.0.1:$CTRL
CookieAuthentication 1
Log notice file $BASE/tor/tor.log
EOF
tor -f $BASE/tor/torrc --RunAsDaemon 1 || fail "tor failed to start"
for i in $(seq 1 60); do
  grep -q "Bootstrapped 100" $BASE/tor/tor.log && break; sleep 2
done
grep -q "Bootstrapped 100" $BASE/tor/tor.log || fail "tor did not bootstrap in 120s: $(tail -3 $BASE/tor/tor.log)"
log "tor bootstrapped"

# --- 2. node A: hidden service via torcontrol ---
cat > $BASE/nodeA/flux.conf <<EOF
regtest=1
server=1
listen=1
port=$A_PORT
rpcport=$A_RPC
rpcuser=t
rpcpassword=t
rpcallowip=127.0.0.1
listenonion=1
torcontrol=127.0.0.1:$CTRL
onion=127.0.0.1:$SOCKS
discover=0
dnsseed=0
debug=tor
debug=net
EOF
$FLUXD -datadir=$BASE/nodeA -daemon || fail "nodeA failed to start"
ONION=""
for i in $(seq 1 60); do
  ONION=$($CLI -datadir=$BASE/nodeA getnetworkinfo 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); a=[x['address'] for x in d.get('localaddresses',[]) if x['address'].endswith('.onion')]; print(a[0] if a else '')" 2>/dev/null)
  [ -n "$ONION" ] && break; sleep 3
done
[ -n "$ONION" ] || fail "nodeA never got an onion address. tor debug: $(grep -i tor $BASE/nodeA/regtest/debug.log | tail -5)"
log "nodeA onion address: $ONION (v3 len=$(echo -n ${ONION%.onion} | wc -c))"

# --- 3. node B: connect to A over tor ---
cat > $BASE/nodeB/flux.conf <<EOF
regtest=1
server=1
listen=0
port=$B_PORT
rpcport=$B_RPC
rpcuser=t
rpcpassword=t
rpcallowip=127.0.0.1
onion=127.0.0.1:$SOCKS
discover=0
dnsseed=0
debug=tor
debug=net
EOF
$FLUXD -datadir=$BASE/nodeB -daemon || fail "nodeB failed to start"
sleep 3
$CLI -datadir=$BASE/nodeB addnode "$ONION:$A_PORT" onetry
CONNECTED=0
for i in $(seq 1 40); do
  N=$($CLI -datadir=$BASE/nodeB getconnectioncount 2>/dev/null || echo 0)
  if [ "$N" -ge 1 ]; then CONNECTED=1; break; fi
  $CLI -datadir=$BASE/nodeB addnode "$ONION:$A_PORT" onetry 2>/dev/null
  sleep 5
done
[ "$CONNECTED" = 1 ] || fail "nodeB never connected to $ONION:$A_PORT. nodeB log: $(tail -5 $BASE/nodeB/regtest/debug.log)"
log "nodeB connected to nodeA over onion"

# --- 4. verify handshake: sendaddrv2 must be exchanged both directions ---
sleep 3
for side in nodeA nodeB; do
  grep -q "sending: sendaddrv2" $BASE/$side/regtest/debug.log || fail "$side never sent sendaddrv2"
  grep -q "received: sendaddrv2" $BASE/$side/regtest/debug.log || fail "$side never received sendaddrv2"
done
log "sendaddrv2 exchanged both directions"
echo "=== nodeB getpeerinfo (key fields) ==="
$CLI -datadir=$BASE/nodeB getpeerinfo | grep -E "\"addr\"|\"network\"|\"addrv2\"|\"version\"" | head -6

# --- 5. block propagation over onion ---
$CLI -datadir=$BASE/nodeA generate 3 >/dev/null 2>&1
sleep 10
HA=$($CLI -datadir=$BASE/nodeA getblockcount)
HB=$($CLI -datadir=$BASE/nodeB getblockcount)
log "block heights: A=$HA B=$HB"
{ [ "$HA" = "$HB" ] && [ "$HA" -ge 3 ]; } || fail "block propagation failed (A=$HA B=$HB)"
log "block propagation over onion OK"

# --- 6. anchors.dat v2: onion must round-trip and reconnect after restart ---
$CLI -datadir=$BASE/nodeB stop; sleep 5
$FLUXD -datadir=$BASE/nodeB -daemon || fail "nodeB restart failed"
sleep 8
ANCHOR_LINE=$(grep "Trying anchor connection" $BASE/nodeB/regtest/debug.log | tail -1)
echo "$ANCHOR_LINE" | grep -q "\.onion" || fail "anchor did not round-trip as onion: $ANCHOR_LINE"
log "anchor round-tripped as onion: $ANCHOR_LINE"
RECONN=0
for i in $(seq 1 30); do
  N=$($CLI -datadir=$BASE/nodeB getconnectioncount 2>/dev/null || echo 0)
  if [ "$N" -ge 1 ]; then RECONN=1; break; fi
  sleep 5
done
[ "$RECONN" = 1 ] || fail "nodeB did not reconnect via anchor"
log "nodeB reconnected via onion anchor"

log "ALL CHECKS PASSED"
cleanup
log "done"
