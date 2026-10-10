#!/usr/bin/env bash
# Fresh-peer IBD served by patched nodes only: sync a brand-new datadir to
# tip with connect= pinned to the patched fleet. Every historic block and
# header the peer receives is served from pruned index entries via the
# disk-read paths, at sustained IBD rate. Run the soak-check command against
# the serving nodes during the sync to confirm they stay at tip with flat
# RssAnon.
#
# Runs on any spare host with ~60 GB free disk (build server works).
#
# Usage: FLUXD=/path/fluxd CLI=/path/flux-cli ./ibd_sync.sh <peer1> [peer2 ...]
set -euo pipefail

[ $# -ge 1 ] || { echo "usage: $0 <peer-ip> [peer-ip ...]"; exit 1; }
FLUXD="${FLUXD:-fluxd}"
CLI="${CLI:-flux-cli}"
DATADIR="${DATADIR:-$HOME/ibd-stress-datadir}"
CSV="/tmp/ibd_sync_$(date +%s).csv"

mkdir -p "$DATADIR"
{
  echo "server=1"; echo "listen=0"; echo "discover=0"; echo "dnsseed=0"
  echo "rpcuser=stress"; echo "rpcpassword=stress"; echo "rpcallowip=127.0.0.1"
  # dedicated ports: must not collide with anything else on a shared host
  echo "rpcport=17124"; echo "port=17125"
  echo "dbcache=200"
  for p in "$@"; do echo "connect=$p"; done
} > "$DATADIR/flux.conf"

echo "Starting IBD from peers: $*"
"$FLUXD" -datadir="$DATADIR" -daemon
trap '"$CLI" -datadir="$DATADIR" stop 2>/dev/null || true' EXIT
until "$CLI" -datadir="$DATADIR" getblockcount >/dev/null 2>&1; do sleep 2; done

echo "ts,height,peers,progress" > "$CSV"
LAST_H=0; LAST_T=$(date +%s); STALL=0
while :; do
  H=$("$CLI" -datadir="$DATADIR" getblockcount)
  P=$("$CLI" -datadir="$DATADIR" getconnectioncount)
  # verificationprogress arrives in scientific notation early in IBD
  # (e.g. 1.18e-05) — parse numerically, never textually
  PROG=$("$CLI" -datadir="$DATADIR" getblockchaininfo | awk -F'[:,]' '/verificationprogress/{gsub(/ /,"",$2); print $2}')
  NOW=$(date +%s)
  RATE=$(( (H - LAST_H) * 3600 / (NOW - LAST_T + 1) ))
  echo "$NOW,$H,$P,$PROG  (${RATE} blk/h)" | tee -a "$CSV"
  if [ "$H" -eq "$LAST_H" ]; then STALL=$((STALL+1)); else STALL=0; fi
  [ "$STALL" -lt 20 ] || { echo "FAIL: sync stalled for 20 intervals at height $H"; exit 1; }
  if [ "$(awk -v p="$PROG" 'BEGIN{print (p+0 > 0.9999) ? 1 : 0}')" = "1" ]; then
    echo "OK: synced to tip ($H) from patched peers only."; break
  fi
  LAST_H=$H; LAST_T=$NOW
  sleep 180
done
