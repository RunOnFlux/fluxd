#!/usr/bin/env bash
# Restart storm: N service restart cycles asserting per cycle that RPC comes
# back, recovery is skipped ("no recovery needed"), blockindex.arena is
# recreated, and post-settle RssAnon stays in band.
#
# OPERATOR RUNBOOK — restarts the node's fluxd repeatedly.
#
# Usage: sudo ./restart_storm.sh [cycles] [rssanon_limit_kb] [datadir]
set -euo pipefail

CYCLES="${1:-10}"
LIMIT_KB="${2:-600000}"
DATADIR="${3:-/dat/var/lib/fluxd}"
CLI="${CLI:-/usr/local/bin/flux-cli}"

systemctl stop flux-watchdog.timer flux-watchdog.service
trap 'systemctl start flux-watchdog.timer' EXIT

for i in $(seq 1 "$CYCLES"); do
  T0=$(date +%s)
  systemctl restart fluxd
  until "$CLI" -datadir="$DATADIR" getblockcount >/dev/null 2>&1; do
    sleep 2
    if [ $(( $(date +%s) - T0 )) -gt 600 ]; then echo "FAIL cycle $i: RPC not up in 600s"; exit 1; fi
  done
  INIT_S=$(( $(date +%s) - T0 ))
  # assert on the LAST recovery line (robust against log rotation/buffering;
  # every boot writes exactly one RecoverFluxnodeCache line)
  LAST_RECOVERY=$(grep -a "RecoverFluxnodeCache" "$DATADIR/debug.log" | tail -1)
  echo "$LAST_RECOVERY" | grep -qE "no recovery needed|skipping recovery" \
    || { echo "FAIL cycle $i: recovery ran on a clean restart: $LAST_RECOVERY"; exit 1; }
  ARENA=$(find "$DATADIR" -name blockindex.arena -newermt "@$T0" | head -1)
  [ -n "$ARENA" ] || { echo "FAIL cycle $i: blockindex.arena not recreated"; exit 1; }
  sleep 60   # settle
  PID=$(pgrep -x fluxd | head -1)
  ANON=$(awk '/RssAnon/{print $2}' "/proc/$PID/status")
  echo "cycle $i/$CYCLES: init ${INIT_S}s, arena $(stat -c%s "$ARENA") B, RssAnon ${ANON} kB"
  [ "$ANON" -lt "$LIMIT_KB" ] || { echo "FAIL cycle $i: RssAnon ${ANON} kB over ${LIMIT_KB} kB"; exit 1; }
done
echo "OK: $CYCLES restart cycles clean."
