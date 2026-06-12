#!/usr/bin/env bash
# Memory-pressure torture: run fluxd under a hard no-swap memory cap and log
# RssAnon/RssFile/major-fault behavior. Cold arena pages must evict and fault
# back; the process must neither OOM nor touch swap.
#
# OPERATOR RUNBOOK — stops the node's fluxd service for the duration.
#
# Usage: sudo ./memory_pressure.sh [cap_mb] [duration_s] [datadir]
# Defaults: 500 MB cap, 3600 s, /dat/var/lib/fluxd
#
# Run header_storm.py against this node from another host during the window
# to combine pressure with the serving workload (PR stress item 4).
set -euo pipefail

CAP_MB="${1:-500}"
DURATION="${2:-3600}"
DATADIR="${3:-/dat/var/lib/fluxd}"
FLUXD="${FLUXD:-/usr/local/bin/fluxd}"
CLI="${CLI:-/usr/local/bin/flux-cli}"
CSV="/tmp/memory_pressure_$(date +%s).csv"

echo "Stopping services (watchdog first)..."
systemctl stop flux-watchdog.timer flux-watchdog.service fluxd

echo "Starting fluxd under MemoryHigh=${CAP_MB}M MemorySwapMax=0 for ${DURATION}s..."
systemd-run --unit=fluxd-stress --collect \
  -p MemoryHigh="${CAP_MB}M" -p MemoryMax="$((CAP_MB + 200))M" -p MemorySwapMax=0 \
  "$FLUXD" -datadir="$DATADIR"

cleanup() {
  echo "Restoring normal service..."
  systemctl stop fluxd-stress 2>/dev/null || true
  sleep 5
  systemctl start fluxd
  systemctl start flux-watchdog.timer
  echo "Samples: $CSV"
}
trap cleanup EXIT

echo "ts,height,RssAnon_kB,RssFile_kB,VmSwap_kB,majflt,mem_current" > "$CSV"
END=$(( $(date +%s) + DURATION ))
while [ "$(date +%s)" -lt "$END" ]; do
  PID=$(systemctl show -p MainPID --value fluxd-stress)
  if [ -z "$PID" ] || [ "$PID" = 0 ]; then
    echo "FAIL: fluxd-stress not running (OOM-killed?)"; journalctl -u fluxd-stress --no-pager | tail -5
    exit 1
  fi
  H=$("$CLI" -datadir="$DATADIR" getblockcount 2>/dev/null || echo "-1")
  ANON=$(awk '/RssAnon/{print $2}' "/proc/$PID/status")
  FILE=$(awk '/RssFile/{print $2}' "/proc/$PID/status")
  SWAP=$(awk '/VmSwap/{print $2}' "/proc/$PID/status")
  MAJ=$(awk '{print $12}' "/proc/$PID/stat")
  CUR=$(cat "/sys/fs/cgroup/system.slice/fluxd-stress.service/memory.current" 2>/dev/null || echo "-")
  echo "$(date +%s),$H,$ANON,$FILE,$SWAP,$MAJ,$CUR" | tee -a "$CSV"
  if [ "$SWAP" != "0" ]; then echo "FAIL: VmSwap=$SWAP kB (must stay 0)"; exit 1; fi
  sleep 30
done
echo "OK: survived ${DURATION}s under ${CAP_MB}M cap with zero swap. Verify height kept advancing in $CSV."
