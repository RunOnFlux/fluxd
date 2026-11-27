#!/usr/bin/env bash
# Wallet rescan against pruned headers: restart with -rescan and assert no
# transaction reports "conflicted" afterwards (the M3 failure shape marked
# EVERY confirmed tx conflicted after a fluxnode restart because the merkle
# check compared against a zeroed pruned root).
#
# OPERATOR RUNBOOK — needs a fluxnode with a wallet that has transactions.
#
# Usage: sudo ./wallet_rescan.sh [datadir]
set -euo pipefail

DATADIR="${1:-/dat/var/lib/fluxd}"
FLUXD="${FLUXD:-/usr/local/bin/fluxd}"
CLI="${CLI:-/usr/local/bin/flux-cli}"

TXCOUNT=$("$CLI" -datadir="$DATADIR" listtransactions "*" 100 0 | grep -c '"txid"' || true)
echo "Wallet has $TXCOUNT recent transactions; restarting with -rescan..."
[ "$TXCOUNT" -gt 0 ] || { echo "SKIP: wallet has no transactions to validate"; exit 0; }

systemctl stop flux-watchdog.timer flux-watchdog.service fluxd
trap 'systemctl start flux-watchdog.timer' EXIT
T0=$(date +%s)
"$FLUXD" -datadir="$DATADIR" -rescan -daemon
until "$CLI" -datadir="$DATADIR" getblockcount >/dev/null 2>&1; do sleep 5; done
echo "Rescan + init took $(( $(date +%s) - T0 ))s"

CONFLICTED=$("$CLI" -datadir="$DATADIR" listtransactions "*" 100 0 | grep -c '"conflicted"' || true)
ABANDONED=$("$CLI" -datadir="$DATADIR" listsinceblock | grep -c '"conflicted": true' || true)
"$CLI" -datadir="$DATADIR" stop
sleep 10
systemctl start fluxd

if [ "$CONFLICTED" -gt 0 ] || [ "$ABANDONED" -gt 0 ]; then
  echo "FAIL: $CONFLICTED/$ABANDONED transactions report conflicted after rescan"
  exit 1
fi
echo "OK: rescan complete, 0 of $TXCOUNT transactions conflicted."
