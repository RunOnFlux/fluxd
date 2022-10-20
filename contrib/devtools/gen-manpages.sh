#!/bin/sh

TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
SRCDIR=${SRCDIR:-$TOPDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

FLUXD=${FLUXD:-$SRCDIR/fluxd}
FLUXCLI=${FLUXCLI:-$SRCDIR/flux-cli}
FLUXTX=${FLUXTX:-$SRCDIR/flux-tx}

[ ! -x $FLUXD ] && echo "$FLUXD not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
FLUXVERSTR=$($FLUXCLI --version | head -n1 | awk '{ print $NF }')
FLUXVER=$(echo $FLUXVERSTR | awk -F- '{ OFS="-"; NF--; print $0; }')
FLUXCOMMIT=$(echo $FLUXVERSTR | awk -F- '{ print $NF }')

# Create a footer file with copyright content.
# This gets autodetected fine for fluxd if --version-string is not set,
# but has different outcomes for flux-cli.
echo "[COPYRIGHT]" > footer.h2m
$FLUXD --version | sed -n '1!p' >> footer.h2m

for cmd in $FLUXD $FLUXCLI $FLUXTX; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=$FLUXVER --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-$FLUXCOMMIT//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
