#!/usr/bin/env bash

# Build both macOS architectures, one after the other, and collect the
# binaries under mac-binaries/<triplet>/.
#
# This is a thin wrapper around zcutil/build.sh: it does not duplicate any of
# the build logic, it just runs build.sh twice with HOST pinned to each
# architecture and cleans the tree in between, because the two builds share
# src/ and would otherwise link objects of the wrong architecture together.

set -eu -o pipefail

function cmd_pref() {
    if type -p "$2" > /dev/null; then
        eval "$1=$2"
    else
        eval "$1=$3"
    fi
}

# If a g-prefixed version of the command exists, use it preferentially.
function gprefix() {
    cmd_pref "$1" "g$2" "$2"
}

gprefix READLINK readlink
cd "$(dirname "$("$READLINK" -f "$0")")/.."

if [[ -z "${MAKE-}" ]]; then
    MAKE=make
fi

HOSTS='aarch64-apple-darwin x86_64-apple-darwin'
BINARIES='fluxd flux-cli flux-tx'
OUTDIR="$PWD/mac-binaries"

# Pull out the arguments this script handles itself; everything else is
# forwarded to build.sh in the order it was given, since build.sh parses its
# own flags positionally.
UNIVERSAL=''
SHOW_HELP=''
BUILD_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --universal) UNIVERSAL=1 ;;
        --help)      SHOW_HELP=1 ;;
        *)           BUILD_ARGS+=("$arg") ;;
    esac
done

if [ -n "$SHOW_HELP" ]; then
    cat <<EOF
Usage:

$0 --help
  Show this help message and exit.

$0 [ --universal ] [ BUILD.SH ARGS... ]
  Build Flux for both macOS architectures, one at a time, and copy the
  resulting binaries to mac-binaries/<triplet>/.

  --universal additionally merges the two together with lipo into a single
  set of universal binaries in mac-binaries/universal/. Those run natively
  on both kinds of Mac from one file, at the cost of being the size of both
  builds combined. The per-architecture directories are still produced, so
  you can test an individual slice.

  Every other argument is passed through to zcutil/build.sh unchanged, so
  the usual flags and MAKEARGS work:

      $0 -j"\$(sysctl -n hw.ncpu)"
      $0 --universal -j"\$(sysctl -n hw.ncpu)"
      $0 --disable-tests -j8

  The architectures built are:

      aarch64-apple-darwin   -> arm64   (Apple Silicon)
      x86_64-apple-darwin    -> x86_64  (Intel, and Rosetta 2)

  One of the two is native and the other is cross-compiled; Xcode's clang
  targets both. BUILD is always pinned to the machine you are running on so
  that the native toolchain (including rustc) is used to drive the cross
  build rather than an emulated one.

  Each architecture gets its own dependency prefix under depends/, so the
  two dependency trees are built once and then coexist. Only the top-level
  src/ tree is shared, which is why it is cleaned between the two passes.
EOF
    exit 0
fi

if [ "$(uname -s)" != 'Darwin' ]; then
    echo "$0: this script only builds macOS targets; run it on a Mac." >&2
    exit 1
fi

# Same derivation as build.sh: uname -p reports plain "arm" on Apple Silicon,
# so use uname -m. Note this reflects the architecture of the *process*, so a
# shell running under Rosetta reports x86_64 on an M-series Mac.
case "$(uname -m)" in
    arm64|aarch64) BUILD_TRIPLET='aarch64-apple-darwin' ;;
    *)             BUILD_TRIPLET='x86_64-apple-darwin' ;;
esac

function expected_arch() {
    case "$1" in
        aarch64-apple-darwin) echo 'arm64' ;;
        x86_64-apple-darwin)  echo 'x86_64' ;;
        *) echo "$0: unknown host triplet $1" >&2; exit 1 ;;
    esac
}

echo "Build machine: $(uname -m) -> $BUILD_TRIPLET"
if [ "$BUILD_TRIPLET" = 'x86_64-apple-darwin' ] && [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = '1' ]; then
    echo
    echo "WARNING: this is an Apple Silicon machine, but the shell is running"
    echo "         under Rosetta, so uname -m reports x86_64. The x86_64 build"
    echo "         will be treated as native and the arm64 build as the cross"
    echo "         build. That still works, but it is slower. Run from a native"
    echo "         arm64 shell to avoid it."
    echo
fi

# Build the native architecture first, so that a failure in the cross build
# still leaves the more important binaries behind.
ORDERED_HOSTS="$BUILD_TRIPLET"
for host in $HOSTS; do
    if [ "$host" != "$BUILD_TRIPLET" ]; then
        ORDERED_HOSTS="$ORDERED_HOSTS $host"
    fi
done

rm -rf "$OUTDIR"

for HOST in $ORDERED_HOSTS; do
    want="$(expected_arch "$HOST")"

    echo
    echo "==============================================================="
    echo " Building $HOST ($want)"
    echo "==============================================================="
    echo

    # src/ is shared between the two passes, so objects from the previous
    # architecture must go before configure runs again for the new host.
    if [ -f Makefile ]; then
        "$MAKE" distclean > /dev/null 2>&1 || true
    fi

    # macOS still ships bash 3.2, where expanding an empty array under `set -u`
    # is an error; the ${x[@]+...} guard keeps a no-argument run working.
    HOST="$HOST" BUILD="$BUILD_TRIPLET" ./zcutil/build.sh ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"}

    mkdir -p "$OUTDIR/$HOST"
    for bin in $BINARIES; do
        if [ ! -f "src/$bin" ]; then
            echo "$0: expected src/$bin to exist after building $HOST" >&2
            exit 1
        fi
        got="$(lipo -archs "src/$bin")"
        if [ "$got" != "$want" ]; then
            echo "$0: src/$bin is '$got' but $HOST should produce '$want'" >&2
            exit 1
        fi
        cp -p "src/$bin" "$OUTDIR/$HOST/$bin"
    done
    echo
    echo "$HOST: $BINARIES -> $OUTDIR/$HOST ($want)"
    LAST_HOST="$HOST"
done

if [ -n "$UNIVERSAL" ]; then
    echo
    echo "==============================================================="
    echo " Merging into universal binaries"
    echo "==============================================================="
    echo

    mkdir -p "$OUTDIR/universal"
    for bin in $BINARIES; do
        inputs=''
        for HOST in $ORDERED_HOSTS; do
            inputs="$inputs $OUTDIR/$HOST/$bin"
        done

        # Word splitting on $inputs is intended here: it is a list of paths we
        # built ourselves, all under $OUTDIR.
        lipo -create $inputs -output "$OUTDIR/universal/$bin"

        # A universal binary that silently lost a slice would run fine on this
        # machine and fail on the other kind, so check every slice is present.
        for HOST in $ORDERED_HOSTS; do
            want="$(expected_arch "$HOST")"
            if ! lipo -archs "$OUTDIR/universal/$bin" | tr ' ' '\n' | grep -qx "$want"; then
                echo "$0: universal $bin is missing the $want slice" >&2
                exit 1
            fi
        done
        echo "  $bin -> $(lipo -archs "$OUTDIR/universal/$bin")"
    done
fi

echo
echo "==============================================================="
echo " Done"
echo "==============================================================="
for HOST in $ORDERED_HOSTS; do
    for bin in $BINARIES; do
        printf '  %-46s %s\n' "mac-binaries/$HOST/$bin" "$(lipo -archs "$OUTDIR/$HOST/$bin")"
    done
done
if [ -n "$UNIVERSAL" ]; then
    for bin in $BINARIES; do
        printf '  %-46s %s\n' "mac-binaries/universal/$bin" "$(lipo -archs "$OUTDIR/universal/$bin")"
    done
fi
echo
echo "The tree is currently configured for $LAST_HOST; run zcutil/build.sh"
echo "directly if you want a normal single-architecture working build."
