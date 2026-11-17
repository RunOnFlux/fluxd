#!/usr/bin/env bash
# Rebuild fluxd amd64 exactly as CI does (.github/workflows/build_release.yml)
# and print the stripped binary checksums, so a second builder can confirm a
# release.
#
#   contrib/repro-build.sh v9.1.1          # a release tag
#   contrib/repro-build.sh <commit-sha>    # any commit
#
# Needs git and Docker. Compare the output with SHA256SUMS-amd64.txt on the
# GitHub release; the two must match byte for byte.
set -euo pipefail

REF="${1:?usage: $0 <tag-or-commit>}"
IMAGE="ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214"
GCC11="11.5.0-10ubuntu1~20~ppa3"   # keep in sync with build_release.yml
REPO_DIR="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
OUT_DIR="${OUT_DIR:-$PWD/repro-out}"
JOBS="${JOBS:-$(nproc)}"   # parallelism does not change the output

COMMIT="$(git -C "$REPO_DIR" rev-parse --verify "$REF^{commit}")"
SOURCE_DATE_EPOCH="$(git -C "$REPO_DIR" log -1 --format=%ct "$COMMIT")"

# The build embeds its path, so build at the same path CI uses:
# /__w/fluxd/fluxd.
WORK="$(mktemp -d)"
trap 'docker run --rm -v "$WORK:/w" "$IMAGE" rm -rf /w/fluxd >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT
git clone -q --no-checkout "$REPO_DIR" "$WORK/fluxd"
# Also fetch every other ref (remote-tracking branches, PR merge refs), so
# any commit in this repo can be built, even from a shallow clone.
git -C "$WORK/fluxd" fetch -q "$REPO_DIR" '+refs/*:refs/source/*'
git -C "$WORK/fluxd" checkout -q --detach "$COMMIT"
# CI clones with only the tag being released (or no tags for a commit); the
# version string comes from `git describe`, so match that.
git -C "$WORK/fluxd" tag -l | while read -r t; do
    if [[ "$t" != "$REF" ]]; then git -C "$WORK/fluxd" tag -d "$t" >/dev/null; fi
done

mkdir -p "$OUT_DIR"
docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive \
    -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
    -e GCC11="$GCC11" -e JOBS="$JOBS" \
    -v "$WORK:/__w/fluxd" \
    -v "$OUT_DIR:/out" \
    "$IMAGE" bash -euo pipefail -c '
        ln -fs /usr/share/zoneinfo/UTC /etc/localtime
        apt-get update -qq
        # Same packages as the amd64 CI job
        apt-get install -y -qq software-properties-common >/dev/null
        add-apt-repository -y ppa:ubuntu-toolchain-r/test >/dev/null
        apt-get update -qq
        apt-get install -y -qq build-essential pkg-config libc6-dev m4 autoconf libtool unzip git wget curl bsdmainutils automake ncurses-dev python3 python3-zmq zlib1g-dev gcc-11=$GCC11 g++-11=$GCC11 g++-11-multilib=$GCC11 cpp-11=$GCC11 >/dev/null
        update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 100
        update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-11 100
        git config --global --add safe.directory /__w/fluxd/fluxd
        cd /__w/fluxd/fluxd
        ./zcutil/build.sh -j"$JOBS" > /out/build.log 2>&1
        dpkg -l | awk "/^ii/ {print \$2, \$3}" > /out/packages.txt
        mkdir -p /tmp/s && cp src/fluxd src/flux-cli src/flux-tx /tmp/s/ && strip /tmp/s/*
        (cd /tmp/s && sha256sum fluxd flux-cli flux-tx) > /out/SHA256SUMS-amd64.txt
    '

echo "commit $COMMIT  SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
cat "$OUT_DIR/SHA256SUMS-amd64.txt"
