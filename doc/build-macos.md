macOS Build Instructions
========================

Flux builds natively on both Intel and Apple Silicon Macs. The architecture is
selected from the `HOST` triplet passed to `depends`; the default is derived from
the machine you are building on, so a stock build on an M-series Mac produces an
arm64 binary and needs no Rosetta.

Prerequisites
-------------

Install the Xcode command line tools and the build dependencies:

```sh
xcode-select --install
brew install autoconf automake libtool pkg-config coreutils wget
```

`coreutils` is required for `greadlink`, which `zcutil/build.sh` uses.

Building
--------

```sh
./zcutil/fetch-params.sh
./zcutil/build.sh -j"$(sysctl -n hw.ncpu)"
```

`build.sh` selects the triplet from `uname -m`:

| Machine        | Triplet                 | Dependency prefix                 |
| -------------- | ----------------------- | --------------------------------- |
| Apple Silicon  | `aarch64-apple-darwin`  | `depends/aarch64-apple-darwin`     |
| Intel          | `x86_64-apple-darwin`   | `depends/x86_64-apple-darwin`      |

Note that `depends/config.guess` cannot be used to derive this: on Apple Silicon
it reports the CPU as plain `arm` (from `uname -p`), which canonicalises to
32-bit ARM. `build.sh` therefore derives the triplet from `uname -m` instead.

Building for the other architecture
-----------------------------------

Both directions work from either machine, since Xcode's clang is a
cross-compiler. Set `HOST` and `BUILD` explicitly:

```sh
# arm64 binary
HOST=aarch64-apple-darwin BUILD=aarch64-apple-darwin ./zcutil/build.sh -j8

# x86_64 binary (runs under Rosetta 2 on Apple Silicon)
HOST=x86_64-apple-darwin BUILD=x86_64-apple-darwin ./zcutil/build.sh -j8
```

The dependency trees are kept in separate prefixes, so the two can coexist.

Verifying the result
--------------------

```sh
lipo -archs src/fluxd
file src/fluxd
```

`lipo -archs` should print `arm64` for an Apple Silicon build and `x86_64` for an
Intel build.

Deployment target
-----------------

`depends/hosts/darwin.mk` sets `OSX_MIN_VERSION=11.0`. macOS 11 is the first
release to support Apple Silicon, and is also the minimum required for the
`std::filesystem` symbols used by the wallet.
