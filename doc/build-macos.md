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
brew install autoconf automake libtool pkg-config
```

Those four are genuinely required: `libsodium`'s `autogen.sh` runs at
preprocess time, so autoconf/automake/libtool must be present even though the
release tarball ships a `configure`.

A few packages that older revisions of this document listed are *not* required
on a current macOS:

* `coreutils` — only needed on macOS 12 and earlier. `zcutil/build.sh` prefers
  `greadlink` but falls back to `readlink`, and BSD `readlink` grew `-f` in
  macOS 13.
* `wget` — `depends` and `fetch-params.sh` both prefer `curl`, which ships with
  the OS.
* `cmake` — only needed if you pass `--enable-proton`. The default build has
  `proton` disabled and never invokes cmake.

The build uses the SDK reported by `xcrun --show-sdk-path`. If you have several
Xcode versions installed, select the one you want with `xcode-select -s` (or
`DEVELOPER_DIR`) before building.

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
cross-compiler. Set `HOST` to what you want to produce and leave `BUILD` as the
machine you are on:

```sh
# on an Apple Silicon Mac, produce an x86_64 binary
HOST=x86_64-apple-darwin BUILD=aarch64-apple-darwin ./zcutil/build.sh -j8

# on an Intel Mac, produce an arm64 binary
HOST=aarch64-apple-darwin BUILD=x86_64-apple-darwin ./zcutil/build.sh -j8
```

`BUILD` is the machine running the compiler, not the target. Setting it to the
target instead makes `depends` fetch the Rust toolchain for the target and run
it under emulation: `depends/packages/rust.mk` picks the compiler tarball by
`build_arch` and the `rust-std` by `HOST`, so with `BUILD` set correctly you get
a native `rustc` cross-compiling, which is both correct and faster.

The dependency trees are kept in separate prefixes, so the two can coexist.

Building both at once
---------------------

`zcutil/buildmac.sh` runs the whole thing twice and collects the results:

```sh
./zcutil/buildmac.sh -j"$(sysctl -n hw.ncpu)"
```

```
mac-binaries/aarch64-apple-darwin/{fluxd,flux-cli,flux-tx}
mac-binaries/x86_64-apple-darwin/{fluxd,flux-cli,flux-tx}
```

Add `--universal` to also merge the two with `lipo` into
`mac-binaries/universal/`:

```sh
./zcutil/buildmac.sh --universal -j"$(sysctl -n hw.ncpu)"
```

A universal binary carries a complete copy of each architecture and the kernel
selects the matching one at exec time, so it runs natively on both kinds of Mac
from a single file — no Rosetta, and no way for someone to download the wrong
one. The cost is size: `fluxd` is about 13 MB arm64, 14 MB x86_64 and 28 MB
universal, since nothing is shared between the slices. The per-architecture
directories are still produced, so an individual slice can still be tested.

Sign *after* merging, not before — `codesign` handles all slices of a universal
binary in one pass, and notarization accepts them. Only ever merge binaries from
the same build; `lipo` will happily combine two different commits into a file
that behaves differently depending on the machine it lands on.

It is a wrapper around `build.sh` and duplicates none of its logic; all
arguments are passed straight through. It builds the native architecture first,
pins `BUILD` to the machine for both passes, checks each binary with
`lipo -archs` before accepting it, and runs `make distclean` between the two
passes — `depends` is already per-host, but the top-level `src/` tree is shared
and would otherwise link objects of the wrong architecture.

Either kind of Mac can build both. An Apple Silicon machine is the better choice
for release builds because it can also *run* both results — arm64 natively and
x86_64 under Rosetta 2 — whereas an Intel Mac cannot execute the arm64 binary it
produces.

Verifying the result
--------------------

```sh
lipo -archs src/fluxd
file src/fluxd
```

`lipo -archs` should print `arm64` for an Apple Silicon build and `x86_64` for an
Intel build.

Running the tests
-----------------

The gtest suite needs the Sapling proving parameters, which
`./zcutil/fetch-params.sh` installs into
`~/Library/Application Support/ZcashParams`. Without them every shielded test
aborts with `couldn't load Sapling spend parameters file`.

```sh
./zcutil/fetch-params.sh
./src/flux-gtest
```

`flux-gtest` is the only suite this tree builds; the Boost.Test targets in
`src/Makefile.test.include` are deprecated and their include is commented out in
`src/Makefile.am`, so `test/test_bitcoin` is never produced.

`WalletTests.CachedWitnessesCleanIndex` currently fails. It is not an Apple
Silicon problem: an x86_64 build of the same commit fails it identically, with
the same anchor values, so arm64 is at parity with Intel at 230/231.

Deployment target
-----------------

`depends/hosts/darwin.mk` sets `OSX_MIN_VERSION=11.0`. macOS 11 is the first
release to support Apple Silicon, and is also the minimum required for the
`std::filesystem` symbols used by the wallet.

Notes for the next person
-------------------------

Things that broke bringing this up on Apple Silicon, and where they were fixed.
None of these need action any more; they are recorded so the symptoms are
searchable.

**`configure: error: C compiler cannot create executables` on the first
`depends` package.** The real error is further up in the package's `config.log`:

```
ld: library 'System' not found
```

`xcrun -f clang` returns the compiler inside `XcodeDefault.xctoolchain`, not the
`/usr/bin/clang` shim. Only the shim exports `SDKROOT`, so the raw driver never
finds the macOS SDK and the link step has no `libSystem` to resolve against.
`depends/builders/darwin.mk` now passes `-isysroot` explicitly for both the
build-machine and host compilers. The stray
`ld: warning: search path '.../native/lib' not found` on the same line is
harmless and unrelated — those directories are created later.

**Wallet tests failing with `CDB: Failed to open database environment`,
`db.log` showing `BDB2015 Unable to acquire/release a mutex` and
`BDB0061 PANIC: BDB0069 DB_LOCK_NOTGRANTED`.** Berkeley DB 6.2.23's aarch64
test-and-set macro returns the complement of its documented result, so every
mutex acquisition was inverted. `depends/patches/bdb/arm64-mutex.patch` replaces
the assembly with `__atomic_exchange_n`.

Despite the name, that code path is reachable only on Apple platforms, for two
independent reasons. BDB's probe for it tests `defined(__arm64__)`, which is an
Apple spelling — GCC and Clang on aarch64 Linux define only `__aarch64__`. And
every assembly probe in `dist/aclocal/mutex.m4` is guarded by
`test "$db_cv_mutex" = no`, while the POSIX pthreads probe that runs earlier is
skipped *only* for `darwin*`. So aarch64 Linux selects `POSIX/pthreads` and
never compiles the broken macro; the patch is inert there.

**`fetch-params.sh` aborting with `usage: sha256sum [-bctwz] [files ...]` after
a successful download.** Current macOS ships a BSD `/sbin/sha256sum` whose `-c`
cannot read digests from stdin. The script now probes for that behaviour rather
than assuming GNU semantics whenever a `sha256sum` binary exists.

**`depends/config.guess` reporting `arm-apple-darwin`.** It takes the Darwin CPU
from `uname -p`, which is plain `arm` on Apple Silicon and canonicalises to
32-bit ARM. `build.sh` uses `uname -m` instead. A side effect is that package
`configure` scripts still self-detect the build machine as
`arm-apple-darwin<version>` while `--host` says `aarch64-apple-darwin`, so they
believe they are cross-compiling. That is harmless for the packages built here,
but it is why `configure` output looks inconsistent.
