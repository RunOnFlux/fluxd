#!/bin/bash
HOST=x86_64-w64-mingw32
CXX=x86_64-w64-mingw32-g++-posix
CC=x86_64-w64-mingw32-gcc-posix
PREFIX="$(pwd)/depends/$HOST"

patch -p1 < buildwin.patch
set -eu -o pipefail

# If --disable-rust is the next argument, disable Rust code:
RUST_ARG=''
if [ "x${1:-}" = 'x--disable-rust' ]
then
    RUST_ARG='--enable-rust=no'
    shift
fi

set -x
cd "$(dirname "$(readlink -f "$0")")/.."


cd depends/ && make HOST=$HOST V=1 NO_QT=1 NO_RUST="$RUST_ARG" && cd ../
./autogen.sh
CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site CXXFLAGS+=" -fopenmp" ./configure --prefix="${PREFIX}" --host=x86_64-w64-mingw32 --enable-static --disable-zmq --disable-rust "$RUST_ARG"
sed -i 's/-lboost_system-mt /-lboost_system-mt-s /' configure
cd src/
CC="${CC}" CXX="${CXX}" make V=1 zelcashd.exe zelcash-cli.exe zelcash-tx.exe
