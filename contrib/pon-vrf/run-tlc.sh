#!/bin/bash
# Run cells of one TLA+ model: run-tlc.sh <model directory> <cell> [<cell> ...]
# Needs java and tla2tools.jar, in the model directory or named by TLA2TOOLS. Each cell's
# output goes to <cell>.out in the model directory, and one line a cell to summary.txt.
set -u
dir=$(cd "$1" && pwd) || exit 2
shift
jar=${TLA2TOOLS:-$dir/tla2tools.jar}
[ -f "$jar" ] || { echo "no tla2tools.jar: put one in $dir or set TLA2TOOLS" >&2; exit 2; }
spec=$(ls "$dir"/*.tla | grep -v _TTrace_ | head -1)
cd "$dir" || exit 2
: > summary.txt
for cell in "$@"; do
    java -XX:+UseParallelGC -Xmx"${TLC_HEAP:-10g}" -cp "$jar" tlc2.TLC -config "$cell.cfg" \
        -workers "${TLC_WORKERS:-auto}" -metadir "$(mktemp -d)" "$(basename "$spec")" > "$cell.out" 2>&1
    echo "== $cell rc=$? $(grep -E 'Invariant .* is violated|No error has been found|Error:' "$cell.out" | head -1) | $(grep -E 'distinct states found' "$cell.out" | tail -1)" >> summary.txt
done
cat summary.txt
