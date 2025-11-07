#!/bin/bash
# Simple install test: run `make install DESTDIR=$PWD/dest` and verify
# that the example config ends up at $DESTDIR/etc/microsocks/microsocks.conf
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DEST="$PWD/dest"
rm -rf "$DEST"
mkdir -p "$DEST"

# Build first
make clean >/dev/null
make all >/dev/null

# Run install into DEST
make install DESTDIR="$DEST" >/dev/null

CFG="$DEST/etc/microsocks/microsocks.conf"
if [ -f "$CFG" ]; then
    echo "install test: PASS - $CFG exists"
    ls -l "$CFG"
    exit 0
else
    echo "install test: FAIL - $CFG missing"
    ls -l "$DEST" || true
    exit 2
fi
