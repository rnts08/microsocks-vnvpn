#!/bin/bash
# Simple test to exercise SIGHUP handling and logfile reopen.
# - builds the project
# - runs microsocks with a temporary logfile and db
# - rotates logfile (mv), sends SIGHUP
# - triggers a minimal SOCKS5 greeting to cause server logging
# - verifies logfile reopened and contains log entries

set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BUILD="$ROOT/microsocks"
TMPLOG="/tmp/microsocks_test.log"
TMPDB="/tmp/microsocks_test.db"
PIDFILE="/tmp/microsocks_test.pid"

# Clean up function
cleanup() {
    if [ -f "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE") || true
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$PIDFILE"
    fi
    rm -f "$TMPLOG" "$TMPLOG".1 "$TMPDB"
}
trap cleanup EXIT

# Build
make clean >/dev/null
make all >/dev/null

# Start server in background with explicit logfile and db
"$BUILD" -L "$TMPLOG" -d "$TMPDB" &
pid=$!
echo "$pid" > "$PIDFILE"

# Wait for startup log or file creation
for i in {1..10}; do
    if [ -f "$TMPLOG" ]; then break; fi
    sleep 0.2
done

if [ ! -f "$TMPLOG" ]; then
    echo "Log file was not created; server startup may have failed"
    exit 2
fi

# Rotate logfile
mv "$TMPLOG" "$TMPLOG".1
# Signal SIGHUP to reopen
kill -HUP "$pid"

# Give it a moment
sleep 0.2

# Trigger a minimal SOCKS5 greeting to cause server-level logging
# send: VER=5, NMETHODS=1, METHODS=0x00
printf "\x05\x01\x00" | nc -w 1 127.0.0.1 1080 || true

sleep 0.5

# Check that new logfile exists and is not empty
if [ -f "$TMPLOG" ] && [ -s "$TMPLOG" ]; then
    echo "SIGHUP reopen test: PASS - logfile reopened and has data"
    cat "$TMPLOG" | tail -n 20
    exit 0
else
    echo "SIGHUP reopen test: FAIL - logfile not present or empty"
    ls -l /tmp/microsocks_test.log* || true
    exit 3
fi
