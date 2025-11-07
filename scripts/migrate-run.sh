#!/bin/bash
# Simple migration wrapper for microsocks DB.
# Creates a timestamped backup, then runs msadmin migrate with provided args.
# Usage: migrate-run.sh /path/to/microsocks.db [--yes] [--only-plaintext|--rehash-needs] [user1 user2 ...]
set -euo pipefail
if [ $# -lt 1 ]; then
  echo "Usage: $0 /path/to/db [msadmin migrate args...]"
  exit 2
fi
DBPATH="$1"
shift
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="${DBPATH}.backup.${TIMESTAMP}"
echo "Backing up ${DBPATH} -> ${BACKUP}"
cp -- "$DBPATH" "$BACKUP"
if [ $? -ne 0 ]; then
  echo "Backup failed" >&2
  exit 1
fi
# Run msadmin migrate with remaining args
MSADMIN_BIN="$(dirname "$0")/../msadmin"
if [ ! -x "$MSADMIN_BIN" ]; then
  # fallback to PATH
  MSADMIN_BIN="msadmin"
fi
echo "Running migration"
"$MSADMIN_BIN" migrate "$DBPATH" "$@"
EXIT=$?
if [ $EXIT -eq 0 ]; then
  echo "Migration finished successfully"
else
  echo "Migration exited with code $EXIT" >&2
fi
exit $EXIT
