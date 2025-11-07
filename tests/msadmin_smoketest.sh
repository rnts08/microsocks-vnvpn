#!/bin/bash
set -euo pipefail

WD=$(pwd)
TMPDB="${WD}/test_microsocks.db"

# cleanup
rm -f "$TMPDB"

# ensure msadmin exists
if [ ! -x ./msadmin ]; then
  echo "msadmin binary not found. Run make first." >&2
  exit 2
fi

# create account
./msadmin -d "$TMPDB" add testuser testpass 1000000

# list accounts (CSV)
echo "--- list (csv) ---"
./msadmin -d "$TMPDB" -c list

# show account
echo "--- show testuser ---"
./msadmin -d "$TMPDB" show testuser

# delete account (non-interactive)
./msadmin -d "$TMPDB" delete testuser

echo "--- list after delete ---"
./msadmin -d "$TMPDB" -c list || true

# cleanup
rm -f "$TMPDB"

echo "smoketest completed"
