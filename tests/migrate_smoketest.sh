#!/bin/bash
# Smoke test for migrate --non-interactive logging
set -euo pipefail
ROOT=$(dirname "$0")/..
cd "$ROOT"
DB="/tmp/msadmin_migrate_test.db"
rm -f "$DB"
# create minimal DB and insert plaintext account (bypass hashing)
sqlite3 "$DB" <<'SQL'
CREATE TABLE accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  whitelist TEXT,
  ts_created INTEGER NOT NULL,
  ts_updated INTEGER NOT NULL,
  ts_seen INTEGER NOT NULL,
  monthly_bandwidth INTEGER DEFAULT 0,
  m_bytes_sent INTEGER DEFAULT 0,
  m_bytes_received INTEGER DEFAULT 0,
  total_bytes_sent INTEGER DEFAULT 0,
  total_bytes_received INTEGER DEFAULT 0,
  online INTEGER DEFAULT 0
);
INSERT INTO accounts (username, password, ts_created, ts_updated, ts_seen) VALUES ('migrate_test', 'plainpass123', strftime('%s','now'), strftime('%s','now'), strftime('%s','now'));
SQL
# Run migrate non-interactively with log file
LOGDIR=/tmp
./msadmin migrate "$DB" --only-plaintext --yes --log-dir "$LOGDIR"
# find log file
LOGFILE=$(ls -1t "$LOGDIR"/migrate-*.log 2>/dev/null | head -n1 || true)
if [ -z "$LOGFILE" ]; then
  echo "No log file found" >&2
  exit 2
fi
echo "Found log: $LOGFILE"
# check that migration happened by inspecting DB
HASH=$(sqlite3 "$DB" "SELECT password FROM accounts WHERE username='migrate_test' LIMIT 1;")
if [[ "$HASH" == plainpass123 ]]; then
  echo "Password was not migrated" >&2
  exit 3
fi
# check log contains migrated line
if ! grep -q "migrated: id=" "$LOGFILE"; then
  echo "Log does not contain migrated entry" >&2
  exit 4
fi
echo "migrate_smoketest passed"
