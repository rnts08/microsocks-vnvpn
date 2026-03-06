# MicroSocks Operational Runbook

This runbook documents day-2 operations for a production MicroSocks deployment.

## 1) Service lifecycle (systemd)

Assumes you installed the hardened unit at `contrib/systemd/microsocks.service` to `/etc/systemd/system/microsocks.service`.

### Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now microsocks
```

### Stop

```bash
sudo systemctl stop microsocks
```

### Restart

```bash
sudo systemctl restart microsocks
```

### Reload configuration

MicroSocks has no explicit hot-reload signal; use a controlled restart after config validation.

```bash
sudo /usr/local/bin/microsocks --config /etc/microsocks/microsocks.conf --print-config
sudo systemctl restart microsocks
```

### Health checks

```bash
sudo systemctl status microsocks --no-pager
sudo journalctl -u microsocks -n 100 --no-pager
```

## 2) Logging and rotation

If `-l`/`logfile` is configured, logs are plain text and should be rotated with `logrotate`.

Example `/etc/logrotate.d/microsocks`:

```conf
/var/log/microsocks/microsocks.log {
  daily
  rotate 14
  compress
  missingok
  notifempty
  create 0640 microsocks microsocks
  postrotate
    /bin/systemctl kill -s HUP microsocks.service >/dev/null 2>&1 || true
  endscript
}
```

Notes:
- If your build does not reopen logs on `HUP`, use `systemctl restart microsocks` in `postrotate` during low traffic windows.
- Keep journald enabled for unit-level diagnostics even when using file logs.

## 3) SQLite backup and restore

Use WAL mode for better write concurrency and online backups.

### Recommended SQLite pragmas

Run once during provisioning:

```bash
sqlite3 /var/lib/microsocks/microsocks.db 'PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;'
```

### Hot backup (online)

```bash
ts="$(date +%Y%m%d-%H%M%S)"
mkdir -p /var/backups/microsocks
sqlite3 /var/lib/microsocks/microsocks.db \
  ".timeout 5000" \
  ".backup /var/backups/microsocks/microsocks-${ts}.db"
sha256sum /var/backups/microsocks/microsocks-${ts}.db > /var/backups/microsocks/microsocks-${ts}.db.sha256
```

### Retention guidance

- Keep daily backups for 14 days.
- Keep weekly backups for 8 weeks.
- Store off-host copies (object storage or secondary region).
- Test restore at least monthly.

### Restore drill (staging)

```bash
# 1) Verify checksum
sha256sum -c /var/backups/microsocks/microsocks-YYYYmmdd-HHMMSS.db.sha256

# 2) Stop service before in-place restore
sudo systemctl stop microsocks

# 3) Restore DB atomically
sudo install -o microsocks -g microsocks -m 0640 \
  /var/backups/microsocks/microsocks-YYYYmmdd-HHMMSS.db \
  /var/lib/microsocks/microsocks.db

# 4) Validate integrity
sqlite3 /var/lib/microsocks/microsocks.db 'PRAGMA integrity_check;'

# 5) Start and verify
sudo systemctl start microsocks
sudo systemctl status microsocks --no-pager
```

## 4) Database maintenance

### Connections retention/pruning

Use server config `connections_retention_days` to enforce periodic cleanup in-process.

For one-off manual prune:

```bash
sqlite3 /var/lib/microsocks/microsocks.db \
  "DELETE FROM connections WHERE ts_timestamp < datetime('now','-90 day');"
```

### WAL checkpoint policy

If the WAL file grows unexpectedly, run:

```bash
sqlite3 /var/lib/microsocks/microsocks.db 'PRAGMA wal_checkpoint(TRUNCATE);'
```

### VACUUM cadence

Run during low traffic windows (weekly or monthly, based on churn):

```bash
sqlite3 /var/lib/microsocks/microsocks.db 'VACUUM;'
```

## 5) Incident response quick actions

### A) Suspected brute-force/auth abuse

1. Confirm spike in auth failures via logs.
2. Temporarily block abusive source IPs at firewall/reverse path ACL.
3. Tighten server-side abuse controls (`auth_fail_window_seconds`, `max_auth_fails_per_window`, `max_connections_per_ip`).
4. Rotate impacted user passwords using `msadmin`.

### B) DB growth or storage pressure

1. Check DB + WAL size.
2. Trigger manual retention prune and checkpoint.
3. Run `VACUUM` in maintenance window.
4. Revisit `connections_retention_days` and backup retention.

### C) Service down / crash loop

1. `systemctl status microsocks` and `journalctl -u microsocks`.
2. Verify DB file permissions and free disk space.
3. Validate config with `--print-config`.
4. Roll back to last-known-good binary or config.
5. If DB corruption is detected, restore from latest valid backup.

## 6) Upgrade + rollback checklist (operator level)

1. Capture pre-change backup (`.backup` + checksum).
2. Validate new binary in staging with representative auth/traffic.
3. Deploy binary and restart service.
4. Run smoke checks (auth success, auth fail, accounting increments, admin UI read path).
5. Monitor for 15-30 minutes.

Rollback:

1. Re-deploy previous binary.
2. Restore previous config.
3. If schema/data changed incompatibly, restore DB backup captured in step 1.

## 7) Suggested automation

- Systemd timer or cron for daily backups.
- Alert when:
  - unit is not `active`;
  - auth failures exceed baseline;
  - DB or WAL size growth exceeds threshold;
  - backup job fails or restore drill is overdue.
