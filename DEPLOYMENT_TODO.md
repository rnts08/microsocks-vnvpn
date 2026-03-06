# Deployment TODO

This file tracks **remaining** work for production hardening and deployment planning.
Completed/fixed items are intentionally removed to keep this focused on open tasks.

## Open deployment tasks

- [ ] Add concurrency/load testing with documented capacity targets (CPU, memory, disk I/O).
- [ ] Add monitoring/alerting deployment examples (Prometheus scrape + baseline alerts for auth failures, error rates, DB growth).
- [ ] Add containerized deployment examples (Docker/Compose, optional Kubernetes).
- [ ] Add a production security guide for Flask admin deployment (TLS termination, network ACLs, secret rotation, optional SSO).

## Current database layout (reference)

SQLite schema currently in use:

- `accounts`: user identity/auth data, enable flag, timestamps, bandwidth quota, monthly/lifetime counters, online count.
- `connections`: per-connection logs with source/destination, status, byte counters, timestamp.
- `account_whitelist`: normalized per-account whitelist entries (`ip_cidr`) with uniqueness on (`account_id`, `ip_cidr`).

Indexes:

- `idx_connections_account_ts` on `connections(account_id, ts_timestamp)`
- `idx_connections_ts` on `connections(ts_timestamp)`
- `idx_account_whitelist_account` on `account_whitelist(account_id)`

## Tests currently performed

- `tests/test_install.sh`: build + install smoke test.
- `tests/msadmin_smoketest.sh`: account CRUD smoke test.
- `tests/migrate_smoketest.sh`: migration smoke test (plaintext -> hashed + log output).
- `tests/test_sighup.sh`: logfile reopen behavior on `SIGHUP`.
- `tests/test_socks5_accounting_concurrent.py`: concurrent end-to-end SOCKS5 auth/relay/accounting integration test.
