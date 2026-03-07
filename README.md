MicroSocks VPN Variant (SOCKS5 + SQLite Accounts)
=================================================

This repository contains a SOCKS5 proxy server (`microsocks`) extended with:

- Per-user authentication backed by SQLite.
- Per-user usage/accounting counters.
- Connection logging to a `connections` table.
- CLI and web admin tools for account management.

Core Components
---------------

- `microsocks` (C server): accepts SOCKS5 TCP CONNECT traffic and authenticates users against SQLite.
- `msadmin` (C CLI): creates, updates, lists, deletes users, and runs password migration/rehash checks.
- `microsocks-app/admin` (Flask app): basic web UI for managing users and viewing recent connection history.

Implemented Functionality
-------------------------

### SOCKS5 server behavior

- SOCKS5 CONNECT support for IPv4, IPv6, and DNS name targets.
- Username/password authentication (RFC 1929 style) using DB accounts.
- Per-account `enabled` flag check (disabled accounts cannot authenticate).
- Optional per-account source-IP whitelist (`accounts.whitelist` CSV).
- Connection accounting into:
  - Monthly counters (`m_bytes_sent`, `m_bytes_received`)
  - Lifetime counters (`total_bytes_sent`, `total_bytes_received`)
- Connection logs persisted in `connections` with destination, status, and byte counts.

### Database layout (SQLite)

The server auto-creates and maintains this schema:

- `accounts`
  - Identity/auth: `id`, `username` (unique), `password` (Argon2 hash)
  - Access control: `enabled`, `last_client_ip`
  - Legacy compatibility: `whitelist` (CSV field still read/written)
  - Timestamps: `ts_created`, `ts_updated`, `ts_seen`
  - Quotas/accounting: `monthly_bandwidth`, `m_bytes_sent`, `m_bytes_received`,
    `total_bytes_sent`, `total_bytes_received`, `online`
- `connections`
  - `id`, `account_id` (FK -> `accounts.id`), `client_ip`, `destination`, `status`
  - `bytes_sent`, `bytes_received`, `ts_timestamp`
  - Indexes:
    - `idx_connections_account_ts` on (`account_id`, `ts_timestamp`)
    - `idx_connections_ts` on (`ts_timestamp`)
- `account_whitelist`
  - Normalized whitelist entries: `id`, `account_id`, `ip_cidr`, `ts_created`
  - Uniqueness: (`account_id`, `ip_cidr`)
  - FK delete behavior: `ON DELETE CASCADE`
  - Index: `idx_account_whitelist_account` on (`account_id`)

SQLite is opened with `PRAGMA journal_mode=WAL` for better concurrency.

### Password handling

- New passwords are hashed with Argon2id via libsodium (`crypto_pwhash_str`) in C tools.
- Existing plaintext passwords are transparently re-hashed on successful login.
- Migration helper script is available at `scripts/migrate-run.sh` (see `MIGRATION.md`).

### Configuration

### Alternative API-backed auth/accounting backend

In addition to the default local SQLite request-path updates, `microsocks` can delegate authentication and live accounting updates to the Flask admin API.

Set these options in `microsocks.conf`:

```ini
auth_backend = api
admin_api_base_url = http://127.0.0.1:5000
admin_api_token = your-shared-token
admin_api_timeout_ms = 3000
```

Then set the same token on the admin service:

```bash
export SOCKS_API_TOKEN='your-shared-token'
```

When enabled:
- SOCKS username/password auth is performed via `POST /api/internal/socks/auth`.
- Session admission checks (enabled user, max concurrent, monthly quota) are performed via `POST /api/internal/socks/session/start`.
- Usage accounting is pushed continuously in-session via `POST /api/internal/socks/accounting`.
- Connection finalization/logging is pushed via `POST /api/internal/socks/session/end`.

This provides an alternative to direct local SQLite writes in the proxy process while preserving the same admin data model.


`microsocks` supports:

- config file (default `/etc/microsocks/microsocks.conf`)
- CLI overrides for listen address/port, database path, bind address, logfile, and quiet mode
- `--print-config` to print effective values and exit

Quick Start
-----------

Build:

```bash
make
```

Create first user (DB is auto-created if needed):

```bash
./msadmin add alice 'strong-password' 0
```

Run server:

```bash
./microsocks -i 0.0.0.0 -p 1080 -d ./microsocks.db
```

Test with curl:

```bash
curl --socks5 alice:strong-password@127.0.0.1:1080 https://example.com
```

Run web admin (optional):

```bash
cd microsocks-app/admin
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export DATABASE=/absolute/path/to/microsocks.db
export ADMIN_USER=admin
export ADMIN_PASS='replace-me'
export SECRET_KEY='replace-me-with-random-value'
python app.py
```


Observability (Prometheus + Grafana)
-----------------------------------

The server can expose a Prometheus-compatible endpoint over HTTP:

- `GET /metrics`: Prometheus text format
- `GET /healthz` or `GET /-/healthy`: simple health check returning `ok`

### Enable metrics endpoint

In `microsocks.conf`:

```ini
metrics_listen = 127.0.0.1
metrics_port = 9108
```

Set `metrics_port = 0` to disable the endpoint.

### Exported metrics

- `microsocks_auth_failures_total` (counter): failed auth attempts
- `microsocks_active_sessions` (gauge): active authenticated proxy sessions
- `microsocks_bytes_uploaded_total` (counter): bytes client -> target
- `microsocks_bytes_downloaded_total` (counter): bytes target -> client
- `microsocks_bytes_per_second` (gauge): average bytes/sec since process start
- `microsocks_db_calls_total` (counter): measured DB calls from request path
- `microsocks_db_latency_seconds_avg` (gauge): average DB latency
- `microsocks_db_latency_seconds_max` (gauge): max DB latency

### Prometheus scrape example

```yaml
scrape_configs:
  - job_name: microsocks
    static_configs:
      - targets: ["127.0.0.1:9108"]
```

If Prometheus runs on a different host, bind metrics to a reachable interface or use a reverse proxy.

### Grafana quick-start

1. Add Prometheus as a Grafana data source (`Configuration -> Data sources`).
2. Create a dashboard and use these PromQL queries:

- Auth failures per minute:
  - `rate(microsocks_auth_failures_total[1m])`
- Active sessions:
  - `microsocks_active_sessions`
- Upload throughput (bytes/sec):
  - `rate(microsocks_bytes_uploaded_total[1m])`
- Download throughput (bytes/sec):
  - `rate(microsocks_bytes_downloaded_total[1m])`
- DB latency average (ms):
  - `microsocks_db_latency_seconds_avg * 1000`
- DB latency max (ms):
  - `microsocks_db_latency_seconds_max * 1000`

### Alerting ideas

- High auth-failure rate:
  - `rate(microsocks_auth_failures_total[5m]) > 5`
- DB latency spike:
  - `microsocks_db_latency_seconds_avg > 0.050`
- Unexpectedly low active sessions (service degradation signal):
  - `microsocks_active_sessions == 0` (only where traffic is expected)

Test coverage
-------------

The repository includes these automated tests/checks:

- `tests/test_install.sh`
  - Builds binaries and verifies `make install DESTDIR=...` installs
    `etc/microsocks/microsocks.conf`.
- `tests/msadmin_smoketest.sh`
  - Exercises `msadmin` account lifecycle: add, list, show, delete.
- `tests/migrate_smoketest.sh`
  - Verifies `msadmin migrate` hashes plaintext passwords and writes a migration log.
- `tests/test_sighup.sh`
  - Verifies `microsocks` reopens logfiles correctly after `SIGHUP`.
- `tests/test_socks5_accounting_concurrent.py`
  - End-to-end concurrent SOCKS5 auth + relay/accounting test with many parallel
    requests through the proxy and DB counter verification.

For remaining deployment/planning work, see `DEPLOYMENT_TODO.md`.


Notes
-----

- For password migration details, see `MIGRATION.md`.
- For web admin details, see `microsocks-app/admin/README.md`.
