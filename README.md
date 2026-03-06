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

### Data model (SQLite)

Server/admin schema includes:

- `accounts`:
  - identity: `id`, `username`, `password`
  - access: `enabled`, `whitelist`, `last_client_ip`
  - timestamps: `ts_created`, `ts_updated`, `ts_seen`
  - quotas/accounting: `monthly_bandwidth`, monthly + lifetime byte counters, `online`
- `connections`:
  - `account_id`, `client_ip`, `destination`, `status`
  - `bytes_sent`, `bytes_received`, `ts_timestamp`

### Password handling

- New passwords are hashed with Argon2id via libsodium (`crypto_pwhash_str`) in C tools.
- Existing plaintext passwords are transparently re-hashed on successful login.
- Migration helper script is available at `scripts/migrate-run.sh` (see `MIGRATION.md`).

### Configuration

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

Deployment Readiness: TODO List
-------------------------------

The project is functional, but the following work should be done before production deployment:

1. Add proper service hardening docs and examples (systemd sandboxing, dedicated user/group, `ProtectSystem`, `NoNewPrivileges`, `PrivateTmp`).
2. Provide a documented backup/restore strategy for SQLite (hot backups, retention, restore drill).
3. Add database maintenance guidance (`VACUUM`, WAL checkpoint policy, log retention/rotation for `connections`).
4. Add observability endpoints or metrics export (Prometheus/textfile) for auth failures, active sessions, bytes/sec, and DB latency.
5. Add integration tests for end-to-end SOCKS5 auth + accounting under concurrent load.
6. Add load/performance sizing guide (expected users/throughput vs CPU, memory, and disk I/O).
7. Add release/versioned upgrade playbook (schema migrations, rollback steps).
8. Add a production security guide for the Flask admin (reverse proxy TLS, network ACLs, secret management, optional SSO).

Known Fix List (Code-Level Gaps)
--------------------------------

1. **Whitelist format is a comma-separated text field.**
   This is simple but brittle for management/auditing. Consider a normalized `account_whitelist` table with one row per IP/CIDR.

2. **Server-side rate limiting / abuse protection is absent.**
   Add controls for auth brute force, per-IP connection rate, and max concurrent sessions per account.

3. **Flask admin now enforces safer startup defaults.**
   It refuses to start with `admin/admin`, empty password, or weak/default `SECRET_KEY`, and debug is opt-in via `FLASK_DEBUG=1`.

4. **Connection-log retention policy is not implemented.**
   `connections` can grow without bounds; add retention/archival and cleanup tooling.


Notes
-----

- For password migration details, see `MIGRATION.md`.
- For web admin details, see `microsocks-app/admin/README.md`.
