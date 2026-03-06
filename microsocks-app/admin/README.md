# MicroSocks Admin (Flask)

Minimal web administration UI for the MicroSocks SQLite database.

## What it does

- Session-based login page for admin operators.
- CSRF protection via Flask-WTF.
- List accounts and show per-user usage/accounting fields.
- Show recent connection records for a selected user.
- Add/update/delete users.
- Update per-user monthly bandwidth and whitelist.
- JSON responses for list/detail/stat routes when requested.
- Includes sales modules backed by SQLite tables for `packages`, `orders`, and `transactions` with a sales dashboard.

## Important behavior

- DB path is controlled by `DATABASE` env var (default `../microsocks.db` relative to admin folder).
- Schema bootstrap is automatic at startup (`init_db()` uses the same `accounts` + `connections` layout as server code).
- Passwords created/updated by this UI are Argon2-hashed (`argon2-cffi`).

## Run

```bash
cd microsocks-app/admin
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export DATABASE=/absolute/path/to/microsocks.db
export ADMIN_USER=admin
export ADMIN_PASS='replace-me'
export SECRET_KEY='replace-me-with-random-value'
# optional multi-admin + role config (admin|viewer):
# export ADMIN_USERS='alice:strongpass:admin;bob:readonlypass:viewer'
# optional auth/session hardening:
# export ADMIN_SESSION_TTL_SECONDS=1800
# export ADMIN_MAX_FAILED_ATTEMPTS=5
# export ADMIN_LOCKOUT_WINDOW_SECONDS=900
# export ADMIN_LOCKOUT_DURATION_SECONDS=900
# optional connection-log retention (0 disables retention):
# export CONNECTION_RETENTION_DAYS=90
# optional debug mode (default is off):
# export FLASK_DEBUG=1

python app.py
```

Then open <http://127.0.0.1:5000/>.

## Security notes

This app is intentionally small and should be treated as an internal admin tool.

For production use, at minimum:

1. Run behind TLS (reverse proxy).
2. Restrict network access (VPN/private subnet/IP allowlist).
3. Set strong `ADMIN_USER`/`ADMIN_PASS` and a strong random `SECRET_KEY`.
4. Flask debug mode is **off by default**; only enable with `FLASK_DEBUG=1` for local development.
5. Add centralized auth (SSO/OIDC) and audit logging if this becomes multi-operator.

## Current status

- Supports multi-admin credential sets via `ADMIN_USERS` with per-user role (`admin` or `viewer`).
- Enforces login throttling and temporary lockout after repeated failed attempts.
- Supports built-in `connections` retention cleanup via `CONNECTION_RETENTION_DAYS` and manual cleanup action.
- Uses session-based auth with idle session timeout (`ADMIN_SESSION_TTL_SECONDS`).
- Refuses to start with insecure default credentials/secret values.

See repository root `README.md` for system-wide deployment TODO/fix items.
