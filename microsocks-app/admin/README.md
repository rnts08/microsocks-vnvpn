# MicroSocks Admin (Flask)

Minimal web administration UI for the MicroSocks SQLite database.

## What it does

- HTTP Basic auth gate for all non-static routes.
- CSRF protection via Flask-WTF.
- List accounts and show per-user usage/accounting fields.
- Show recent connection records for a selected user.
- Add/update/delete users.
- Update per-user monthly bandwidth and whitelist.
- JSON responses for list/detail/stat routes when requested.

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
# optional local-dev bypass only:
# export ALLOW_INSECURE_DEFAULTS=1
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

## Current gaps

- No RBAC/multi-admin support.
- No account lockout or login throttling.
- No built-in retention management for large `connections` tables.
- Uses HTTP Basic auth only (no MFA/session policy).
- `ALLOW_INSECURE_DEFAULTS=1` bypass exists for local development and must not be used in production.

See repository root `README.md` for system-wide deployment TODO/fix items.
