# MicroSocks Admin (Flask)

## Simple Flask web admin for the MicroSocks SQLite DB

## Features

- List accounts
- Show account details (including recent connections)
- Add account (password hashed with Argon2)
- Update account (password and monthly_bandwidth)
- Delete account (confirmation)

## Requirements

- Python 3.8+
- Install dependencies:

```bash
    pip install -r requirements.txt
```

## Run

- By default the app expects the DB at ../microsocks.db relative to the admin folder. You can override with the DATABASE env var:

```bash
    export DATABASE=/path/to/microsocks.db
    python app.py
```

- Visit <http://127.0.0.1:5000/> to use the UI. The app also supports JSON responses when the client prefers JSON (Accept header).

Notes

- This is a minimal admin UI intended for local or internal use only; add authentication and CSRF protection before exposing publicly.
- It creates the DB schema if the database file is missing.

Virtualenv / development environment

- Create and activate a virtualenv (recommended):

```bash
python3 -m venv .venv
source .venv/bin/activate
```

- Install dependencies:

```bash
pip install -r requirements.txt
```

- Export optional configuration (example):

```bash
export DATABASE=/path/to/microsocks.db
export ADMIN_USER=admin
export ADMIN_PASS=secret
export SECRET_KEY="a-strong-secret-for-csrf-and-sessions"
```

- Run the app:

```bash
python app.py
```

Security note: The app now includes HTTP Basic authentication and CSRF protection, but it is still minimal and intended for internal use. Use a strong SECRET_KEY and secure the admin endpoint behind a firewall or reverse proxy (with TLS) in production.
