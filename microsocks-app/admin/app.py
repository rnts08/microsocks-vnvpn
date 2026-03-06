from flask import (
    Flask,
    g,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    session,
)
import sqlite3
import os
import time
import hmac
from functools import wraps
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')

DATABASE = os.environ.get('DATABASE', os.path.join(os.path.dirname(__file__), '..', 'microsocks.db'))
PH = PasswordHasher()
csrf = CSRFProtect()
csrf.init_app(app)

DEFAULT_ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
DEFAULT_ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin')

SESSION_TTL_SECONDS = int(os.environ.get('ADMIN_SESSION_TTL_SECONDS', '1800'))
MAX_FAILED_ATTEMPTS = int(os.environ.get('ADMIN_MAX_FAILED_ATTEMPTS', '5'))
LOCKOUT_WINDOW_SECONDS = int(os.environ.get('ADMIN_LOCKOUT_WINDOW_SECONDS', '900'))
LOCKOUT_DURATION_SECONDS = int(os.environ.get('ADMIN_LOCKOUT_DURATION_SECONDS', '900'))
CONNECTION_RETENTION_DAYS = int(os.environ.get('CONNECTION_RETENTION_DAYS', '0'))
RETENTION_CHECK_INTERVAL_SECONDS = 3600
_last_retention_run = 0


def _is_truthy(value: str) -> bool:
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on')


def _parse_admins():
    """
    ADMIN_USERS format:
      user:pass:role;viewer1:pass:viewer
    role can be admin|viewer (default admin).
    """
    raw = os.environ.get('ADMIN_USERS', '').strip()
    admins = {}
    if raw:
        for chunk in raw.split(';'):
            if not chunk.strip():
                continue
            parts = chunk.split(':')
            username = parts[0].strip()
            password = parts[1] if len(parts) > 1 else ''
            role = (parts[2] if len(parts) > 2 else 'admin').strip().lower()
            if role not in ('admin', 'viewer'):
                role = 'viewer'
            admins[username] = {'password': password, 'role': role}
    else:
        admins[DEFAULT_ADMIN_USER] = {'password': DEFAULT_ADMIN_PASS, 'role': 'admin'}
    return admins


ADMINS = _parse_admins()


def validate_security_config():
    """Fail fast on insecure defaults."""
    errors = []

    secret_key = app.secret_key or ''
    if secret_key in ('dev-secret', 'replace-me-with-random-value', ''):
        errors.append('Set a strong random SECRET_KEY.')

    for username, data in ADMINS.items():
        if not username.strip():
            errors.append('Admin username cannot be empty.')
        if data['password'].strip() == '':
            errors.append(f'Password for admin user {username!r} cannot be empty.')
        if username == 'admin' and data['password'] == 'admin':
            errors.append('Refusing to run with default admin/admin credentials.')

    if errors:
        raise RuntimeError('Unsafe admin configuration. ' + ' '.join(errors))


# Schema taken from db.c (keeps compatibility with existing DB)
SCHEMA_SQL = '''
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  whitelist TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  last_client_ip TEXT,
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

CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL,
  client_ip TEXT NOT NULL,
  destination TEXT NOT NULL,
  status TEXT NOT NULL,
  bytes_sent INTEGER NOT NULL,
  bytes_received INTEGER NOT NULL,
  ts_timestamp INTEGER NOT NULL,
  FOREIGN KEY(account_id) REFERENCES accounts(id)
);

CREATE TABLE IF NOT EXISTS admin_login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  client_ip TEXT NOT NULL,
  success INTEGER NOT NULL,
  ts_attempt INTEGER NOT NULL
);
'''


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        g._database = db
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    db = get_db()
    db.executescript(SCHEMA_SQL)
    db.commit()


def _client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'


def _record_login_attempt(username: str, success: bool):
    db = get_db()
    db.execute(
        'INSERT INTO admin_login_attempts(username, client_ip, success, ts_attempt) VALUES(?, ?, ?, ?)',
        (username, _client_ip(), 1 if success else 0, int(time.time())),
    )
    db.commit()


def _is_locked_out(username: str) -> tuple[bool, int]:
    db = get_db()
    now = int(time.time())
    since = now - LOCKOUT_WINDOW_SECONDS
    row = db.execute(
        '''SELECT MAX(ts_attempt) AS last_failure, COUNT(*) AS failures
           FROM admin_login_attempts
           WHERE username = ? AND client_ip = ? AND success = 0 AND ts_attempt >= ?''',
        (username, _client_ip(), since),
    ).fetchone()
    failures = int(row['failures'] or 0)
    last_failure = int(row['last_failure'] or 0)
    if failures < MAX_FAILED_ATTEMPTS or last_failure == 0:
        return False, 0
    retry_at = last_failure + LOCKOUT_DURATION_SECONDS
    if now < retry_at:
        return True, retry_at - now
    return False, 0


def _run_connection_retention_if_needed(force: bool = False):
    global _last_retention_run
    if CONNECTION_RETENTION_DAYS <= 0:
        return
    now = int(time.time())
    if not force and (now - _last_retention_run) < RETENTION_CHECK_INTERVAL_SECONDS:
        return
    cutoff = now - (CONNECTION_RETENTION_DAYS * 24 * 3600)
    db = get_db()
    db.execute('DELETE FROM connections WHERE ts_timestamp < ?', (cutoff,))
    db.commit()
    _last_retention_run = now


def require_login(role: str | None = None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = session.get('admin_user')
            user_role = session.get('admin_role')
            last_seen = int(session.get('last_seen', 0))
            now = int(time.time())

            if not user:
                return redirect(url_for('login', next=request.path))

            if last_seen and (now - last_seen) > SESSION_TTL_SECONDS:
                session.clear()
                flash('Session expired. Please log in again.', 'warning')
                return redirect(url_for('login', next=request.path))

            session['last_seen'] = now
            if role == 'admin' and user_role != 'admin':
                flash('This action requires admin privileges.', 'error')
                return redirect(url_for('index'))
            return fn(*args, **kwargs)

        return wrapped

    return decorator


@app.before_request
def apply_security_hooks():
    public_endpoints = {'login', 'static'}
    if request.endpoint in public_endpoints:
        return None
    _run_connection_retention_if_needed(force=False)
    return None


@app.context_processor
def inject_auth_context():
    return {
        'admin_user': session.get('admin_user'),
        'admin_role': session.get('admin_role'),
        'is_admin': session.get('admin_role') == 'admin',
    }


@app.template_filter('bytes_to_gb')
def bytes_to_gb(value):
    return f'{value / 1_000_000_000:.2f} GB'


@app.template_filter('human_readable')
def human_readable(num_bytes):
    if num_bytes is None:
        return '0 B'

    step_unit = 1000.0
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(num_bytes)
    for unit in units:
        if size < step_unit:
            return f"{size:.2f} {unit}"
        size /= step_unit
    return f"{size:.2f} PB"


def hash_password(password: str) -> str:
    return PH.hash(password)


def verify_password(stored: str, provided: str) -> bool:
    try:
        return PH.verify(stored, provided)
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception:
        return False


@app.route('/login', methods=['GET', 'POST'])
def login():
    next_path = request.args.get('next') or request.form.get('next') or url_for('index')
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        locked, seconds_left = _is_locked_out(username)
        if locked:
            flash(f'Too many failed attempts. Try again in {seconds_left} seconds.', 'error')
            return render_template('login.html', next_path=next_path), 429

        admin = ADMINS.get(username)
        if not admin:
            _record_login_attempt(username, False)
            flash('Invalid credentials.', 'error')
            return render_template('login.html', next_path=next_path), 401

        ok_pass = hmac.compare_digest(password, admin['password'])
        if not ok_pass:
            _record_login_attempt(username, False)
            flash('Invalid credentials.', 'error')
            return render_template('login.html', next_path=next_path), 401

        _record_login_attempt(username, True)
        session.clear()
        session['admin_user'] = username
        session['admin_role'] = admin['role']
        session['last_seen'] = int(time.time())
        return redirect(next_path)

    return render_template('login.html', next_path=next_path)


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('login'))


@app.route('/')
@require_login()
def index():
    db = get_db()
    cur = db.execute('''SELECT username, monthly_bandwidth, m_bytes_sent, m_bytes_received, total_bytes_sent, total_bytes_received, online, datetime(ts_seen,'unixepoch') as last_seen, last_client_ip AS last_ip FROM accounts ORDER BY username''')
    rows = cur.fetchall()
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        users = []
        for r in rows:
            users.append({
                'username': r['username'],
                'monthly_bandwidth': r['monthly_bandwidth'],
                'monthly_used': (r['m_bytes_sent'] + r['m_bytes_received']),
                'total_used': (r['total_bytes_sent'] + r['total_bytes_received']),
                'online': r['online'],
                'last_seen': r['last_seen'],
                'last_ip': r['last_ip']
            })
        return jsonify(users)
    return render_template('list.html', rows=rows)


@app.route('/user/<username>')
@require_login()
def show_user(username):
    db = get_db()
    cur = db.execute('''SELECT id, username, password, whitelist, monthly_bandwidth, m_bytes_sent, m_bytes_received, total_bytes_sent, total_bytes_received, online, datetime(ts_created,'unixepoch') as created, datetime(ts_updated,'unixepoch') as updated, datetime(ts_seen,'unixepoch') as last_seen FROM accounts WHERE username = ?''', (username,))
    row = cur.fetchone()
    if not row:
        if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
            return jsonify({'error': 'not found'}), 404
        flash('Account not found', 'error')
        return redirect(url_for('index'))

    conn_cur = db.execute('''SELECT datetime(ts_timestamp,'unixepoch') as ts, client_ip, destination, status, bytes_sent, bytes_received FROM connections WHERE account_id = ? ORDER BY ts_timestamp DESC LIMIT 5''', (row['id'],))
    conns = conn_cur.fetchall()

    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        data = dict(row)
        data['recent_connections'] = [dict(c) for c in conns]
        return jsonify(data)

    return render_template('show.html', row=row, conns=conns)


@app.route('/user/<username>/usage.json')
@require_login()
def user_usage_json(username):
    db = get_db()

    range_param = request.args.get('range', '30d')
    now = int(time.time())
    if range_param == '7d':
        since = now - 7 * 24 * 3600
    elif range_param == '30d':
        since = now - 30 * 24 * 3600
    else:
        since = 0

    cur = db.execute('''
        SELECT date(datetime(c.ts_timestamp, 'unixepoch')) AS day,
               SUM(c.bytes_sent) AS sent,
               SUM(c.bytes_received) AS received
        FROM connections AS c
        JOIN accounts AS a ON c.account_id = a.id
        WHERE a.username = ?
          AND c.ts_timestamp >= ?
        GROUP BY day
        ORDER BY day ASC
    ''', (username, since))

    data = cur.fetchall()
    labels = [row['day'] for row in data]
    sent = [row['sent'] or 0 for row in data]
    received = [row['received'] or 0 for row in data]
    total = [s + r for s, r in zip(sent, received)]

    return jsonify({'labels': labels, 'sent': sent, 'received': received, 'total': total})


@app.route('/add', methods=['GET', 'POST'])
@require_login(role='admin')
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        monthly = request.form.get('monthly_bandwidth', '0')
        try:
            monthly_i = int(monthly)
        except Exception:
            monthly_i = 0
        if not username or not password:
            flash('username and password required', 'error')
            return redirect(url_for('add_user'))
        hashed = hash_password(password)
        now = int(time.time())
        db = get_db()
        try:
            db.execute('''INSERT INTO accounts (username, password, monthly_bandwidth, ts_created, ts_updated, ts_seen) VALUES (?, ?, ?, ?, ?, ?)''', (username, hashed, monthly_i, now, now, now))
            db.commit()
            flash('Account created', 'success')
            return redirect(url_for('index'))
        except sqlite3.IntegrityError:
            flash('username already exists', 'error')
            return redirect(url_for('add_user'))
    return render_template('form.html', action='add', row=None)


@app.route('/update/<username>', methods=['GET', 'POST'])
@require_login(role='admin')
def update_user(username):
    db = get_db()
    cur = db.execute('SELECT id, username, monthly_bandwidth, whitelist FROM accounts WHERE username = ?', (username,))
    row = cur.fetchone()
    if not row:
        flash('Account not found', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        password = request.form.get('password')
        monthly = request.form.get('monthly_bandwidth', '0')
        whitelist = request.form.get('whitelist', '')

        try:
            monthly_i = int(monthly)
        except Exception:
            monthly_i = 0
        params = []
        sets = []
        if password:
            hashed = hash_password(password)
            sets.append('password = ?')
            params.append(hashed)
        sets.append('monthly_bandwidth = ?')
        params.append(monthly_i)
        sets.append('whitelist = ?')
        params.append(whitelist)
        sets.append('ts_updated = ?')
        params.append(int(time.time()))
        params.append(username)
        sql = 'UPDATE accounts SET ' + ', '.join(sets) + ' WHERE username = ?'
        try:
            db.execute(sql, params)
            db.commit()
            flash('Account updated', 'success')
            return redirect(url_for('show_user', username=username))
        except Exception as e:
            flash('Failed to update: %s' % e, 'error')
            return redirect(url_for('update_user', username=username))

    return render_template('form.html', action='update', row=row)


@app.route('/delete/<username>', methods=['GET', 'POST'])
@require_login(role='admin')
def delete_user(username):
    db = get_db()
    if request.method == 'POST':
        db.execute('DELETE FROM accounts WHERE username = ?', (username,))
        db.commit()
        flash('Account deleted', 'success')
        return redirect(url_for('index'))
    return render_template('confirm_delete.html', username=username)


@app.route('/connections')
@require_login()
def list_connections():
    db = get_db()

    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page

    cur = db.execute('''
        SELECT c.id, a.username, c.client_ip, c.destination, c.status,
               c.bytes_sent, c.bytes_received,
               datetime(c.ts_timestamp, 'unixepoch') as ts
        FROM connections c
        JOIN accounts a ON c.account_id = a.id
        ORDER BY c.ts_timestamp DESC
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    rows = cur.fetchall()

    total_cur = db.execute('SELECT COUNT(*) FROM connections')
    total = total_cur.fetchone()[0]
    total_pages = max((total + per_page - 1) // per_page, 1)

    totals = db.execute('''
        SELECT SUM(bytes_sent) AS total_sent,
               SUM(bytes_received) AS total_received
        FROM connections
    ''').fetchone()

    month_start = int(time.mktime(time.strptime(time.strftime('%Y-%m-01'), '%Y-%m-%d')))
    monthly_totals = db.execute('''
        SELECT SUM(bytes_sent) AS month_sent,
               SUM(bytes_received) AS month_received
        FROM connections
        WHERE ts_timestamp >= ?
    ''', (month_start,)).fetchone()

    return render_template(
        'connections.html',
        rows=rows,
        page=page,
        total_pages=total_pages,
        totals=totals,
        monthly_totals=monthly_totals,
        connection_retention_days=CONNECTION_RETENTION_DAYS,
    )


@app.route('/connections/stats')
@require_login()
def connections_stats():
    db = get_db()

    totals = db.execute('''
        SELECT SUM(bytes_sent) AS total_sent,
               SUM(bytes_received) AS total_received
        FROM connections
    ''').fetchone()

    month_start = int(time.mktime(time.strptime(time.strftime('%Y-%m-01'), '%Y-%m-%d')))
    monthly_totals = db.execute('''
        SELECT SUM(bytes_sent) AS month_sent,
               SUM(bytes_received) AS month_received
        FROM connections
        WHERE ts_timestamp >= ?
    ''', (month_start,)).fetchone()

    data = {
        'total_sent': totals['total_sent'] or 0,
        'total_received': totals['total_received'] or 0,
        'month_sent': monthly_totals['month_sent'] or 0,
        'month_received': monthly_totals['month_received'] or 0
    }

    return jsonify(data)


@app.route('/maintenance/retention', methods=['POST'])
@require_login(role='admin')
def run_retention_now():
    if CONNECTION_RETENTION_DAYS <= 0:
        flash('Retention is disabled. Set CONNECTION_RETENTION_DAYS to enable it.', 'warning')
        return redirect(url_for('list_connections'))
    _run_connection_retention_if_needed(force=True)
    flash('Connection retention cleanup completed.', 'success')
    return redirect(url_for('list_connections'))


if __name__ == '__main__':
    validate_security_config()

    with app.app_context():
        init_db()

    debug_mode = _is_truthy(os.environ.get('FLASK_DEBUG', '0'))
    app.run(host='127.0.0.1', port=5000, debug=debug_mode)
