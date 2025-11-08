from flask import Flask, g, render_template, request, redirect, url_for, flash, jsonify, Response
import sqlite3
import os
import time
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from flask_wtf import CSRFProtect
import hmac

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret')

DATABASE = os.environ.get('DATABASE', os.path.join(os.path.dirname(__file__), '..', 'microsocks.db'))

PH = PasswordHasher()
csrf = CSRFProtect()
csrf.init_app(app)

# Basic admin credentials (use env vars to override)
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin')


def _check_basic_auth():
    auth = request.authorization
    if not auth:
        return False
    # use hmac.compare_digest for timing-attack resistant comparison
    try:
        ok_user = hmac.compare_digest(auth.username, ADMIN_USER)
        ok_pass = hmac.compare_digest(auth.password, ADMIN_PASS)
        return ok_user and ok_pass
    except Exception:
        return False


@app.before_request
def require_basic_auth():
    # Allow static assets without auth
    if request.endpoint == 'static':
        return None
    # If the client provides valid basic auth credentials, proceed
    if _check_basic_auth():
        return None
    # Otherwise request auth
    return Response('Authentication required', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})

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


# Utilities
@app.template_filter('bytes_to_gb')
def bytes_to_gb(value):
    return f'{value / 1_000_000_000:.2f} GB'

# Human-readable byte formatting
@app.template_filter('human_readable')
def human_readable(num_bytes):
    """Convert bytes to a human-readable string with appropriate units."""
    if num_bytes is None:
        return '0 B'

    step_unit = 1000.0  # use decimal multiples (KB, MB, GB)
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


# Routes
@app.route('/')
def index():
    # list users
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
def user_usage_json(username):
    db = get_db()

    # Determine time range
    range_param = request.args.get('range', '30d')
    now = int(time.time())
    if range_param == '7d':
        since = now - 7 * 24 * 3600
    elif range_param == '30d':
        since = now - 30 * 24 * 3600
    else:
        since = 0  # all time

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
def delete_user(username):
    db = get_db()
    if request.method == 'POST':
        # perform delete
        db.execute('DELETE FROM accounts WHERE username = ?', (username,))
        db.commit()
        flash('Account deleted', 'success')
        return redirect(url_for('index'))
    else:
        # show confirm
        return render_template('confirm_delete.html', username=username)
    
@app.route('/connections')
def list_connections():
    db = get_db()

    # pagination
    page = request.args.get('page', 1, type=int)
    per_page = 50
    offset = (page - 1) * per_page

    # main query (latest first)
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

    # count total for pagination
    total_cur = db.execute('SELECT COUNT(*) FROM connections')
    total = total_cur.fetchone()[0]
    total_pages = (total + per_page - 1) // per_page

    # overall totals
    totals = db.execute('''
        SELECT SUM(bytes_sent) AS total_sent,
               SUM(bytes_received) AS total_received
        FROM connections
    ''').fetchone()

    # monthly totals (first day of current month)
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
        monthly_totals=monthly_totals
    )
    
@app.route('/connections/stats')
def connections_stats():
    db = get_db()

    # overall totals
    totals = db.execute('''
        SELECT SUM(bytes_sent) AS total_sent,
               SUM(bytes_received) AS total_received
        FROM connections
    ''').fetchone()

    # monthly totals
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

if __name__ == '__main__':
    # ensure DB exists and schema is applied
    with app.app_context():
        init_db()
    app.run(host='127.0.0.1', port=5000, debug=True)
