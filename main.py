import os
import time
import datetime
import threading
import sqlite3
from flask import Flask, request, jsonify, render_template, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")
DB_FILE = 'visitlog.db'
RATE_LIMIT = 20
RATE_WINDOW = 60

BOT_KEYWORDS = [
    'bot', 'crawler', 'spider', 'crawl', 'slurp',
    'google', 'bing', 'scrape', 'yandex', 'duckduckgo', 'gpt', 'ai',
    'requests', 'httpx', 'go-http-client', 'claude', 'curl',
    'fetch', 'wget', 'python', 'anthropic',
    'assistant', 'automation',
    'headless', 'selenium', 'puppeteer', 'phantom'
]
COMMON_BROWSER_HEADERS = [
    'accept', 'accept-encoding', 'accept-language', 'cache-control', 'cookie', 'dnt',
    'referer', 'user-agent', 'sec-ch-ua'
]

ip_activity = {}  # In-memory for rate limiting only

# --- Helper for readable timestamps ---
def format_timestamp(ts):
    try:
        dt = datetime.datetime.fromisoformat(ts)
        return dt.strftime('%b %d, %Y %I:%M:%S %p UTC')
    except Exception:
        return ts  # fallback if parse fails

# --- DB functions ---
def init_db():
    with sqlite3.connect(DB_FILE) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                ip TEXT,
                user_agent TEXT,
                visitor_type TEXT,
                details TEXT,
                session_key TEXT
            )
        """)

def log_event(ip, user_agent, visitor_type, details, session_key):
    with sqlite3.connect(DB_FILE) as con:
        con.execute(
            "INSERT INTO logs (timestamp, ip, user_agent, visitor_type, details, session_key) VALUES (?, ?, ?, ?, ?, ?)",
            (datetime.datetime.utcnow().isoformat(), ip, user_agent, visitor_type, details, session_key)
        )

def upgrade_log(session_key, new_type, details):
    with sqlite3.connect(DB_FILE) as con:
        # Find the unclassified log for this session_key
        cur = con.execute(
            "SELECT ip, user_agent FROM logs WHERE session_key = ? AND visitor_type = 'unclassified' ORDER BY id DESC LIMIT 1",
            (session_key,)
        )
        row = cur.fetchone()
        if row:
            ip, user_agent = row
            # Delete the unclassified log
            con.execute("DELETE FROM logs WHERE session_key = ? AND visitor_type = 'unclassified'", (session_key,))
            # Insert the new log with the same info
            con.execute(
                "INSERT INTO logs (timestamp, ip, user_agent, visitor_type, details, session_key) VALUES (?, ?, ?, ?, ?, ?)",
                (datetime.datetime.utcnow().isoformat(), ip, user_agent, new_type, details, session_key)
            )

def get_recent_unclassified(time_limit=35):
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(seconds=time_limit)
    with sqlite3.connect(DB_FILE) as con:
        res = con.execute(
            "SELECT session_key FROM logs WHERE visitor_type = 'unclassified' AND timestamp < ?",
            (cutoff.isoformat(),)
        )
        return [r[0] for r in res.fetchall()]

def clear_log():
    with sqlite3.connect(DB_FILE) as con:
        con.execute("DELETE FROM logs")

def get_logs():
    with sqlite3.connect(DB_FILE) as con:
        return list(con.execute("SELECT timestamp, ip, user_agent, visitor_type, details FROM logs ORDER BY id DESC"))

# --- Header check ---
def is_suspicious_headers(headers):
    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing = [h for h in COMMON_BROWSER_HEADERS if h not in lower_headers]
    # Only require these three to be present
    important = set(['user-agent', 'accept', 'accept-language'])
    if any(h not in lower_headers for h in important):
        return True, f"Missing critical browser headers: {important - set(lower_headers.keys())}"
    return False, ''

# --- Flask routes and hooks ---
@app.before_request
def universal_bot_block():
    # --------- FIXED: Allow static files to always go through ---------
    if request.path.startswith('/static/'):
        return  # skip bot check for static files (including downloads)
    # ---------------------------------------------------------------

    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '').lower()
    now = time.time()
    ip_activity.setdefault(ip, [])
    ip_activity[ip] = [t for t in ip_activity[ip] if now - t < RATE_WINDOW]
    ip_activity[ip].append(now)
    # Rate limit
    if len(ip_activity[ip]) > RATE_LIMIT:
        log_event(ip, user_agent, "bot", "Rate limit exceeded", "none")
        return "Access denied (rate limit)", 403
    # Keyword match
    for keyword in BOT_KEYWORDS:
        if keyword in user_agent:
            log_event(ip, user_agent, 'bot', f"Keyword '{keyword}' in User-Agent", "none")
            return "Access denied (bot UA)", 403
    # Suspicious headers
    suspicious, details = is_suspicious_headers(request.headers)
    if suspicious:
        log_event(ip, user_agent, 'bot', details, "none")
        return "Access denied (suspicious headers)", 403

@app.route('/honeypot')
def honeypot():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'unknown')
    log_event(ip, user_agent, "bot", "Honeypot URL triggered", "none")
    return "Access denied (honeypot).", 403

@app.route('/log.json')
def log_json():
    logs = get_logs()
    return jsonify([
        {
            "Timestamp": format_timestamp(l[0]),
            "IP": l[1],
            "User Agent": l[2],
            "Visitor Type": l[3],
            "Details": l[4]
        }
        for l in logs
    ])

@app.route('/clear', methods=['GET'])
def clear_log_route():
    clear_log()
    return 'Log cleared.', 200

@app.route('/robots.txt')
def robots_txt():
    return app.send_static_file('robots.txt')

@app.route('/')
def homepage():
    session['visited'] = True
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', 'unknown')
    # Use a session_key unique to this visit for tracking
    session_key = session.get('session_key')
    if not session_key:
        session_key = os.urandom(12).hex()
        session['session_key'] = session_key
    # Log as unclassified
    log_event(ip, user_agent, "unclassified", "Pageview (JS not yet checked)", session_key)
    return render_template('index.html', honeypot_url=url_for('honeypot'))

@app.route('/track', methods=['POST'])
def track_visit():
    data = request.get_json()
    is_headless = data.get('is_headless', False)
    session_key = session.get('session_key')
    if is_headless:
        upgrade_log(session_key, "bot", "Detected headless browser via JS")
        return "Access denied (headless bot)", 403
    if not session.get('visited'):
        upgrade_log(session_key, "bot", "No session cookie set; likely no-JS bot")
        return "Access denied (no session cookie)", 403
    # JS ran: mark as human and delete any unclassified entry for this session
    upgrade_log(session_key, "human", "")
    return jsonify({'status': 'logged'}), 200

@app.route('/dashboard')
def dashboard():
    logs = get_logs()
    columns = ["Timestamp", "IP", "User Agent", "Visitor Type", "Details"]
    # Format timestamp for each log
    rows = [(format_timestamp(l[0]), l[1], l[2], l[3], l[4]) for l in logs]
    return render_template('dashboard.html', columns=columns, rows=rows)

# --- Background: Upgrade old unclassified to bot (no js) ---
def cleanup_no_js_visits():
    while True:
        # Find unclassified visits >35 seconds old
        session_keys = get_recent_unclassified()
        for sk in session_keys:
            upgrade_log(sk, "bot", "No JS detected within 30s")
        time.sleep(10)

if __name__ == '__main__':
    init_db()
    threading.Thread(target=cleanup_no_js_visits, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)