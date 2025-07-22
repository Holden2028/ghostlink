import os
import time
import datetime
import threading
import sqlite3
from flask import Flask, request, jsonify, render_template, session, url_for
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
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

def format_timestamp(ts):
    try:
        dt = datetime.datetime.fromisoformat(ts)
        return dt.strftime('%b %d, %Y %I:%M:%S %p UTC')
    except Exception:
        return ts  # fallback if parse fails

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
        cur = con.execute(
            "SELECT ip, user_agent FROM logs WHERE session_key = ? AND visitor_type = 'unclassified' ORDER BY id DESC LIMIT 1",
            (session_key,)
        )
        row = cur.fetchone()
        if row:
            ip, user_agent = row
            con.execute("DELETE FROM logs WHERE session_key = ? AND visitor_type = 'unclassified'", (session_key,))
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

def is_suspicious_headers(headers):
    lower_headers = {k.lower(): v for k, v in headers.items()}
    important = set(['user-agent', 'accept', 'accept-language'])
    if any(h not in lower_headers for h in important):
        return True, f"Missing critical browser headers: {important - set(lower_headers.keys())}"
    return False, ''

@app.before_request
def universal_bot_block():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = request.headers.get('User-Agent', '').lower()
    now = time.time()
    ip_activity.setdefault(ip, [])
    ip_activity[ip] = [t for t in ip_activity[ip] if now - t < RATE_WINDOW]
    ip_activity[ip].append(now)
    if len(ip_activity[ip]) > RATE_LIMIT:
        log_event(ip, user_agent, "bot", "Rate limit exceeded", "none")
        return "Access denied (rate limit)", 403
    for keyword in BOT_KEYWORDS:
        if keyword in user_agent:
            log_event(ip, user_agent, 'bot', f"Keyword '{keyword}' in User-Agent", "none")
            return "Access denied (bot UA)", 403
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