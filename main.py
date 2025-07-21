from flask import Flask, request, jsonify, render_template, session, url_for
import csv
import datetime
import os
import threading
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")
LOG_FILE = 'log.csv'
RATE_LIMIT = 20    # max requests per minute per IP
RATE_WINDOW = 60   # seconds

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

# In-memory tracking for pageviews and rate limiting
recent_pageviews = {}  # {(ip, user_agent): (timestamp, logged_js)}
ip_activity = defaultdict(list)  # ip: [timestamps]

def initialize_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'IP', 'User Agent', 'Visitor Type', 'Details'])

def is_suspicious_headers(headers):
    lower_headers = {k.lower(): v for k, v in headers.items()}
    missing = [h for h in COMMON_BROWSER_HEADERS if h not in lower_headers]
    # Check for minimal headers or strange patterns
    if len(missing) > 3 or 'user-agent' not in lower_headers:
        return True, f"Missing headers: {missing}"
    return False, ''

def log_request(req, visitor_type, details=''):
    timestamp = datetime.datetime.now().strftime('%b %d, %Y %I:%M:%S %p UTC')
    ip = req.headers.get('X-Forwarded-For', req.remote_addr)
    user_agent = req.headers.get('User-Agent', 'unknown')
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, ip, user_agent, visitor_type, details])

@app.before_request
def universal_bot_block():
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    now = time.time()
    ip_activity[ip] = [t for t in ip_activity[ip] if now - t < RATE_WINDOW]
    ip_activity[ip].append(now)
    # 1. Rate limit
    if len(ip_activity[ip]) > RATE_LIMIT:
        log_request(request, "bot", "Rate limit exceeded")
        return "Access denied (rate limit)", 403
    # 2. Keyword bot UA
    user_agent = request.headers.get('User-Agent', '').lower()
    for keyword in BOT_KEYWORDS:
        if keyword in user_agent:
            log_request(request, 'bot', f"Keyword '{keyword}' in User-Agent")
            return "Access denied (bot UA)", 403
    # 3. Suspicious headers
    suspicious, details = is_suspicious_headers(request.headers)
    if suspicious:
        log_request(request, 'bot', details)
        return "Access denied (suspicious headers)", 403

@app.route('/honeypot')
def honeypot():
    log_request(request, "bot", "Honeypot URL triggered")
    return "Access denied (honeypot).", 403

@app.route('/log.json')
def log_json():
    with open(LOG_FILE, 'r') as f:
        reader = csv.DictReader(f)
        clean_rows = []
        for row in reader:
            if None in row or any(v is None for v in row.values()):
                continue
            clean_rows.append(row)
        return jsonify(clean_rows)

@app.route('/clear', methods=['GET'])
def clear_log():
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'IP', 'User Agent', 'Visitor Type', 'Details'])
    return 'Log cleared.', 200

@app.route('/robots.txt')
def robots_txt():
    return app.send_static_file('robots.txt')

@app.route('/')
def homepage():
    # Set session cookie to test for no-JS/cookie bots
    session['visited'] = True
    # Log every pageview (backend)
    user_agent = request.headers.get('User-Agent', 'unknown')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    key = (ip, user_agent)
    recent_pageviews[key] = {'time': time.time(), 'js': False}
    # Insert honeypot link in rendered template
    return render_template('index.html', honeypot_url=url_for('honeypot'))

@app.route('/track', methods=['POST'])
def track_visit():
    data = request.get_json()
    timestamp = datetime.datetime.now().strftime('%b %d, %Y %I:%M:%S %p UTC')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = data.get('user_agent', request.headers.get('User-Agent', 'unknown'))
    url = data.get('url', 'unknown')
    referrer = data.get('referrer', '')
    is_headless = data.get('is_headless', False)
    visitor_type = 'human'
    details = ''

    # 1. Headless JS signal (optional, if you update your ghost.js)
    if is_headless:
        visitor_type = 'bot'
        details = "Detected headless browser via JS"
        log_request(request, visitor_type, details)
        return "Access denied (headless bot)", 403
    # 2. Session cookie check
    if not session.get('visited'):
        visitor_type = 'bot'
        details = "No session cookie set; likely no-JS bot"
        log_request(request, visitor_type, details)
        return "Access denied (no session cookie)", 403
    # 3. Mark as JS-executed in memory
    key = (ip, user_agent)
    if key in recent_pageviews:
        recent_pageviews[key]['js'] = True
    # 4. Final log as human
    log_request(request, visitor_type, details)
    return jsonify({'status': 'logged'}), 200

@app.route('/dashboard')
def dashboard():
    with open(LOG_FILE, 'r') as f:
        reader = list(csv.reader(f))
        columns = reader[0]
        rows = reader[1:][::-1]
    # Remove "Flag" column if present (shouldn't be, but just in case)
    columns = [c for c in columns if c.lower() != "flag"]
    new_rows = []
    for row in rows:
        if len(row) == 6:  # drop 5th column (Flag)
            row.pop(4)
        new_rows.append(row)
    return render_template('dashboard.html', columns=columns, rows=new_rows)

def cleanup_no_js_visits():
    # Runs in background: flag pageviews without JS after 30s
    while True:
        now = time.time()
        for key, data in list(recent_pageviews.items()):
            if not data['js'] and now - data['time'] > 30:
                class DummyReq:
                    headers = {'User-Agent': key[1], 'X-Forwarded-For': key[0]}
                log_request(DummyReq, "bot", "No JS detected within 30s")
                del recent_pageviews[key]
        time.sleep(10)

if __name__ == '__main__':
    initialize_log()
    threading.Thread(target=cleanup_no_js_visits, daemon=True).start()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)