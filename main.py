from flask import Flask, request, jsonify, render_template, send_file
import csv
import datetime
import os

app = Flask(__name__)
LOG_FILE = 'log.csv'

BOT_KEYWORDS = [
    'bot', 'crawler', 'spider', 'crawl', 'slurp',
    'google', 'bing', 'scrape', 'yandex', 'duckduckgo', 'gpt', 'ai',
    'requests', 'httpx', 'go-http-client', 'curl', 'wget', 'python',
    'anthropic', 'openai', 'claude', 'chatgpt', 'llm'
]

@app.before_request
def log_and_check_bots():
    # Skip logging for certain endpoints to avoid infinite loops
    if request.endpoint in ['log_json', 'clear_log', 'dashboard']:
        return

    # Log every request first
    log_request(request)

    # Then check if it should be blocked
    user_agent = request.headers.get('User-Agent', '').lower()
    for keyword in BOT_KEYWORDS:
        if keyword in user_agent:
            # Update the last log entry to mark it as denied
            update_last_log_entry_as_denied(keyword)
            return "Access denied", 403

def initialize_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'IP', 'User Agent', 'Visitor Type', 'Flag'])

def classify_visitor(user_agent):
    ua = user_agent.lower()
    for keyword in BOT_KEYWORDS:
        if keyword in ua:
            return 'bot', keyword
    return 'human', ''

def log_request(req):
    timestamp = datetime.datetime.now().strftime('%b %d, %Y %I:%M:%S %p')
    ip = req.headers.get('X-Forwarded-For', req.remote_addr)
    user_agent = req.headers.get('User-Agent', 'unknown')
    visitor_type, flag = classify_visitor(user_agent)

    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, ip, user_agent, visitor_type, flag])

    return visitor_type


def update_last_log_entry_as_denied(flag_keyword):
    # Read all rows
    with open(LOG_FILE, 'r', newline='') as f:
        rows = list(csv.reader(f))

    # Update the last row to mark as denied
    if len(rows) > 1:  # Make sure there's data beyond header
        rows[-1][3] = 'bot (denied)'  # Visitor Type column
        rows[-1][4] = flag_keyword  # Flag column

    # Write back all rows
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(rows)

@app.route('/log.json')
def log_json():
    with open(LOG_FILE, 'r') as f:
        reader = csv.DictReader(f)
        clean_rows = []
        for row in reader:
            # skip rows that are missing any of the expected columns
            if None in row or any(v is None for v in row.values()):
                continue
            clean_rows.append(row)
        return jsonify(clean_rows)

@app.route('/clear', methods=['GET'])
def clear_log():
    with open(LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Timestamp', 'IP', 'User Agent', 'Visitor Type', 'Flag'])
    return 'Log cleared.', 200

@app.route('/')
def homepage():
    return render_template('index.html')

@app.route('/track', methods=['POST'])
def track_visit():
    data = request.get_json()
    timestamp = datetime.datetime.now().strftime('%b %d, %Y %I:%M:%S %p')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    user_agent = data.get('user_agent', 'unknown')
    url = data.get('url', 'unknown')
    referrer = data.get('referrer', '')
    flag = ''
    visitor_type = 'human'

    for keyword in BOT_KEYWORDS:
        if keyword in user_agent.lower():
            visitor_type = 'bot'
            flag = keyword
            break

    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, ip, user_agent, visitor_type, flag])

    return jsonify({'status': 'logged'}), 200

@app.route('/dashboard')
def dashboard():
    with open(LOG_FILE, 'r') as f:
        reader = list(csv.reader(f))
        columns = reader[0]
        rows = reader[1:]
    return render_template('dashboard.html', columns=columns, rows=rows)

if __name__ == '__main__':
    initialize_log()
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)