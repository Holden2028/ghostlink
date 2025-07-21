from flask import Flask, request, jsonify, render_template
import csv
import datetime
import os

app = Flask(__name__)
LOG_FILE = 'log.csv'

BOT_KEYWORDS = [
    'bot', 'crawler', 'spider', 'crawl', 'slurp',
    'google', 'bing', 'scrape', 'yandex', 'duckduckgo', 'gpt', 'ai',
    'requests', 'httpx', 'go-http-client', 'claude', 'curl',
    'fetch', 'curl', 'wget', 'python', 'anthropic',
    'assistant', 'automation',
    'headless', 'selenium', 'puppeteer', 'phantom'
]

@app.before_request
def block_known_bots():
    user_agent = request.headers.get('User-Agent', '').lower()
    for keyword in BOT_KEYWORDS:
        if keyword in user_agent:
            timestamp = datetime.datetime.now().strftime('%b %d, %Y %I:%M:%S %p')
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            flag = keyword

            with open(LOG_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, ip, user_agent, 'bot (denied)', flag])

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
    ip = request.headers.get('X-Forwarded-For', req.remote_addr)
    user_agent = req.headers.get('User-Agent', 'unknown')
    visitor_type, flag = classify_visitor(user_agent)

    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, ip, user_agent, visitor_type, flag])

    return visitor_type


    html += '<tr>' + ''.join(f'<th>{col}</th>' for col in rows[0]) + '</tr>'
    for row in rows[1:]:
        visitor_type = row[3].lower()
        if 'denied' in visitor_type:
            css_class = 'denied'
        elif visitor_type == 'bot':
            css_class = 'bot'
        else:
            css_class = 'human'
        html += f"<tr class='{css_class}'>" + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>'

    html += '</table></body></html>'
    return html

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

@app.route('/robots.txt')
def robots_txt():
    return app.send_static_file('robots.txt')

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
        rows = reader[1:][::-1]  # reverse rows so newest first
    return render_template('dashboard.html', columns=columns, rows=rows)

if __name__ == '__main__':
    initialize_log()
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)