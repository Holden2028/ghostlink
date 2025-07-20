from flask import Flask, request, jsonify
import csv
import datetime
import os

app = Flask(__name__)
LOG_FILE = 'log.csv'

BOT_KEYWORDS = [
    'bot', 'crawler', 'spider', 'crawl', 'slurp',
    'google', 'bing', 'scrape', 'yandex', 'duckduckgo', 'gpt', 'ai',
    'requests', 'httpx', 'go-http-client'
]

def initialize_log():
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'ip', 'user_agent', 'visitor_type', 'flag'])

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

@app.route('/')
def home():
    visitor_type = log_request(request)
    return ('Your visit has been logged as a bot.', 200) if visitor_type == 'bot' else ('Hello, human!', 200)

@app.route('/log')
def show_log():
    with open(LOG_FILE, 'r') as f:
        rows = list(csv.reader(f))

    html = """<html><head><title>Visitor Log</title></head><body><h1>Visitor Log</h1><table border='1'>"""
    html += '<tr>' + ''.join(f'<th>{col}</th>' for col in rows[0]) + '</tr>'
    for row in rows[1:]:
        html += '<tr>' + ''.join(f'<td>{cell}</td>' for cell in row) + '</tr>'
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

@app.route('/stats')
def show_stats():
    with open(LOG_FILE, 'r') as f:
        reader = csv.DictReader(f)
        total = bot = human = 0
        for row in reader:
            total += 1
            if row['visitor_type'] == 'bot':
                bot += 1
            else:
                human += 1
    return jsonify({
        "total_visits": total,
        "bots": bot,
        "humans": human
    })

if __name__ == '__main__':
    initialize_log()
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)