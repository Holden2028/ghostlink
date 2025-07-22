import os
from flask import Flask, render_template

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

# --- Helper for readable timestamps ---
def format_timestamp(ts):
    import datetime
    try:
        dt = datetime.datetime.fromisoformat(ts)
        return dt.strftime('%b %d, %Y %I:%M:%S %p UTC')
    except Exception:
        return ts  # fallback if parse fails

# --- Read logs from file written by FastAPI ---
def get_logs():
    logs = []
    log_file = "log.txt"  # Make sure this path matches your FastAPI API
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            for line in f:
                logs.append(line.strip())
    else:
        logs.append("No logs found.")
    return logs

@app.route('/')
def homepage():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    logs = get_logs()
    return render_template('dashboard.html', logs=logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
