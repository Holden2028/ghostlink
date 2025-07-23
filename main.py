import os
import requests
from flask import Flask, render_template

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "changeme")

@app.route('/')
def homepage():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    try:
        api_url = "https://ghostwallapi.onrender.com/logs"
        r = requests.get(api_url, timeout=5)
        r.raise_for_status()
        logs = r.json().get("logs", [])
    except Exception as e:
        logs = [f"Error fetching logs: {e}"]
    return render_template('dashboard.html', logs=logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050)