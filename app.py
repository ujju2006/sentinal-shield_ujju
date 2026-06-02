import os
import json
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from waf_middleware import WafMiddleware

app = Flask(__name__)
app.secret_key = 'sentinelshield_soc_secret_2026'
RULES_FILE = 'rules.json'
USERS_FILE = 'users.json'

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# Ensure default rules exist for RuleEngine
if not os.path.exists(RULES_FILE):
    default_rules = {
        "rules": [
            {
                "rule_id": "SEC-SQLI-001",
                "category": "SQL Injection",
                "description": "SQLi Injection Attempt",
                "regex": "(?i)(UNION\\s+SELECT|'\\s*OR\\s*.*=.*|--|#)",
                "threat_score": 5,
                "severity": "Critical"
            },
            {
                "rule_id": "SEC-XSS-001",
                "category": "XSS",
                "description": "Cross-Site Scripting Attempt",
                "regex": "(?i)(<script.*?>|onerror\\s*=|onload\\s*=)",
                "threat_score": 5,
                "severity": "High"
            },
            {
                "rule_id": "SEC-LFI-001",
                "category": "LFI",
                "description": "LFI / Path Traversal Attempt",
                "regex": "(?i)(\\.\\./\\.\\./|/etc/passwd|/etc/shadow)",
                "threat_score": 4,
                "severity": "High"
            },
            {
                "rule_id": "SEC-CMD-001",
                "category": "Command Injection",
                "description": "Command Injection Attempt",
                "regex": "(?i)(\\|\\||&&|whoami|uname|net\\s+user|cat\\s+)",
                "threat_score": 5,
                "severity": "Critical"
            }
        ]
    }
    with open(RULES_FILE, 'w') as f:
        json.dump(default_rules, f, indent=2)

# Wrap Flask App with SentinelShield WafMiddleware
# Limit threshold is set low (e.g. 5 req / 10 sec) for easier rate limit testing
waf = WafMiddleware(app, rules_path=RULES_FILE, limit_threshold=5, time_window=10)

# ==========================================
# VULNERABLE ROUTES (For Testing the WAF)
# ==========================================

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        
        users = load_users()
        if user in users and check_password_hash(users[user], pwd):
            session['logged_in'] = True
            session['username'] = user
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        user = request.form.get('username')
        pwd = request.form.get('password')
        confirm = request.form.get('confirm')
        
        if pwd != confirm:
            return render_template('signup.html', error='Passwords do not match')
            
        users = load_users()
        if user in users:
            return render_template('signup.html', error='Username already exists')
            
        users[user] = generate_password_hash(pwd)
        save_users(users)
        
        return redirect(url_for('login', success='Account created! Please log in.'))
    return render_template('signup.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        user = session.get('username')
        old_pwd = request.form.get('old_password')
        new_pwd = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        
        users = load_users()
        if user in users and check_password_hash(users[user], old_pwd):
            if new_pwd == confirm:
                users[user] = generate_password_hash(new_pwd)
                save_users(users)
                return render_template('change_password.html', success='Password updated successfully.')
            else:
                return render_template('change_password.html', error='New passwords do not match.')
        return render_template('change_password.html', error='Incorrect current password.')
        
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/test')
def test_lab():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('test.html')

@app.route('/search')
def search():
    # Target for XSS testing
    q = request.args.get('q', '')
    return jsonify({'status': 'success', 'query': q, 'results': []})

@app.route('/view')
def view():
    # Target for Path Traversal testing
    filename = request.args.get('file', '')
    return jsonify({'status': 'success', 'file': filename, 'content': 'Dummy file content'})

@app.route('/ping')
def ping():
    # Target for Command Injection testing
    ip = request.args.get('ip', '')
    return jsonify({'status': 'success', 'output': f'pinging {ip} completed'})

# ==========================================
# DASHBOARD & TELEMETRY ROUTES
# ==========================================

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/logs')
def get_logs():
    # Return recent JSON telemetry
    alerts = waf.logger.get_recent_alerts(limit=500)
    return jsonify({'logs': alerts})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.json or {}
    payload = data.get('payload', '')
    
    params_to_scan = {'manual_payload': waf.decoder.decode(payload)}
    threat_score, triggered_rules = waf.rule_engine.evaluate(params_to_scan)
    
    return jsonify({
        'status': 'success',
        'threat_score': threat_score,
        'matched_rules': [r for r in triggered_rules]
    })

if __name__ == '__main__':
    # Start Flask Server on all interfaces (0.0.0.0) so it's accessible via Docker
    app.run(host='0.0.0.0', debug=True, port=5000)
