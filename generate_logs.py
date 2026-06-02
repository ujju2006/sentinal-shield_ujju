import json
import random
from datetime import datetime, timedelta
import os

LOG_FILE = 'security_alerts.json'

# Helper data
IPS = [
    "192.168.1.5", "192.168.1.7", "192.168.1.9", "192.168.1.12",
    "10.0.0.4", "10.0.0.15", "10.0.0.22",
    "172.16.0.5", "172.16.0.100",
    "185.22.66.11", "185.22.66.14", "185.44.12.8",
    "45.33.22.1", "45.33.22.9",
    "103.11.22.5", "103.11.22.88"
]

PATHS_NORMAL = ["/", "/dashboard", "/about", "/contact", "/products", "/api/status"]
PATHS_ATTACK = ["/login", "/search", "/admin", "/api/users", "/profile", "/view"]

PAYLOADS = {
    "Normal": ["", "q=hello", "id=123", "user=john", "page=2"],
    "SQL Injection": ["' OR 1=1 --", "admin' #", "UNION SELECT username, password FROM users", "' OR 'a'='a"],
    "XSS": ["<script>alert(1)</script>", "onerror=alert(document.cookie)", "javascript:alert(1)", "<img src=x onerror=prompt()>"],
    "Command Injection": ["| whoami", "&& cat /etc/passwd", "; net user", "| ping 8.8.8.8"],
    "LFI": ["../../../../etc/passwd", "../../../../Windows/win.ini", "file:///etc/shadow"],
    "Traversal": ["../config.json", "..\\..\\boot.ini", "/var/www/html/../../etc/passwd"]
}

def generate_event(event_time, event_type):
    ip = random.choice(IPS)
    method = random.choice(["GET", "POST"])
    
    if event_type == "Normal":
        uri = random.choice(PATHS_NORMAL)
        if method == "GET":
            payload = random.choice(PAYLOADS["Normal"])
            if payload: uri += "?" + payload
        else:
            payload = random.choice(PAYLOADS["Normal"])
        
        return {
            "timestamp": event_time.isoformat(),
            "src_ip": ip,
            "method": method,
            "uri": uri,
            "matched_rules": [],
            "threat_score": 0,
            "outcome": "Allowed",
            "payload_sample": payload
        }
    
    elif event_type == "Brute Force":
        # Simulate rate limiting
        uri = "/login"
        payload = "user=admin&pass=password123"
        return {
            "timestamp": event_time.isoformat(),
            "src_ip": random.choice(["45.33.22.1", "185.22.66.11"]), # Specific IPs for brute force
            "method": "POST",
            "uri": uri,
            "matched_rules": [],
            "threat_score": 0, # Rate limit doesn't necessarily have a threat score from rules
            "outcome": "HTTP 429 Too Many Requests",
            "payload_sample": payload
        }
        
    else:
        # Attack types
        uri = random.choice(PATHS_ATTACK)
        payload = random.choice(PAYLOADS[event_type])
        if method == "GET": uri += "?q=" + payload
        
        rule_map = {
            "SQL Injection": {"rule_id": "SEC-SQLI-001", "category": "SQL Injection", "threat_score": 5},
            "XSS": {"rule_id": "SEC-XSS-001", "category": "XSS", "threat_score": 5},
            "Command Injection": {"rule_id": "SEC-CMD-001", "category": "Command Injection", "threat_score": 5},
            "LFI": {"rule_id": "SEC-LFI-001", "category": "LFI", "threat_score": 4},
            "Traversal": {"rule_id": "SEC-LFI-001", "category": "LFI", "threat_score": 4} # Traversal uses LFI rule in our simple engine
        }
        
        rule = rule_map[event_type]
        
        return {
            "timestamp": event_time.isoformat(),
            "src_ip": ip,
            "method": method,
            "uri": uri,
            "matched_rules": [rule],
            "threat_score": rule["threat_score"],
            "outcome": "HTTP 403 Forbidden",
            "payload_sample": payload
        }

def generate_dataset(num_events=2000):
    events = []
    
    # Time window: last 24 hours
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=24)
    time_step = (end_time - start_time) / num_events
    
    current_time = start_time
    
    # Distribution
    types = ["Normal", "SQL Injection", "XSS", "Brute Force", "Command Injection", "LFI", "Traversal"]
    weights = [45, 15, 15, 10, 7, 5, 3]
    
    # Inject an attack spike around hour 20
    spike_start = start_time + timedelta(hours=20)
    spike_end = spike_start + timedelta(minutes=15)
    
    for i in range(num_events):
        # Determine if we're in the spike
        if spike_start <= current_time <= spike_end:
            # During spike, heavy brute force and SQLi
            ev_type = random.choices(["Brute Force", "SQL Injection"], weights=[70, 30])[0]
        else:
            ev_type = random.choices(types, weights=weights)[0]
            
        event = generate_event(current_time, ev_type)
        events.append(event)
        
        # Advance time slightly randomized
        jitter = random.uniform(0.5, 1.5)
        current_time += time_step * jitter
        
    # Write to file
    with open(LOG_FILE, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
            
    print(f"Generated {len(events)} events into {LOG_FILE}")

if __name__ == "__main__":
    generate_dataset(2000)
