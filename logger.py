import json
import csv
import os
from datetime import datetime

class SecurityLogger:
    """
    Structured security logger.
    Logs telemetry data to JSON and CSV formats.
    """
    def __init__(self, json_path='security_alerts.json', csv_path='access_traffic.csv'):
        self.json_path = json_path
        self.csv_path = csv_path
        self.init_csv()

    def init_csv(self):
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['timestamp', 'src_ip', 'method', 'uri', 'attack_type', 'threat_score', 'outcome', 'payload_sample'])

    def log_event(self, src_ip, method, uri, matched_rules, threat_score, outcome, payload_sample=''):
        timestamp = datetime.now().isoformat()
        
        # Determine attack types for CSV
        attack_types = [r.get('category', 'Unknown') for r in matched_rules]
        attack_types_str = ','.join(attack_types) if attack_types else 'None'
        
        # 1. Log JSON alert (Structured telemetry)
        event_data = {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'method': method,
            'uri': uri,
            'matched_rules': matched_rules,
            'threat_score': threat_score,
            'outcome': outcome,
            'payload_sample': payload_sample
        }
        with open(self.json_path, 'a') as f:
            f.write(json.dumps(event_data) + '\n')

        # 2. Log CSV line (Human-readable)
        with open(self.csv_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, method, uri, attack_types_str, threat_score, outcome, payload_sample])

    def get_recent_alerts(self, limit=100):
        alerts = []
        if os.path.exists(self.json_path):
            with open(self.json_path, 'r') as f:
                for line in f:
                    try:
                        alerts.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return alerts[-limit:]
