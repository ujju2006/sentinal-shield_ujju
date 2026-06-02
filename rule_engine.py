import re
import json

class RuleEngine:
    """
    Detects known attack signatures using regex patterns.
    Scores requests based on the severity of matched rules.
    """
    def __init__(self, rules_path):
        self.rules = []
        self.load_rules(rules_path)

    def load_rules(self, rules_path):
        try:
            with open(rules_path, 'r') as f:
                data = json.load(f)
                self.rules = data.get('rules', [])
        except Exception:
            # Fallback default rules based on user spec
            self.rules = [
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

    def evaluate(self, params):
        total_threat_score = 0
        triggered_rules = []

        for param_name, param_val in params.items():
            if not param_val:
                continue
            for rule in self.rules:
                pattern = rule.get('regex')
                if pattern and re.search(pattern, str(param_val)):
                    score = rule.get('threat_score', 0)
                    total_threat_score += score
                    triggered_rules.append(rule)

        # Deduplicate triggered rules
        unique_rules = {r['rule_id']: r for r in triggered_rules}.values()
        
        return total_threat_score, list(unique_rules)
