import json
from flask import request, Response
from rate_limiter import RateLimiter
from rule_engine import RuleEngine
from logger import SecurityLogger
from decoder import PayloadDecoder

class WafMiddleware:
    """
    HTTP Request Interception Middleware.
    Extracts data, normalizes it, enforces rate limits, evaluates rules, and triggers actions.
    """
    def __init__(self, app, rules_path='rules.json', limit_threshold=15, time_window=10):
        self.app = app
        self.rate_limiter = RateLimiter(limit_threshold, time_window)
        self.rule_engine = RuleEngine(rules_path)
        self.logger = SecurityLogger()
        self.decoder = PayloadDecoder()
        
        # Register Flask before_request hook
        app.before_request(self.before_request)

    def before_request(self):
        # Allow static files and dashboard routes to pass without blocking
        if request.path.startswith('/static') or request.path in ['/dashboard', '/logs']:
            return None

        # Support X-Forwarded-For header for simulated attacker testing
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            client_ip = forwarded.split(',')[0].strip()
        else:
            client_ip = request.remote_addr
        target_path = request.path

        # 1. Rate Limiting Check
        if not self.rate_limiter.is_allowed(client_ip):
            self.logger.log_event(client_ip, request.method, target_path, [], 0, 'HTTP 429 Too Many Requests')
            response_data = json.dumps({'error': 'Too Many Requests', 'retry_after': self.rate_limiter.time_window})
            return Response(response_data, status=429, mimetype='application/json')

        # 2. Extract parameters and normalize (Decode)
        params_to_scan = {}
        for k, v in request.args.items():
            params_to_scan[f'query_{k}'] = self.decoder.decode(v)
        for k, v in request.form.items():
            params_to_scan[f'body_{k}'] = self.decoder.decode(v)
        
        # We can scan headers, but limit to prevent false positives. Usually User-Agent and Referer.
        if 'User-Agent' in request.headers:
             params_to_scan['header_user_agent'] = self.decoder.decode(request.headers['User-Agent'])

        # 3. Rule Evaluation Check
        threat_score, triggered_rules = self.rule_engine.evaluate(params_to_scan)
        
        # Threat Score Logic
        # Low < 3 (Allow), Medium >=3 (Monitor/Log), High >=4 (Alert/Block), Critical >= 5 (Block)
        if threat_score >= 4:
            # Request Blocked
            # Grab a sample of the offending payload for the logs
            payload_sample = str(params_to_scan)[:100]
            
            self.logger.log_event(
                client_ip, 
                request.method, 
                target_path, 
                triggered_rules, 
                threat_score, 
                'HTTP 403 Forbidden',
                payload_sample
            )
            
            response_data = json.dumps({
                'error': 'Request Blocked',
                'reason': 'Threat signature matched',
                'threat_score': threat_score,
                'matched_categories': [r.get('category') for r in triggered_rules]
            })
            return Response(response_data, status=403, mimetype='application/json')

        # Log allowed request for auditing
        self.logger.log_event(client_ip, request.method, target_path, [], threat_score, 'Allowed')
        
        # Return None to allow Flask to proceed to the backend route
        return None
