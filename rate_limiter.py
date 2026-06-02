import time
from collections import deque

class RateLimiter:
    """
    Monitors request frequency per IP using a sliding window algorithm.
    """
    def __init__(self, limit_threshold=15, time_window=10):
        self.limit_threshold = limit_threshold
        self.time_window = time_window
        self.ip_history = {} # Maps IP to deque of timestamps
        self.blocked_ips = set() # Optional: track permanently or temporarily blocked IPs

    def is_allowed(self, client_ip):
        current_time = time.time()
        
        if client_ip not in self.ip_history:
            self.ip_history[client_ip] = deque()

        queue = self.ip_history[client_ip]

        # Remove timestamps older than the sliding window
        while queue and queue[0] < current_time - self.time_window:
            queue.popleft()

        # Check if limits exceeded
        if len(queue) >= self.limit_threshold:
            self.blocked_ips.add(client_ip)
            return False

        # Add current request timestamp
        queue.append(current_time)
        return True
