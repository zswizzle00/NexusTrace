import logging
from datetime import datetime, timedelta
from collections import deque
from threading import Lock
import time

logger = logging.getLogger(__name__)

class RateLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self.lock = Lock()

    def acquire(self):
        """Acquire a rate limit token, sleeping outside the lock to allow other threads through."""
        while True:
            with self.lock:
                now = datetime.now()
                while self.requests and (now - self.requests[0]) > self.time_window:
                    self.requests.popleft()

                if len(self.requests) < self.max_requests:
                    self.requests.append(now)
                    return True

                sleep_time = (self.requests[0] + self.time_window - now).total_seconds()

            if sleep_time > 0:
                time.sleep(sleep_time)
            else:
                time.sleep(0.01)  # yield to avoid busy-spin when clock skew gives sleep_time <= 0

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def setup_rate_limiters(app):
    pass
