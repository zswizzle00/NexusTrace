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

    def _take(self):
        """(granted, wait_seconds) after expiring the window. The single implementation of
        the deque bookkeeping, so acquire() and try_acquire() cannot drift apart. Returns
        under the lock and never sleeps; the caller decides what to do with `wait_seconds`.
        """
        with self.lock:
            now = datetime.now()
            while self.requests and (now - self.requests[0]) > self.time_window:
                self.requests.popleft()

            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True, 0.0

            return False, (self.requests[0] + self.time_window - now).total_seconds()

    def acquire(self):
        """Acquire a rate limit token, sleeping outside the lock to allow other threads through."""
        while True:
            granted, sleep_time = self._take()
            if granted:
                return True

            if sleep_time > 0:
                time.sleep(sleep_time)
            else:
                time.sleep(0.01)  # yield to avoid busy-spin when clock skew gives sleep_time <= 0

    def try_acquire(self):
        """Non-blocking acquire: True having consumed a token, False having consumed
        nothing. No token is ever held for a caller that gets False.

        Only for windows long enough that waiting is worse than not asking. Every other
        limiter here has a sub-second window where acquire()'s blocking politeness is
        exactly right; VirusTotal's is 4 per minute, so a blocked caller parks a gunicorn
        worker thread for up to a minute (see hash_service.get_virustotal_report).
        """
        return self._take()[0]

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

def setup_rate_limiters(app):
    pass
