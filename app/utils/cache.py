import time
import logging
from functools import lru_cache, wraps
import threading

# Configure logging
logger = logging.getLogger(__name__)

# Cache configuration
CACHE_TTL = 1800  # 30 minutes cache TTL
MAX_CACHE_SIZE = 1000  # Maximum number of cached items

def setup_cache(app):
    """Setup caching for the application."""
    pass  # Add any necessary setup code here

def timed_lru_cache(seconds: int, maxsize: int = MAX_CACHE_SIZE):
    """Cache decorator with TTL and size limit."""
    def wrapper_decorator(func):
        func = lru_cache(maxsize=maxsize)(func)
        func.lifetime = seconds
        func.expiration = time.time() + seconds

        @wraps(func)
        def wrapped_func(*args, **kwargs):
            if time.time() >= func.expiration:
                func.cache_clear()
                func.expiration = time.time() + func.lifetime
            return func(*args, **kwargs)

        return wrapped_func
    return wrapper_decorator

def clear_caches():
    """Clear all cached functions periodically."""
    for func in [check_abuseipdb, get_ipinfo_data, get_shodan_info, 
                get_proxycheck_data, get_alienvault_data, get_intezer_analysis]:
        if hasattr(func, 'cache_clear'):
            func.cache_clear()

def schedule_cache_clearing():
    """Schedule cache clearing every 30 minutes."""
    while True:
        time.sleep(1800)  # 30 minutes
        clear_caches()

# Start cache clearing thread
cache_thread = threading.Thread(target=schedule_cache_clearing, daemon=True)
cache_thread.start() 