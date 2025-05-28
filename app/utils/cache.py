import time
import logging
from functools import lru_cache, wraps
import threading
import importlib

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
    try:
        # Dynamically import the modules when needed
        ip_service = importlib.import_module('app.services.ip_service')
        file_service = importlib.import_module('app.services.file_service')
        
        # List of functions to clear
        functions = [
            ip_service.check_abuseipdb,
            ip_service.get_ipinfo_data,
            ip_service.get_shodan_info,
            ip_service.get_proxycheck_data,
            ip_service.get_alienvault_data,
            file_service.get_intezer_analysis
        ]
        
        for func in functions:
            if hasattr(func, 'cache_clear'):
                func.cache_clear()
    except Exception as e:
        logger.error(f"Error clearing caches: {str(e)}")

def schedule_cache_clearing():
    """Schedule cache clearing every 30 minutes."""
    while True:
        time.sleep(1800)  # 30 minutes
        clear_caches()

# Start cache clearing thread
cache_thread = threading.Thread(target=schedule_cache_clearing, daemon=True)
cache_thread.start() 