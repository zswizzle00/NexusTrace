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

# Thread safety lock for cache operations
_cache_lock = threading.Lock()

# Flag to prevent multiple cache threads
_cache_thread_started = False
_cache_thread_lock = threading.Lock()


def setup_cache(app):
    """Setup caching for the application."""
    start_cache_clearing_thread()


def timed_lru_cache(seconds: int, maxsize: int = MAX_CACHE_SIZE):
    """
    Cache decorator with TTL and size limit.
    Thread-safe implementation with proper locking.
    """
    def wrapper_decorator(func):
        func = lru_cache(maxsize=maxsize)(func)
        func.lifetime = seconds
        func.expiration = time.time() + seconds
        func._lock = threading.Lock()

        @wraps(func)
        def wrapped_func(*args, **kwargs):
            with func._lock:
                if time.time() >= func.expiration:
                    func.cache_clear()
                    func.expiration = time.time() + func.lifetime
            return func(*args, **kwargs)

        # Expose cache_clear with thread safety
        original_cache_clear = func.cache_clear

        def thread_safe_cache_clear():
            with func._lock:
                original_cache_clear()
                func.expiration = time.time() + func.lifetime

        wrapped_func.cache_clear = thread_safe_cache_clear
        wrapped_func.cache_info = func.cache_info

        return wrapped_func
    return wrapper_decorator


def clear_caches():
    """Clear all cached functions periodically."""
    with _cache_lock:
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
                file_service.get_intezer_analysis
            ]

            for func in functions:
                if hasattr(func, 'cache_clear'):
                    try:
                        func.cache_clear()
                    except Exception as e:
                        logger.debug(f"Could not clear cache for {func.__name__}: {e}")

            logger.debug("Caches cleared successfully")
        except ImportError as e:
            logger.debug(f"Module not loaded yet, skipping cache clear: {e}")
        except Exception as e:
            logger.error(f"Error clearing caches: {str(e)}")


def schedule_cache_clearing():
    """Schedule cache clearing every 30 minutes."""
    while True:
        time.sleep(CACHE_TTL)
        clear_caches()


def start_cache_clearing_thread():
    """Start the cache clearing thread (only once)."""
    global _cache_thread_started

    with _cache_thread_lock:
        if _cache_thread_started:
            return

        cache_thread = threading.Thread(
            target=schedule_cache_clearing,
            daemon=True,
            name="CacheClearingThread"
        )
        cache_thread.start()
        _cache_thread_started = True
        logger.info("Cache clearing thread started")
