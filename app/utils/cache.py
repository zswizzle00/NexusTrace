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
            ip_service = importlib.import_module('app.services.ip_service')
            domain_service = importlib.import_module('app.services.domain_service')
            hash_service = importlib.import_module('app.services.hash_service')
            url_service = importlib.import_module('app.services.url_service')
            file_service = importlib.import_module('app.services.file_service')
            event_service = importlib.import_module('app.services.event_service')
            azure_error_service = importlib.import_module('app.services.azure_error_service')

            functions = [
                # ip_service
                ip_service.check_abuseipdb,
                ip_service.get_ipinfo_data,
                ip_service.get_shodan_info,
                ip_service.get_proxycheck_data,
                ip_service.get_alienvault_data,
                ip_service.get_vpn_data,
                ip_service.get_ip2location_data,
                ip_service.get_ipapi_data,
                # domain_service
                domain_service.get_whois_info,
                domain_service.get_dns_records,
                domain_service.get_ssl_info,
                domain_service.get_reverse_ip_domains,
                domain_service.get_subdomains_crtsh,
                domain_service.get_dmarc_record,
                domain_service.get_talos_reputation,
                domain_service.get_domain_info,
                domain_service.get_domain_info_quick,
                # hash_service
                hash_service.get_virustotal_report,
                hash_service.get_malwarebazaar_report,
                hash_service.get_threatfox_iocs,
                hash_service.get_hash_info,
                # url_service
                url_service.get_favicon_hash,
                url_service.get_tech_stack,
                # file_service
                file_service.get_combined_file_analysis,
                # event/azure services
                event_service.get_event_info,
                azure_error_service.get_azure_error_info,
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
