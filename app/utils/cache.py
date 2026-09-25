import time
import logging
from functools import lru_cache, wraps
import threading
import importlib

logger = logging.getLogger(__name__)

# How often the background thread flushes every cache in clear_caches(). This is NOT a
# TTL: each cached function carries its own via timed_lru_cache(seconds=...), and those
# range from 600 to 3600. Because the sweep clears all of them unconditionally, it is a
# ceiling on every one, so the four functions declaring 3600 effectively expire at 1800.
# Raise this before raising any per-function TTL past it, or the longer TTL does nothing.
CLEAR_INTERVAL_SECONDS = 1800
MAX_CACHE_SIZE = 1000

_cache_lock = threading.Lock()

_cache_thread_started = False
_cache_thread_lock = threading.Lock()


def setup_cache(app):
    start_cache_clearing_thread()


def timed_lru_cache(seconds: int, maxsize: int = MAX_CACHE_SIZE):
    """Thread-safe cache decorator with TTL and size limit. The TTL is
    per-function, not per-key: one expiry flushes the whole function's cache."""
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
    """Every cached function in the app, listed explicitly below: a function decorated
    with timed_lru_cache is not cleared until it is added here."""
    with _cache_lock:
        try:
            ip_service = importlib.import_module('app.services.ip_service')
            domain_service = importlib.import_module('app.services.domain_service')
            hash_service = importlib.import_module('app.services.hash_service')
            url_service = importlib.import_module('app.services.url_service')
            file_service = importlib.import_module('app.services.file_service')
            event_service = importlib.import_module('app.services.event_service')
            azure_error_service = importlib.import_module('app.services.azure_error_service')
            abusech = importlib.import_module('app.services.abusech')

            functions = [
                ip_service.check_abuseipdb,
                ip_service.get_ipinfo_data,
                ip_service.get_shodan_info,
                ip_service.get_proxycheck_data,
                ip_service.get_alienvault_data,
                ip_service.get_vpn_data,
                ip_service.get_ip2location_data,
                ip_service.get_ipapi_data,
                ip_service.get_greynoise_data,
                # Caching matters more for these two than for most: rdap.org bootstraps
                # to a different registry per TLD, and web.archive.org's CDX latency was
                # measured swinging between 2s and 10s for the SAME request seconds
                # apart. A cached success rides out the next slow window.
                domain_service.get_rdap_info,
                domain_service.get_wayback_history,
                domain_service.get_whois_info,
                domain_service.get_dns_records,
                domain_service.get_ssl_info,
                domain_service.get_reverse_ip_domains,
                domain_service.get_subdomains_crtsh,
                domain_service.get_dmarc_record,
                domain_service.get_talos_reputation,
                domain_service.get_domain_info,
                domain_service.get_domain_info_quick,
                # The cached function is the private inner one: get_virustotal_report is a
                # thin uncached wrapper that turns a spent quota into `rate_limited`
                # without memoizing it.
                hash_service._virustotal_report,
                hash_service.get_malwarebazaar_report,
                hash_service.get_threatfox_iocs,
                hash_service.get_circl_hashlookup,
                hash_service.get_cymru_mhr,
                hash_service.get_hash_info,
                abusech.threatfox_lookup,
                abusech.threatfox_hash,
                abusech.urlhaus_host,
                abusech.urlhaus_url,
                abusech.urlhaus_payload,
                abusech.malwarebazaar_hash,
                abusech.hunting_fplist,
                url_service.get_favicon_hash,
                url_service.get_tech_stack,
                file_service.get_combined_file_analysis,
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
    while True:
        time.sleep(CLEAR_INTERVAL_SECONDS)
        clear_caches()


def start_cache_clearing_thread():
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
