import os
import socket
import ssl
import dns.resolver
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
from datetime import timedelta
from ..utils.rate_limiter import RateLimiter
from ..utils.cache import timed_lru_cache

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiters
ip2whois_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))

# Global timeout settings (in seconds)
TIMEOUT_SHORT = 5
TIMEOUT_MEDIUM = 10
TIMEOUT_LONG = 15

# Configure DNS resolver with timeout
dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = TIMEOUT_SHORT
dns_resolver.lifetime = TIMEOUT_MEDIUM


def setup_domain_services(app):
    """Setup domain-related services."""
    pass


def safe_execute(func, *args, default=None, timeout=TIMEOUT_MEDIUM, **kwargs):
    """Execute a function with timeout and error handling."""
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func, *args, **kwargs)
            return future.result(timeout=timeout)
    except FuturesTimeoutError:
        logger.warning(f"{func.__name__} timed out after {timeout}s")
        return default
    except Exception as e:
        logger.error(f"{func.__name__} failed: {str(e)}")
        return default


@timed_lru_cache(seconds=1800, maxsize=500)
def get_whois_info(domain):
    """Fetch WHOIS information for a domain using IP2Location API."""
    try:
        ip2whois_key = os.getenv('IP2WHOIS_KEY')
        if not ip2whois_key:
            logger.warning("IP2WHOIS_KEY not configured")
            return None
        ip2whois_limiter.acquire()
        response = requests.get(
            'https://api.ip2whois.com/v2',
            params={'key': ip2whois_key, 'domain': domain},
            timeout=TIMEOUT_MEDIUM
        )
        response.raise_for_status()
        return response.json()
    except requests.Timeout:
        logger.warning(f"WHOIS lookup timed out for {domain}")
        return None
    except Exception as e:
        logger.error(f"Error fetching WHOIS information: {str(e)}")
        return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_whois_python(domain):
    """Fetch WHOIS using python-whois library (fallback)."""
    try:
        import whois
        # whois.whois can hang, so wrap it
        def _fetch():
            return whois.whois(domain)
        return safe_execute(_fetch, timeout=TIMEOUT_MEDIUM)
    except Exception as e:
        logger.error(f"Python WHOIS failed for {domain}: {str(e)}")
        return None


@timed_lru_cache(seconds=900, maxsize=500)
def get_dns_records(domain):
    """Fetch various DNS records for a domain with timeouts."""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    def fetch_record(record_type):
        try:
            answers = dns_resolver.resolve(domain, record_type)
            return record_type, [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return record_type, []
        except dns.resolver.NoAnswer:
            return record_type, []
        except dns.resolver.Timeout:
            logger.debug(f"DNS {record_type} lookup timed out for {domain}")
            return record_type, []
        except Exception as e:
            logger.debug(f"Could not fetch {record_type} records: {str(e)}")
            return record_type, []

    # Fetch all DNS records in parallel
    with ThreadPoolExecutor(max_workers=len(record_types)) as executor:
        futures = {executor.submit(fetch_record, rt): rt for rt in record_types}
        for future in as_completed(futures, timeout=TIMEOUT_MEDIUM):
            try:
                record_type, values = future.result()
                records[record_type] = values
            except Exception:
                records[futures[future]] = []

    return records


@timed_lru_cache(seconds=1800, maxsize=500)
def get_ssl_info(domain):
    """Fetch SSL/TLS certificate information for a domain with timeout."""
    try:
        context = ssl.create_default_context()
        # Set socket timeout
        with socket.create_connection((domain, 443), timeout=TIMEOUT_SHORT) as sock:
            sock.settimeout(TIMEOUT_SHORT)
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert['version'],
                    'serial_number': cert['serialNumber'],
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter'],
                    'cipher': ssock.cipher()
                }
    except socket.timeout:
        logger.warning(f"SSL connection timed out for {domain}")
        return None
    except Exception as e:
        logger.debug(f"Error fetching SSL information: {str(e)}")
        return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_reverse_ip_domains(ip):
    """Get domains sharing the same IP using hackertarget.com."""
    if not ip:
        return []
    try:
        resp = requests.get(
            f'https://api.hackertarget.com/reverseiplookup/?q={ip}',
            timeout=TIMEOUT_SHORT
        )
        if resp.status_code == 200 and 'No records' not in resp.text and 'error' not in resp.text.lower():
            domains = [d.strip() for d in resp.text.splitlines() if d.strip()]
            return domains[:50]  # Limit results
    except requests.Timeout:
        logger.warning(f"Reverse IP lookup timed out for {ip}")
    except Exception as e:
        logger.error(f"Error in reverse IP lookup: {str(e)}")
    return []


@timed_lru_cache(seconds=3600, maxsize=500)
def get_subdomains_crtsh(domain):
    """Get subdomains from crt.sh (certificate transparency logs)."""
    try:
        # crt.sh is often slow, use short timeout
        resp = requests.get(
            f'https://crt.sh/?q=%25.{domain}&output=json',
            timeout=TIMEOUT_SHORT,
            headers={'User-Agent': 'NexusTrace/1.0'}
        )
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data[:500]:  # Limit processing
                name = entry.get('name_value')
                if name:
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(domain.lower()) and '*' not in sub:
                            subdomains.add(sub)
            return sorted(subdomains)[:100]  # Limit results
    except requests.Timeout:
        logger.warning(f"crt.sh lookup timed out for {domain}")
    except Exception as e:
        logger.debug(f"Error in crt.sh subdomain lookup: {str(e)}")
    return []


def parse_spf_dkim_dmarc(txt_records):
    """Parse email security records from TXT records."""
    spf = [r for r in txt_records if 'v=spf1' in r.lower()]
    dkim = [r for r in txt_records if 'dkim' in r.lower()]
    dmarc = [r for r in txt_records if 'v=dmarc1' in r.lower()]
    return {'spf': spf, 'dkim': dkim, 'dmarc': dmarc}


@timed_lru_cache(seconds=3600, maxsize=500)
def get_dmarc_record(domain):
    """Fetch DMARC record directly."""
    try:
        answers = dns_resolver.resolve(f'_dmarc.{domain}', 'TXT')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def extract_domain_for_phishtank(indicator):
    """Extract domain from URL or return as-is."""
    try:
        if indicator.lower().startswith(('http://', 'https://')):
            return urlparse(indicator).netloc
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator):
            return None
        else:
            return indicator
    except Exception:
        return indicator


def check_phishtank(indicator):
    """Generate PhishTank search URL."""
    domain = extract_domain_for_phishtank(indicator)
    if domain:
        return f'https://phishtank.org/search.php?valid=y&active=y&Search={domain}'
    return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_talos_reputation(domain):
    """Generate Talos lookup URL (avoid scraping which is unreliable)."""
    return {
        'talos_url': f'https://talosintelligence.com/reputation_center/lookup?search={domain}',
        'verdict': None,
        'category': None
    }


@timed_lru_cache(seconds=900, maxsize=500)
def get_domain_info(domain):
    """Get comprehensive domain information with all operations in parallel."""
    results = {
        'domain': domain,
        'whois': None,
        'dns_records': {},
        'ssl_info': None,
        'ip_address': None,
        'reverse_domains': [],
        'subdomains': [],
        'email_security': {'spf': [], 'dkim': [], 'dmarc': []},
        'phishtank_url': None,
        'talos_reputation': None,
        'errors': []
    }

    try:
        # Phase 1: Core lookups in parallel (fast, essential)
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(get_whois_info, domain): 'whois_api',
                executor.submit(get_dns_records, domain): 'dns',
                executor.submit(get_ssl_info, domain): 'ssl',
                executor.submit(lambda: socket.gethostbyname(domain)): 'ip',
            }

            for future in as_completed(futures, timeout=TIMEOUT_LONG):
                key = futures[future]
                try:
                    result = future.result(timeout=TIMEOUT_SHORT)
                    if key == 'whois_api':
                        results['whois'] = result
                    elif key == 'dns':
                        results['dns_records'] = result or {}
                    elif key == 'ssl':
                        results['ssl_info'] = result
                    elif key == 'ip':
                        results['ip_address'] = result
                except Exception as e:
                    results['errors'].append(f"{key}: {str(e)}")
                    logger.debug(f"Phase 1 {key} failed: {str(e)}")

        # Parse email security from DNS TXT records
        txt_records = results['dns_records'].get('TXT', [])
        results['email_security'] = parse_spf_dkim_dmarc(txt_records)

        # Get DMARC if not in TXT records
        if not results['email_security']['dmarc']:
            dmarc = get_dmarc_record(domain)
            if dmarc:
                results['email_security']['dmarc'] = dmarc

        # Generate static URLs (no network call needed)
        results['phishtank_url'] = check_phishtank(domain)
        results['talos_reputation'] = get_talos_reputation(domain)

        # Phase 2: Enrichment lookups in parallel (slower, optional)
        ip_address = results['ip_address']
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}

            if ip_address:
                futures[executor.submit(get_reverse_ip_domains, ip_address)] = 'reverse_ip'

            futures[executor.submit(get_subdomains_crtsh, domain)] = 'subdomains'

            for future in as_completed(futures, timeout=TIMEOUT_LONG):
                key = futures[future]
                try:
                    result = future.result(timeout=TIMEOUT_MEDIUM)
                    if key == 'reverse_ip':
                        results['reverse_domains'] = result or []
                    elif key == 'subdomains':
                        results['subdomains'] = result or []
                except Exception as e:
                    results['errors'].append(f"{key}: timed out or failed")
                    logger.debug(f"Phase 2 {key} failed: {str(e)}")

        # Clean up errors list if empty
        if not results['errors']:
            del results['errors']

        return results

    except Exception as e:
        logger.error(f"Error getting domain information for {domain}: {str(e)}")
        results['errors'].append(f"Fatal error: {str(e)}")
        return results


@timed_lru_cache(seconds=600, maxsize=500)
def get_domain_info_quick(domain):
    """Quick domain lookup - only essential info with strict timeouts."""
    results = {
        'domain': domain,
        'dns_records': {},
        'ssl_info': None,
        'ip_address': None,
        'email_security': {'spf': [], 'dkim': [], 'dmarc': []},
    }

    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(get_dns_records, domain): 'dns',
                executor.submit(get_ssl_info, domain): 'ssl',
                executor.submit(lambda: socket.gethostbyname(domain)): 'ip',
            }

            for future in as_completed(futures, timeout=TIMEOUT_MEDIUM):
                key = futures[future]
                try:
                    result = future.result(timeout=TIMEOUT_SHORT)
                    if key == 'dns':
                        results['dns_records'] = result or {}
                    elif key == 'ssl':
                        results['ssl_info'] = result
                    elif key == 'ip':
                        results['ip_address'] = result
                except Exception:
                    pass

        txt_records = results['dns_records'].get('TXT', [])
        results['email_security'] = parse_spf_dkim_dmarc(txt_records)

        return results

    except Exception as e:
        logger.error(f"Quick domain lookup failed for {domain}: {str(e)}")
        return results
