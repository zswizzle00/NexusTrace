import os
import requests
import logging
from urllib.parse import quote
import concurrent.futures
from datetime import timedelta
import shodan
from ..utils.cache import timed_lru_cache
from ..utils.rate_limiter import RateLimiter
from ..utils.constants import TIMEOUT_SHORT, TIMEOUT_MEDIUM
from ..utils.url_guard import _blocked_ip
import json
import re
import ipaddress

logger = logging.getLogger(__name__)

alienvault_limiter = RateLimiter(max_requests=4, time_window=timedelta(seconds=1))
vpnapi_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
abuseipdb_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
ipinfo_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
proxycheck_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
shodan_limiter = RateLimiter(max_requests=1, time_window=timedelta(seconds=1))
# IP-API.com free tier: 45 req/min over HTTP
ipapi_limiter = RateLimiter(max_requests=1, time_window=timedelta(seconds=2))
ip2location_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))

shodan_key = os.getenv('SHODAN_KEY')
if not shodan_key:
    logger.warning("SHODAN_KEY not configured")
shodan_api = shodan.Shodan(shodan_key) if shodan_key else None

try:
    import geoip2.database
    MMDB_AVAILABLE = True
except ImportError:
    MMDB_AVAILABLE = False
    logger.warning("geoip2 library not available. MMDB database support disabled.")

mmdb_reader = None
if MMDB_AVAILABLE:
    mmdb_path = os.getenv('MMDB_PATH', os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'ipinfo_lite.mmdb'))
    if os.path.exists(mmdb_path):
        try:
            mmdb_reader = geoip2.database.Reader(mmdb_path)
            logger.info("MMDB database loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load MMDB database: {e}")
            mmdb_reader = None
    else:
        logger.info("MMDB database file not found. Download from https://ipinfo.io/lite")

def setup_ip_services(app):
    """Setup IP-related services."""
    pass

@timed_lru_cache(seconds=1800)
def check_abuseipdb(ip_address):
    """Check IP address against AbuseIPDB."""
    abuseipdb_api_key = os.getenv('ABUSEIPDB_KEY')
    if not abuseipdb_api_key:
        logger.warning("AbuseIPDB API key not configured")
        return None
    
    with abuseipdb_limiter:
        try:
            headers = {
                'Key': abuseipdb_api_key,
                'Accept': 'application/json'
            }
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check',
                params={
                    'ipAddress': ip_address,  # requests encodes params; manual quote() would double-encode IPv6
                    'maxAgeInDays': '90',
                    'verbose': ''
                },
                headers=headers,
                timeout=TIMEOUT_MEDIUM
            )
            response.raise_for_status()
            data = response.json()
            if 'data' in data:
                abuse_data = data['data']
                reports = abuse_data.get('reports', [])
                for report in reports:
                    for field in ['categories', 'reporter_id', 'reporter_country_code', 'reporter_country_name', 'reporter_email', 'reporter_username']:
                        if field not in report:
                            report[field] = None
                return {
                    'abuse_confidence_score': abuse_data.get('abuseConfidenceScore', 0),
                    'total_reports': abuse_data.get('totalReports', 0),
                    'distinct_users': abuse_data.get('numDistinctUsers', 0),
                    'last_reported': abuse_data.get('lastReportedAt'),
                    'is_whitelisted': abuse_data.get('isWhitelisted', False),
                    'usage_type': abuse_data.get('usageType'),
                    'isp': abuse_data.get('isp'),
                    'domain': abuse_data.get('domain'),
                    'hostnames': abuse_data.get('hostnames', []),
                    'reports': reports,
                    'country_code': abuse_data.get('countryCode'),
                    'country_name': abuse_data.get('countryName'),
                }
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"AbuseIPDB API request failed: {str(e)}")
            return None

@timed_lru_cache(seconds=1800)
def get_ipinfo_data(ip_address):
    """Get IP information from IPinfo Lite API (no MMDB support, supports flat IPinfo Lite response)."""
    token = os.getenv('IPINFO_TOKEN')
    if not token:
        logger.warning("IPinfo token not configured")
        return None
    encoded_ip = quote(ip_address)
    url = f"https://api.ipinfo.io/lite/{encoded_ip}?token={token}"
    with ipinfo_limiter:
        try:
            response = requests.get(url, timeout=TIMEOUT_MEDIUM)
            response.raise_for_status()
            data = response.json()
            result = {'ip': ip_address}
            for k, v in data.items():
                if v is not None:
                    result[k] = v
            return result
        except Exception as e:
            logger.error(f"IPinfo Lite API request failed: {str(e)}")
            return None

@timed_lru_cache(seconds=1800)
def get_shodan_info(ip_address):
    """Get IP information from Shodan, flattening nested data for frontend rendering."""
    if not shodan_api:
        logger.warning("Shodan API not available - SHODAN_KEY not configured")
        return None
    shodan_limiter.acquire()
    try:
        # Shodan library handles IPv6 natively, no manual encoding needed
        host = shodan_api.host(ip_address)
        def flatten_dict(d):
            return {k: (json.dumps(v, indent=2) if isinstance(v, (dict, list)) else v) for k, v in d.items()}

        shodan_data = {
            'ip': host.get('ip_str'),
            'organization': host.get('org', 'N/A'),
            'operating_system': host.get('os', 'N/A'),
            'ports': [],
            'vulnerabilities': [],
            'services': [],
            'hostnames': host.get('hostnames', []),
            'domains': [str(domain) for domain in host.get('domains', [])],
            'last_update': host.get('last_update'),
            'isp': host.get('isp'),
            'city': host.get('city'),
            'region_code': host.get('region_code'),
            'area_code': host.get('area_code'),
            'dma_code': host.get('dma_code'),
            'country_code': host.get('country_code'),
            'country_name': host.get('country_name'),
            'longitude': host.get('longitude'),
            'latitude': host.get('latitude'),
            'tags': host.get('tags', []),
            'data': [],
        }

        for item in host.get('data', []):
            port_info = flatten_dict({
                'port': item.get('port'),
                'service': item.get('_shodan', {}).get('module', 'N/A'),
                'banner': item.get('data', 'N/A'),
                'product': item.get('product', 'N/A'),
                'version': item.get('version', 'N/A'),
                'cpe': ', '.join(item.get('cpe', [])) if isinstance(item.get('cpe', []), list) else item.get('cpe', ''),
                'ssl': json.dumps(item.get('ssl')) if item.get('ssl') else None,
                'http': json.dumps(item.get('http')) if item.get('http') else None,
            })
            shodan_data['ports'].append(port_info)

            if port_info['service'] != 'N/A':
                service_info = flatten_dict({
                    'service': port_info['service'],
                    'port': port_info['port'],
                    'product': port_info['product'],
                    'version': port_info['version'],
                    'ssl': port_info['ssl'],
                    'http': port_info['http'],
                })
                shodan_data['services'].append(service_info)

            shodan_data['data'].append(flatten_dict(item))

        if 'vulns' in host:
            for vuln in host['vulns']:
                vuln_info = host['vulns'][vuln]
                shodan_data['vulnerabilities'].append(flatten_dict({
                    'id': vuln,
                    'summary': vuln_info.get('summary', 'N/A'),
                    'cvss': vuln_info.get('cvss', 'N/A')
                }))

        return shodan_data
    except shodan.APIError as e:
        logger.error(f"Shodan API error: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Error fetching Shodan information: {str(e)}")
        return None

@timed_lru_cache(seconds=1800)
def get_proxycheck_data(ip_address):
    """Get IP information from ProxyCheck.io."""
    proxycheck_limiter.acquire()
    try:
        proxycheck_key = os.getenv('PROXYCHECK_KEY')
        params = {
            'vpn': 1,
            'asn': 1,
            'key': proxycheck_key
        }
        # Manual quoting is needed here because the IP goes in the path, not params.
        encoded_ip = quote(ip_address)
        url = f'https://proxycheck.io/v2/{encoded_ip}'
        response = requests.get(url, params=params, timeout=TIMEOUT_MEDIUM)
        response.raise_for_status()
        data = response.json()
        ip_data = proxycheck_ip_data(data, ip_address)
        return {'proxycheck': {
            **ip_data,
            'risk': ip_data.get('risk'),
            'type': ip_data.get('type'),
            'provider': ip_data.get('provider'),
            'isocode': ip_data.get('isocode'),
            'regioncode': ip_data.get('regioncode'),
            'timezone': ip_data.get('timezone'),
            'abuse': ip_data.get('abuse'),
            'query time': ip_data.get('query time'),
            'node': ip_data.get('node'),
            'active': ip_data.get('active'),
            'last seen': ip_data.get('last seen'),
        }}
    except Exception as e:
        logger.error(f"ProxyCheck.io API request failed: {str(e)}")
        return None

def otx_indicator_type(indicator):
    """Return the OTX endpoint segment for an indicator: 'IPv4', 'IPv6', or 'domain'.

    Must not be narrowed to an IPv4 regex: IPv6 addresses would fall through to the
    'domain' endpoint and never return OTX data.
    """
    try:
        return 'IPv6' if ipaddress.ip_address(indicator).version == 6 else 'IPv4'
    except ValueError:
        return 'domain'

def proxycheck_ip_data(data, ip_address):
    """Pull the per-IP block out of a ProxyCheck.io response.

    ProxyCheck keys the result by IP but may normalize (compress) an IPv6 address so
    it differs from the queried string, making an exact `data[ip]` lookup silently
    miss - hence the fallback to address equality.
    """
    if not isinstance(data, dict):
        return {}
    block = data.get(ip_address)
    if isinstance(block, dict):
        return block
    try:
        target = ipaddress.ip_address(ip_address)
    except ValueError:
        return {}
    for key, value in data.items():
        try:
            if isinstance(value, dict) and ipaddress.ip_address(key) == target:
                return value
        except ValueError:
            continue
    return {}

@timed_lru_cache(seconds=1800)
def get_alienvault_data(indicator):
    """Get data from AlienVault OTX API"""
    api_key = os.getenv('ALIENVAULT_KEY') or os.getenv('ALIENVAULT') or os.getenv('OTX_API_KEY')
    if not api_key:
        logger.debug("AlienVault API key not configured (ALIENVAULT_KEY)")
        return None

    endpoint_type = otx_indicator_type(indicator)

    base_url = f'https://otx.alienvault.com/api/v1/indicators/{endpoint_type}/{indicator}'
    headers = {'X-OTX-API-KEY': api_key}

    try:
        alienvault_limiter.acquire()

        response = requests.get(f'{base_url}/general', headers=headers, timeout=TIMEOUT_MEDIUM)
        response.raise_for_status()
        general_data = response.json()

        geo_data = {}
        try:
            alienvault_limiter.acquire()
            response = requests.get(f'{base_url}/geo', headers=headers, timeout=TIMEOUT_MEDIUM)
            response.raise_for_status()
            geo_data = response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"AlienVault OTX error for section geo: {e}")

        malware_data = {}
        try:
            alienvault_limiter.acquire()
            response = requests.get(f'{base_url}/malware', headers=headers, timeout=TIMEOUT_MEDIUM)
            response.raise_for_status()
            malware_data = response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"AlienVault OTX error for section malware: {e}")

        passive_dns_data = {}
        try:
            alienvault_limiter.acquire()
            response = requests.get(f'{base_url}/passive_dns', headers=headers, timeout=TIMEOUT_MEDIUM)
            response.raise_for_status()
            passive_dns_data = response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"AlienVault OTX error for section passive_dns: {e}")

        return {
            'general': general_data,
            'geo': geo_data,
            'malware': malware_data,
            'passive_dns': passive_dns_data
        }
    except Exception as e:
        # Broad catch (not just RequestException) so a bad/non-JSON response can never
        # propagate and 500 the analysis page; the service degrades to "no OTX data".
        logger.error(f"AlienVault OTX error: {e}")
        return None

@timed_lru_cache(seconds=1800)
def get_vpn_data(ip_address):
    """Get IP information from VPNapi.io."""
    api_key = os.getenv('VPNAPI_KEY')
    if not api_key:
        logger.warning("VPNapi.io API key not configured")
        return None

    with vpnapi_limiter:
        try:
            encoded_ip = quote(ip_address)
            response = requests.get(
                f'https://vpnapi.io/api/{encoded_ip}?key={api_key}',
                timeout=TIMEOUT_SHORT
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"VPNapi.io API request failed: {str(e)}")
            return None

BATCH_COLUMNS = (
    'ip', 'vpn', 'proxy', 'tor', 'relay',
    'city', 'region', 'country', 'continent', 'latitude', 'longitude',
    'network', 'asn', 'asn_org',
    'abuse_score', 'abuse_total_reports', 'abuse_distinct_users', 'abuse_last_reported',
    'abuse_usage_type', 'abuse_isp', 'abuse_domain', 'abuse_whitelisted',
    'ipinfo_hostname', 'ipinfo_org', 'ipinfo_city', 'ipinfo_region', 'ipinfo_country',
    'whois_domain', 'whois_registrar', 'whois_status', 'whois_create_date',
    'whois_expire_date',
    'error',
)

BATCH_SOURCES = ('vpnapi', 'abuseipdb', 'ipinfo')


def batch_row(ip, error=None, **values):
    """A batch row with every column present, so the CSV shape never depends on which
    sources answered."""
    row = dict.fromkeys(BATCH_COLUMNS)
    row.update(values)
    row['ip'] = ip
    row['error'] = error
    return row


def process_ip_batch(ip_addresses):
    """One row per input address, in input order.

    A row is never dropped: an IP that could not be queried or that no source answered
    for comes back with its ``error`` column set. Silent omission would make the report
    lie about how many indicators were checked.
    """
    rows = [None] * len(ip_addresses)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_index = {
            executor.submit(process_single_ip, ip): index
            for index, ip in enumerate(ip_addresses)
        }
        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            try:
                rows[index] = future.result()
            except Exception as e:
                logger.error(f"Error processing IP {ip_addresses[index]}: {e}")
                rows[index] = batch_row(ip_addresses[index], error=f'internal error: {e}')
    return rows


def process_single_ip(ip):
    """Enrich one IP into a batch row from whatever sources answer.

    Every source is optional: a service whose key is missing is a skipped source, not a
    failed row. VPNapi used to gate the whole row, which silently made VPNAPI_KEY a hard
    dependency of the bulk report.
    """
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return batch_row(ip, error='not queried: not a valid IP address')

    # url_guard._blocked_ip is the app's only IP-safety classifier, and its ipv4-mapped,
    # NAT64, site-local and reserved-range branches each closed a real bypass. Private by
    # name, but a second implementation here would drift from the one under test.
    if _blocked_ip(parsed):
        return batch_row(ip, error='not queried: not a globally routable address')

    sources = {}
    for name, fetch in (('vpnapi', get_vpn_data),
                        ('abuseipdb', check_abuseipdb),
                        ('ipinfo', get_ipinfo_data)):
        try:
            sources[name] = fetch(ip)
        except Exception as e:
            logger.error(f"Batch source {name} failed for {ip}: {e}")
            sources[name] = None

    # get_vpn_data returns raw provider JSON, which is not guaranteed to be an object.
    vpn_data = sources['vpnapi'] if isinstance(sources['vpnapi'], dict) else None
    if vpn_data is None or 'error' in vpn_data:
        sources['vpnapi'] = None
        vpn_data = {}
    abuse_data = sources['abuseipdb'] or {}
    ipinfo_data = sources['ipinfo'] or {}

    whois_data = {}
    hostname = ipinfo_data.get('hostname')
    if hostname:
        try:
            from .domain_service import get_whois_info
            whois = get_whois_info(hostname)
            whois_data = whois if isinstance(whois, dict) else {}
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {hostname} ({ip}): {e}")

    security = vpn_data.get('security') or {}
    location = vpn_data.get('location') or {}
    network = vpn_data.get('network') or {}
    registrar = whois_data.get('registrar')
    registrar = registrar if isinstance(registrar, dict) else {}

    silent = [name for name in BATCH_SOURCES if not sources.get(name)]
    if len(silent) == len(BATCH_SOURCES):
        error = 'no data returned by any source: ' + ', '.join(silent)
    elif silent:
        error = 'no data from: ' + ', '.join(silent)
    else:
        error = None

    return batch_row(
        ip,
        error=error,
        vpn=security.get('vpn'),
        proxy=security.get('proxy'),
        tor=security.get('tor'),
        relay=security.get('relay'),
        city=location.get('city'),
        region=location.get('region'),
        country=location.get('country'),
        continent=location.get('continent'),
        latitude=location.get('latitude'),
        longitude=location.get('longitude'),
        network=network.get('network'),
        asn=network.get('autonomous_system_number'),
        asn_org=network.get('autonomous_system_organization'),
        abuse_score=abuse_data.get('abuse_confidence_score'),
        abuse_total_reports=abuse_data.get('total_reports'),
        abuse_distinct_users=abuse_data.get('distinct_users'),
        abuse_last_reported=abuse_data.get('last_reported'),
        abuse_usage_type=abuse_data.get('usage_type'),
        abuse_isp=abuse_data.get('isp'),
        abuse_domain=abuse_data.get('domain'),
        abuse_whitelisted=abuse_data.get('is_whitelisted'),
        ipinfo_hostname=ipinfo_data.get('hostname'),
        ipinfo_org=ipinfo_data.get('org'),
        ipinfo_city=ipinfo_data.get('city'),
        ipinfo_region=ipinfo_data.get('region'),
        ipinfo_country=ipinfo_data.get('country'),
        whois_domain=whois_data.get('domain'),
        whois_registrar=registrar.get('name'),
        whois_status=whois_data.get('status'),
        whois_create_date=whois_data.get('create_date'),
        whois_expire_date=whois_data.get('expire_date'),
    )


@timed_lru_cache(seconds=1800)
def get_ip2location_data(ip_address):
    """Get IP information from IP2Location.io API."""
    api_key = os.getenv('IP2LOCATION_KEY')
    if not api_key:
        logger.warning("IP2Location.io API key not configured")
        return None
    encoded_ip = quote(ip_address)
    url = f'https://api.ip2location.io/?key={api_key}&ip={encoded_ip}&format=json'
    with ip2location_limiter:
        try:
            response = requests.get(url, timeout=TIMEOUT_MEDIUM)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"IP2Location.io API request failed: {str(e)}")
            return None


@timed_lru_cache(seconds=1800)
def get_ipapi_data(ip_address):
    """Get geolocation and network data from IP-API.com (free, no key required).

    Uses HTTP (not HTTPS) - required for the free tier.
    Non-commercial use only per IP-API.com terms.
    """
    try:
        with ipapi_limiter:
            encoded_ip = quote(ip_address)
            fields = 'status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query'
            url = f'http://ip-api.com/json/{encoded_ip}?fields={fields}'
            response = requests.get(url, timeout=TIMEOUT_MEDIUM)
            response.raise_for_status()
            data = response.json()
            if data.get('status') == 'fail':
                logger.debug(f"IP-API.com failure for {ip_address}: {data.get('message')}")
                return None
            return data
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.error(f"IP-API.com request failed for {ip_address}: {str(e)}")
        return None 