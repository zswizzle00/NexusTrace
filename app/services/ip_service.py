import os
import requests
import logging
from urllib.parse import quote
import concurrent.futures
from functools import lru_cache, wraps
import time
from datetime import datetime, timedelta
from collections import deque
from threading import Lock
import ipinfo
import shodan
from ..utils.cache import timed_lru_cache
from ..utils.rate_limiter import RateLimiter
import json
import re

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiters
alienvault_limiter = RateLimiter(max_requests=4, time_window=timedelta(seconds=1))
vpnapi_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
abuseipdb_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
ipinfo_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
proxycheck_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
shodan_limiter = RateLimiter(max_requests=1, time_window=timedelta(seconds=1))

# Initialize API clients
ipinfo_token = os.getenv('IPINFO_TOKEN')
ipinfo_handler = ipinfo.getHandler(ipinfo_token) if ipinfo_token else None

shodan_key = os.getenv('SHODAN_KEY')
if not shodan_key:
    logger.warning("SHODAN_KEY not configured")
shodan_api = shodan.Shodan(shodan_key) if shodan_key else None

# Try to import geoip2 for MMDB support
try:
    import geoip2.database
    MMDB_AVAILABLE = True
except ImportError:
    MMDB_AVAILABLE = False
    logger.warning("geoip2 library not available. MMDB database support disabled.")

# Initialize MMDB reader if available
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
    pass  # Add any necessary setup code here

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
            # URL encode the IP address to handle IPv6 addresses properly
            encoded_ip = quote(ip_address)
            response = requests.get(
                f'https://api.abuseipdb.com/api/v2/check',
                params={
                    'ipAddress': encoded_ip,
                    'maxAgeInDays': '90',
                    'verbose': ''
                },
                headers=headers,
                timeout=10
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
    url = f"https://api.ipinfo.io/lite/{ip_address}?token={token}"
    result = {'ip': ip_address}
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        # Map all non-None fields
        for k, v in data.items():
            if v is not None:
                result[k] = v
        return result
    except Exception as e:
        logger.error(f"IPinfo Lite API request failed: {str(e)}")
        return result

@timed_lru_cache(seconds=1800)
def get_shodan_info(ip_address):
    """Get IP information from Shodan, flattening nested data for frontend rendering."""
    if not shodan_api:
        logger.warning("Shodan API not available - SHODAN_KEY not configured")
        return None
    try:
        shodan_limiter.acquire()
        host = shodan_api.host(ip_address)
        def flatten_dict(d):
            # Only keep primitives, serialize nested objects
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

        # Process ports and services
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

            # Add to data array (flattened)
            shodan_data['data'].append(flatten_dict(item))

        # Process vulnerabilities
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
    try:
        proxycheck_limiter.acquire()
        proxycheck_key = os.getenv('PROXYCHECK_KEY')
        params = {
            'vpn': 1,
            'asn': 1,
            'key': proxycheck_key
        }
        url = f'https://proxycheck.io/v2/{ip_address}'
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        ip_data = data.get(ip_address, {})
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

@timed_lru_cache(seconds=1800)
def get_alienvault_data(indicator):
    """Get data from AlienVault OTX API"""
    # Support multiple env var names for backwards compatibility
    api_key = os.getenv('ALIENVAULT_KEY') or os.getenv('ALIENVAULT') or os.getenv('ALIENVAULT_API_KEY')
    if not api_key:
        logger.debug("AlienVault API key not configured (ALIENVAULT_KEY)")
        return None

    # Determine if the indicator is an IP or domain
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    is_ip = bool(ip_pattern.match(indicator))

    # Use the appropriate endpoint type
    endpoint_type = 'IPv4' if is_ip else 'domain'

    base_url = f'https://otx.alienvault.com/api/v1/indicators/{endpoint_type}/{indicator}'
    headers = {'X-OTX-API-KEY': api_key}

    try:
        alienvault_limiter.acquire()

        # Get general information
        response = requests.get(f'{base_url}/general', headers=headers, timeout=10)
        response.raise_for_status()
        general_data = response.json()

        # Get geo information
        geo_data = {}
        try:
            alienvault_limiter.acquire()
            response = requests.get(f'{base_url}/geo', headers=headers, timeout=10)
            response.raise_for_status()
            geo_data = response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"AlienVault OTX error for section geo: {e}")

        # Get malware information
        malware_data = {}
        try:
            alienvault_limiter.acquire()
            response = requests.get(f'{base_url}/malware', headers=headers, timeout=10)
            response.raise_for_status()
            malware_data = response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"AlienVault OTX error for section malware: {e}")

        # Get passive DNS information
        passive_dns_data = {}
        try:
            alienvault_limiter.acquire()
            response = requests.get(f'{base_url}/passive_dns', headers=headers, timeout=10)
            response.raise_for_status()
            passive_dns_data = response.json()
        except requests.exceptions.RequestException as e:
            logger.debug(f"AlienVault OTX error for section passive_dns: {e}")

        # Combine all data
        return {
            'general': general_data,
            'geo': geo_data,
            'malware': malware_data,
            'passive_dns': passive_dns_data
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"AlienVault OTX error: {e}")
        return None

def get_vpn_data(ip_address):
    """Get IP information from VPNapi.io."""
    api_key = os.getenv('VPNAPI_KEY')
    if not api_key:
        logger.warning("VPNapi.io API key not configured")
        return None

    with vpnapi_limiter:
        try:
            # URL encode the IP address to handle IPv6 addresses properly
            encoded_ip = quote(ip_address)
            response = requests.get(
                f'https://vpnapi.io/api/{encoded_ip}?key={api_key}',
                timeout=5
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"VPNapi.io API request failed: {str(e)}")
            return None

def process_ip_batch(ip_addresses):
    """Process a batch of IP addresses concurrently."""
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_ip = {executor.submit(process_single_ip, ip): ip for ip in ip_addresses}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                rows.append(result)
            time.sleep(0.2)
    
    return rows

def process_single_ip(ip):
    """Process a single IP address with all its checks."""
    try:
        # Get VPN API data
        vpn_data = get_vpn_data(ip)
        if not vpn_data or 'error' in vpn_data:
            return None

        # Get other data sources
        abuse_data = check_abuseipdb(ip)
        ipinfo_data = get_ipinfo_data(ip)
        
        # Get WHOIS data if domain is available
        whois_data = None
        if ipinfo_data and ipinfo_data.get('hostname'):
            from .domain_service import get_whois_info
            whois_data = get_whois_info(ipinfo_data['hostname'])

        return {
            'ip': ip,
            # Security
            'vpn': vpn_data.get('security', {}).get('vpn'),
            'proxy': vpn_data.get('security', {}).get('proxy'),
            'tor': vpn_data.get('security', {}).get('tor'),
            'relay': vpn_data.get('security', {}).get('relay'),
            # Location
            'city': vpn_data.get('location', {}).get('city'),
            'region': vpn_data.get('location', {}).get('region'),
            'country': vpn_data.get('location', {}).get('country'),
            'continent': vpn_data.get('location', {}).get('continent'),
            'latitude': vpn_data.get('location', {}).get('latitude'),
            'longitude': vpn_data.get('location', {}).get('longitude'),
            # Network
            'network': vpn_data.get('network', {}).get('network'),
            'asn': vpn_data.get('network', {}).get('autonomous_system_number'),
            'asn_org': vpn_data.get('network', {}).get('autonomous_system_organization'),
            # Abuse
            'abuse_score': abuse_data.get('abuse_confidence_score') if abuse_data else None,
            'abuse_total_reports': abuse_data.get('total_reports') if abuse_data else None,
            'abuse_distinct_users': abuse_data.get('distinct_users') if abuse_data else None,
            'abuse_last_reported': abuse_data.get('last_reported') if abuse_data else None,
            'abuse_usage_type': abuse_data.get('usage_type') if abuse_data else None,
            'abuse_isp': abuse_data.get('isp') if abuse_data else None,
            'abuse_domain': abuse_data.get('domain') if abuse_data else None,
            'abuse_whitelisted': abuse_data.get('is_whitelisted') if abuse_data else None,
            # IPinfo
            'ipinfo_hostname': ipinfo_data.get('hostname') if ipinfo_data else None,
            'ipinfo_org': ipinfo_data.get('org') if ipinfo_data else None,
            'ipinfo_city': ipinfo_data.get('city') if ipinfo_data else None,
            'ipinfo_region': ipinfo_data.get('region') if ipinfo_data else None,
            'ipinfo_country': ipinfo_data.get('country') if ipinfo_data else None,
            # WHOIS
            'whois_domain': whois_data.get('domain') if whois_data else None,
            'whois_registrar': whois_data.get('registrar', {}).get('name') if whois_data and whois_data.get('registrar') else None,
            'whois_status': whois_data.get('status') if whois_data else None,
            'whois_create_date': whois_data.get('create_date') if whois_data else None,
            'whois_expire_date': whois_data.get('expire_date') if whois_data else None,
        }
    except Exception as e:
        logger.error(f"Error processing IP {ip}: {str(e)}")
        return None 

def get_ip2location_data(ip_address):
    """Get IP information from IP2Location.io API."""
    api_key = os.getenv('IP2LOCATION_KEY')
    if not api_key:
        logger.warning("IP2Location.io API key not configured")
        return None
    url = f'https://api.ip2location.io/?key={api_key}&ip={ip_address}&format=json'
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        # Optionally, flatten or map fields for template
        return data
    except Exception as e:
        logger.error(f"IP2Location.io API request failed: {str(e)}")
        return None 

def get_ip_info(ip):
    result = {}
    # ... existing code ...
    # Add AlienVault OTX
    try:
        from .alienvault_service import get_alienvault_data, parse_alienvault_otx
        alienvault_raw = get_alienvault_data(ip)
        if alienvault_raw:
            result['alienvault'] = parse_alienvault_otx(alienvault_raw)
    except Exception as e:
        logger.error(f"AlienVault OTX error: {str(e)}")
    # Add Intezer (if available for IPs)
    try:
        from .file_service import get_intezer_analysis
        intezer_result = get_intezer_analysis(ip=ip)
        if intezer_result:
            result['intezer_result'] = intezer_result
    except Exception as e:
        logger.error(f"Intezer enrichment error: {str(e)}")
    # ... existing code ...
    return result 