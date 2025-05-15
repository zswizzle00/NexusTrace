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

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiters
alienvault_limiter = RateLimiter(max_requests=4, time_window=timedelta(seconds=1))
vpnapi_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
abuseipdb_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
ipinfo_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))

# Initialize API clients
ipinfo_token = os.getenv('IPINFO_TOKEN')
ipinfo_handler = ipinfo.getHandler(ipinfo_token) if ipinfo_token else None

shodan_key = os.getenv('SHODAN_KEY', '***REMOVED***')
shodan_api = shodan.Shodan(shodan_key)

def setup_ip_services(app):
    """Setup IP-related services."""
    pass  # Add any necessary setup code here

@timed_lru_cache(seconds=1800)
def check_abuseipdb(ip_address):
    """Check IP address against AbuseIPDB."""
    abuseipdb_api_key = '0292dbf8d7f5cf73d1b3111c92a7455e3984a8167b7b67054029f5775288be330b64336ef7192141'
    if not abuseipdb_api_key:
        logger.warning("AbuseIPDB API key not configured")
        return None
    
    with abuseipdb_limiter:
        try:
            headers = {
                'Key': abuseipdb_api_key,
                'Accept': 'application/json'
            }
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
    """Get IP information from IPinfo."""
    with ipinfo_limiter:
        try:
            details = ipinfo_handler.getDetails(ip_address)
            return {
                'ipinfo': {
                    'ip': getattr(details, 'ip', None),
                    'hostname': getattr(details, 'hostname', None),
                    'city': getattr(details, 'city', None),
                    'region': getattr(details, 'region', None),
                    'country': getattr(details, 'country', None),
                    'loc': getattr(details, 'loc', None),
                    'org': getattr(details, 'org', None),
                    'postal': getattr(details, 'postal', None),
                    'timezone': getattr(details, 'timezone', None),
                    'asn': getattr(details, 'asn', None),
                    'company': getattr(details, 'company', None),
                    'privacy': getattr(details, 'privacy', None),
                    'anycast': getattr(details, 'anycast', None),
                    'abuse': getattr(details, 'abuse', None),
                    'carrier': getattr(details, 'carrier', None),
                    'domains': getattr(details, 'domains', None),
                    'bogon': getattr(details, 'bogon', None),
                }
            }
        except Exception as e:
            logger.error(f"IPinfo API request failed: {str(e)}")
            return None

@timed_lru_cache(seconds=1800)
def get_shodan_info(ip_address):
    """Get IP information from Shodan."""
    try:
        host = shodan_api.host(ip_address)
        shodan_data = {
            'ip': host.get('ip_str'),
            'organization': host.get('org', 'N/A'),
            'operating_system': host.get('os', 'N/A'),
            'ports': [],
            'vulnerabilities': [],
            'services': [],
            'hostnames': host.get('hostnames', []),
            'domains': host.get('domains', []),
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
            'data': host.get('data', []),
        }
        
        # Process ports and services
        for item in host.get('data', []):
            port_info = {
                'port': item.get('port'),
                'service': item.get('_shodan', {}).get('module', 'N/A'),
                'banner': item.get('data', 'N/A'),
                'product': item.get('product', 'N/A'),
                'version': item.get('version', 'N/A'),
                'cpe': item.get('cpe', []),
                'ssl': item.get('ssl'),
                'http': item.get('http'),
            }
            shodan_data['ports'].append(port_info)
            
            if port_info['service'] != 'N/A':
                service_info = {
                    'service': port_info['service'],
                    'port': port_info['port'],
                    'product': port_info['product'],
                    'version': port_info['version'],
                    'ssl': port_info['ssl'],
                    'http': port_info['http'],
                }
                shodan_data['services'].append(service_info)
        
        # Process vulnerabilities
        if 'vulns' in host:
            for vuln in host['vulns']:
                shodan_data['vulnerabilities'].append({
                    'id': vuln,
                    'summary': host['vulns'][vuln].get('summary', 'N/A'),
                    'cvss': host['vulns'][vuln].get('cvss', 'N/A')
                })
        
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
def get_alienvault_data(ip_address):
    """Get IP information from AlienVault OTX."""
    api_key = os.getenv('ALIENVAULT')
    if not api_key:
        logger.warning("AlienVault API key not configured")
        return None

    base_url = 'https://otx.alienvault.com/api/v1/indicators/IPv4'
    headers = {
        'X-OTX-API-KEY': api_key,
        'Accept': 'application/json'
    }
    
    sections = ['general', 'vpn', 'geo']
    results = {}
    
    with alienvault_limiter:
        def fetch_section(section):
            try:
                url = f"{base_url}/{ip_address}/{section}"
                resp = requests.get(
                    url, 
                    headers=headers, 
                    timeout=30,
                    verify=True
                )
                resp.raise_for_status()
                return section, resp.json()
            except Exception as e:
                logger.error(f"AlienVault OTX error for section {section}: {str(e)}")
                return section, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            future_to_section = {
                executor.submit(fetch_section, section): section 
                for section in sections
            }
            
            for future in concurrent.futures.as_completed(future_to_section):
                section, data = future.result()
                results[section] = data
                time.sleep(0.5)

    return results

def get_vpn_data(ip_address):
    """Get IP information from VPNapi.io."""
    api_key = os.getenv('VPNAPI_KEY')
    if not api_key:
        logger.warning("VPNapi.io API key not configured")
        return None

    with vpnapi_limiter:
        try:
            response = requests.get(
                f'https://vpnapi.io/api/{ip_address}?key={api_key}',
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
        if ipinfo_data and ipinfo_data.get('ipinfo', {}).get('hostname'):
            from .domain_service import get_whois_info
            whois_data = get_whois_info(ipinfo_data['ipinfo']['hostname'])

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
            'ipinfo_hostname': ipinfo_data.get('ipinfo', {}).get('hostname') if ipinfo_data else None,
            'ipinfo_org': ipinfo_data.get('ipinfo', {}).get('org') if ipinfo_data else None,
            'ipinfo_city': ipinfo_data.get('ipinfo', {}).get('city') if ipinfo_data else None,
            'ipinfo_region': ipinfo_data.get('ipinfo', {}).get('region') if ipinfo_data else None,
            'ipinfo_country': ipinfo_data.get('ipinfo', {}).get('country') if ipinfo_data else None,
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