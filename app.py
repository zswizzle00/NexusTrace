from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
import requests
import os
import webbrowser
from dotenv import load_dotenv
from threading import Timer
import atexit
import logging
from urllib.parse import quote, urlparse
import ipinfo
import socket
import pandas as pd
import io
import shodan
import dns.resolver
import ssl
import socket
import whois
from datetime import datetime, timedelta
import json
import re
from bs4 import BeautifulSoup
import builtwith
import requests.exceptions
import concurrent.futures
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from functools import lru_cache, wraps
import time
import logging.handlers
from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis
import threading
from threading import Lock
from collections import deque

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configure requests session with connection pooling
session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"],
    respect_retry_after_header=True
)
adapter = requests.adapters.HTTPAdapter(
    pool_connections=20,
    pool_maxsize=20,
    max_retries=retry_strategy,
    pool_block=False
)
session.mount('http://', adapter)
session.mount('https://', adapter)

# Set default timeout for all requests
session.timeout = 30

# Configure Flask app
app = Flask(__name__)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

lock_file = os.path.join(os.path.dirname(__file__), "browser.lock")

@app.before_request
def before_request():
    """Set up session before each request."""
    session.permanent = True

@app.after_request
def after_request(response):
    """Clean up after each request."""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Cache configuration
CACHE_TTL = 1800  # 30 minutes cache TTL
MAX_WORKERS = 10  # Maximum number of concurrent workers
MAX_CACHE_SIZE = 1000  # Maximum number of cached items

# Cache decorator with TTL and size limit
def timed_lru_cache(seconds: int, maxsize: int = MAX_CACHE_SIZE):
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

# Add periodic cache clearing
def clear_caches():
    """Clear all cached functions periodically."""
    for func in [check_abuseipdb, get_ipinfo_data, get_shodan_info, 
                get_proxycheck_data, get_alienvault_data, get_intezer_analysis]:
        if hasattr(func, 'cache_clear'):
            func.cache_clear()

# Schedule cache clearing every 30 minutes
def schedule_cache_clearing():
    while True:
        time.sleep(1800)  # 30 minutes
        clear_caches()

# Start cache clearing thread
cache_thread = threading.Thread(target=schedule_cache_clearing, daemon=True)
cache_thread.start()

# Get server's IP address
def get_server_ip():
    try:
        # Try to get public IP
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        if response.status_code == 200:
            return response.json()['ip']
    except Exception as e:
        logger.warning(f"Could not get public IP: {str(e)}")
    
    try:
        # Fallback to local IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        logger.error(f"Could not get local IP: {str(e)}")
        return "127.0.0.1"

# Initialize IPinfo handler
ipinfo_token = os.getenv('IPINFO_TOKEN')
if not ipinfo_token:
    logger.warning("IPinfo token not configured")
ipinfo_handler = ipinfo.getHandler(ipinfo_token) if ipinfo_token else None

# Get API keys
api_key = os.getenv('VPNAPI_KEY')
ip2whois_key = os.getenv('IP2WHOIS_KEY', '***REMOVED***')
shodan_key = os.getenv('SHODAN_KEY', '***REMOVED***')

# Initialize Shodan API
shodan_api = shodan.Shodan(shodan_key)

# Initialize Intezer API
intezer_api_key = os.getenv('INTEZER_API_KEY')
if not intezer_api_key:
    logger.warning("Intezer API key not configured")
else:
    api.set_global_api(intezer_api_key)

def cleanup():
    if os.path.exists(lock_file):
        os.remove(lock_file)
        logger.info("Cleaned up browser lock file")

def open_browser():
    if not os.path.exists(lock_file):
        server_ip = get_server_ip()
        port = os.getenv('PORT', '5000')
        url = f'http://{server_ip}:{port}'
        webbrowser.open(url)
        with open(lock_file, 'w') as f:
            f.write('1')
        atexit.register(cleanup)
        logger.info(f"Browser opened successfully at {url}")

@app.route('/')
def index():
    server_ip = get_server_ip()
    return render_template('home.html', server_ip=server_ip)

@app.route('/ip')
def ip_section():
    return render_template('ip_section.html')

@app.route('/domain')
def domain_section():
    return render_template('domain_section.html')

@app.route('/url')
def url_section():
    return render_template('url_section.html')

@timed_lru_cache(seconds=CACHE_TTL)
def check_abuseipdb(ip_address):
    abuseipdb_api_key = '0292dbf8d7f5cf73d1b3111c92a7455e3984a8167b7b67054029f5775288be330b64336ef7192141'
    if not abuseipdb_api_key:
        logger.warning("AbuseIPDB API key not configured")
        return None
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
            # Flatten report details
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

@timed_lru_cache(seconds=CACHE_TTL)
def get_ipinfo_data(ip_address):
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

def get_whois_info(domain):
    """Fetch WHOIS information for a domain using IP2Location API."""
    try:
        response = requests.get(
            f'https://api.ip2whois.com/v2',
            params={
                'key': ip2whois_key,
                'domain': domain
            },
            timeout=10
        )
        response.raise_for_status()
        logging.info(f"WHOIS raw response for {domain}: {response.text}")
        return response.json()
    except Exception as e:
        logging.error(f"Error fetching WHOIS information: {str(e)}")
        return None

@timed_lru_cache(seconds=CACHE_TTL)
def get_shodan_info(ip_address):
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
            'data': host.get('data', []),  # raw banners for each port/service
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
            # Extract service information
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
        # Process vulnerabilities if available
        if 'vulns' in host:
            for vuln in host['vulns']:
                shodan_data['vulnerabilities'].append({
                    'id': vuln,
                    'summary': host['vulns'][vuln].get('summary', 'N/A'),
                    'cvss': host['vulns'][vuln].get('cvss', 'N/A')
                })
        return shodan_data
    except shodan.APIError as e:
        logging.error(f"Shodan API error: {str(e)}")
        return None
    except Exception as e:
        logging.error(f"Error fetching Shodan information: {str(e)}")
        return None

@timed_lru_cache(seconds=CACHE_TTL)
def get_proxycheck_data(ip_address):
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
        # Add all possible fields
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

@timed_lru_cache(seconds=CACHE_TTL)
def get_alienvault_data(ip_address):
    """Fetch multiple sections from AlienVault OTX for an IPv4 address using concurrent requests."""
    api_key = os.getenv('ALIENVAULT')
    if not api_key:
        logger.warning("AlienVault API key not configured")
        return None

    logger.info(f"AlienVault API key configured: {'Yes' if api_key else 'No'}")

    base_url = 'https://otx.alienvault.com/api/v1/indicators/IPv4'
    headers = {
        'X-OTX-API-KEY': api_key,
        'Accept': 'application/json'
    }
    
    # Fetch only used sections from AlienVault OTX
    sections = [
        'general',      # Basic information
        'vpn',         # VPN detection
        'geo'          # Geolocation data
    ]
    
    # Create a session with retry strategy
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    results = {}
    
    def fetch_section(section):
        """Fetch a single section with retry logic."""
        try:
            url = f"{base_url}/{ip_address}/{section}"
            logger.info(f"Fetching AlienVault section {section} from URL: {url}")
            
            resp = session.get(
                url, 
                headers=headers, 
                timeout=30,
                verify=True
            )
            
            logger.info(f"AlienVault {section} response status: {resp.status_code}")
            
            resp.raise_for_status()
            return section, resp.json()
            
        except requests.exceptions.Timeout:
            logger.error(f"Timeout while fetching AlienVault {section} section")
            return section, None
        except requests.exceptions.RequestException as e:
            logger.error(f"AlienVault OTX error for section {section}: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response text: {e.response.text}")
            return section, None
        except Exception as e:
            logger.error(f"Unexpected error fetching AlienVault {section}: {str(e)}")
            return section, None

    # Use ThreadPoolExecutor for concurrent requests with rate limiting
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        # Submit all tasks
        future_to_section = {
            executor.submit(fetch_section, section): section 
            for section in sections
        }
        
        # Process results as they complete
        for future in concurrent.futures.as_completed(future_to_section):
            section, data = future.result()
            results[section] = data
            # Add a small delay between requests to respect rate limits
            time.sleep(0.5)

    return results

@app.route('/check_ip', methods=['POST'])
def check_ip():
    ip_address = request.json.get('ip')
    if not ip_address:
        return jsonify({'error': 'IP address is required'}), 400
    
    try:
        # Get VPN API data first (primary source)
        vpn_data = None
        try:
            vpn_response = session.get(
                f'https://vpnapi.io/api/{ip_address}?key={api_key}',
                timeout=5
            )
            vpn_response.raise_for_status()
            vpn_data = vpn_response.json()
            if 'error' in vpn_data:
                return jsonify({'error': vpn_data['error']}), 500
        except Exception as e:
            logging.error(f"VPNAPI error: {str(e)}")
            vpn_data = {}
        
        # Run API calls sequentially
        results = {}
        
        # AbuseIPDB
        try:
            results['abuse'] = check_abuseipdb(ip_address)
        except Exception as e:
            logging.error(f"AbuseIPDB error: {str(e)}")
            results['abuse'] = None
            
        # IPinfo
        try:
            results['ipinfo'] = get_ipinfo_data(ip_address)
        except Exception as e:
            logging.error(f"IPinfo error: {str(e)}")
            results['ipinfo'] = None
            
        # Shodan
        try:
            results['shodan'] = get_shodan_info(ip_address)
        except Exception as e:
            logging.error(f"Shodan error: {str(e)}")
            results['shodan'] = None
            
        # ProxyCheck
        try:
            results['proxycheck'] = get_proxycheck_data(ip_address)
        except Exception as e:
            logging.error(f"ProxyCheck error: {str(e)}")
            results['proxycheck'] = None
            
        # AlienVault
        try:
            results['alienvault'] = get_alienvault_data(ip_address)
        except Exception as e:
            logging.error(f"AlienVault error: {str(e)}")
            results['alienvault'] = None

        # Combine results with VPNapi.io data as primary source
        result = vpn_data if vpn_data else {}
        
        # Add other data sources
        if results['abuse']:
            result['abuse'] = results['abuse']
        if results['ipinfo']:
            result.update(results['ipinfo'])
        if results['shodan']:
            result['shodan'] = results['shodan']
        if results['proxycheck']:
            result.update(results['proxycheck'])
        if results['alienvault']:
            result['alienvault'] = results['alienvault']
        
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error processing IP {ip_address}: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/check_ips', methods=['POST'])
def check_ips():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Read the file based on its extension
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith('.xlsx'):
            df = pd.read_excel(file)
        elif file.filename.endswith('.txt'):
            df = pd.read_csv(file, header=None, names=['ip'])
        else:
            return jsonify({'error': 'Unsupported file format'}), 400
        
        # Extract IP addresses from the first column
        ip_addresses = df.iloc[:, 0].tolist()
        
        # Validate IP addresses
        valid_ips = []
        for ip in ip_addresses:
            try:
                # Basic IP validation
                if isinstance(ip, str) and len(ip.split('.')) == 4:
                    valid_ips.append(ip)
            except:
                continue
        
        if not valid_ips:
            return jsonify({'error': 'No valid IP addresses found in the file'}), 400

        def process_ip(ip):
            """Process a single IP address with all its checks."""
            try:
                # Create a session with retry strategy for this IP
                ip_session = requests.Session()
                retry_strategy = Retry(
                    total=3,
                    backoff_factor=1,
                    status_forcelist=[429, 500, 502, 503, 504]
                )
                adapter = HTTPAdapter(max_retries=retry_strategy)
                ip_session.mount("http://", adapter)
                ip_session.mount("https://", adapter)

                # Get VPN API data
                vpn_response = ip_session.get(
                    f'https://vpnapi.io/api/{ip}?key={api_key}',
                    timeout=10
                )
                vpn_response.raise_for_status()
                vpn_data = vpn_response.json()
                if 'error' in vpn_data:
                    return None

                # Get other data sources
                abuse_data = check_abuseipdb(ip)
                ipinfo_data = get_ipinfo_data(ip)
                
                # Get WHOIS data if domain is available
                whois_data = None
                if ipinfo_data and ipinfo_data.get('ipinfo', {}).get('hostname'):
                    whois_data = get_whois_info(ipinfo_data['ipinfo']['hostname'])

                # Flatten and stringify complex fields for CSV
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
                logging.error(f"Error processing IP {ip}: {str(e)}")
                return None

        # Process IPs concurrently with rate limiting
        rows = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            # Submit all tasks
            future_to_ip = {executor.submit(process_ip, ip): ip for ip in valid_ips}
            
            # Process results as they complete
            for future in concurrent.futures.as_completed(future_to_ip):
                result = future.result()
                if result:
                    rows.append(result)
                # Add a small delay between batches to respect rate limits
                time.sleep(0.2)

        if not rows:
            return jsonify({'error': 'No valid results could be obtained for any IP addresses'}), 400

        # Create a DataFrame and output as CSV
        out_df = pd.DataFrame(rows)
        output = io.StringIO()
        out_df.to_csv(output, index=False)
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name='ip_report.csv'
        )
    except Exception as e:
        logging.error(f"Error processing file: {str(e)}")
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

def get_dns_records(domain):
    """Fetch various DNS records for a domain."""
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [str(rdata) for rdata in answers]
        except Exception as e:
            records[record_type] = []
            logging.debug(f"Could not fetch {record_type} records: {str(e)}")
    
    return records

def get_ssl_info(domain):
    """Fetch SSL/TLS certificate information for a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
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
    except Exception as e:
        logging.error(f"Error fetching SSL information: {str(e)}")
        return None

def analyze_url(url):
    """Analyze a URL for various security and technical aspects."""
    try:
        # Configure retry strategy
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Parse URL
        parsed_url = urlparse(url)
        
        # Get response with headers
        response = session.get(url, timeout=10, allow_redirects=True)
        
        # Analyze redirect chain
        redirect_chain = []
        if response.history:
            for resp in response.history:
                redirect_chain.append({
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers)
                })
        
        # Get final response info
        final_response = {
            'url': response.url,
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type', ''),
            'headers': dict(response.headers),
            'redirect_chain': redirect_chain
        }
        
        # Check security headers
        security_headers = {
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Not Set'),
            'X-Frame-Options': response.headers.get('X-Frame-Options', 'Not Set'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Not Set'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Not Set'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Not Set')
        }
        
        # Detect technologies
        try:
            tech_stack = builtwith.builtwith(url)
        except:
            tech_stack = {}
        
        # Parse content if it's HTML
        if 'text/html' in response.headers.get('content-type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = [{'name': tag.get('name', ''), 'content': tag.get('content', '')} 
                        for tag in soup.find_all('meta')]
            title = soup.title.string if soup.title else ''
        else:
            meta_tags = []
            title = ''

        # Get Intezer analysis if API key is configured
        intezer_analysis = None
        if os.getenv('INTEZER_API_KEY'):
            try:
                # Initialize Intezer API
                api.set_global_api_key(os.getenv('INTEZER_API_KEY'))
                
                # Create a temporary file with the URL content
                temp_file = f'/tmp/url_content_{hash(url)}.html'
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                
                # Analyze the file
                analysis = FileAnalysis(file_path=temp_file)
                analysis.send(wait=True)
                result = analysis.result()
                
                # Get additional information
                root_analysis = analysis.get_root_analysis()
                code_reuse = root_analysis.code_reuse if root_analysis else None
                metadata = root_analysis.metadata if root_analysis else None
                
                intezer_analysis = {
                    'analysis_id': result.get('analysis_id'),
                    'analysis_time': result.get('analysis_time'),
                    'analysis_url': result.get('analysis_url'),
                    'family_name': result.get('family_name'),
                    'is_private': result.get('is_private'),
                    'sha256': result.get('sha256'),
                    'sub_verdict': result.get('sub_verdict'),
                    'verdict': result.get('verdict'),
                    'code_reuse': code_reuse,
                    'metadata': metadata
                }
                
                # Clean up temporary file
                os.remove(temp_file)
            except Exception as e:
                logger.error(f"Intezer URL analysis failed: {str(e)}")
        
        return {
            'url_analysis': {
                'parsed_url': {
                    'scheme': parsed_url.scheme,
                    'netloc': parsed_url.netloc,
                    'path': parsed_url.path,
                    'params': parsed_url.params,
                    'query': parsed_url.query,
                    'fragment': parsed_url.fragment
                },
                'response': final_response,
                'security_headers': security_headers,
                'technologies': tech_stack,
                'meta_tags': meta_tags,
                'title': title,
                'intezer_analysis': intezer_analysis
            }
        }
    except Exception as e:
        logging.error(f"Error analyzing URL: {str(e)}")
        return None

def get_domain_info(domain):
    """Get comprehensive domain information in parallel."""
    from concurrent.futures import ThreadPoolExecutor
    try:
        with ThreadPoolExecutor() as executor:
            whois_future = executor.submit(whois.whois, domain)
            dns_future = executor.submit(get_dns_records, domain)
            ssl_future = executor.submit(get_ssl_info, domain)

            whois_info = whois_future.result()
            dns_records = dns_future.result()
            ssl_info = ssl_future.result()

        # Get IP address (can be done synchronously, it's fast)
        try:
            ip_address = socket.gethostbyname(domain)
        except:
            ip_address = None

        return {
            'domain': domain,
            'whois': whois_info,
            'dns_records': dns_records,
            'ssl_info': ssl_info,
            'ip_address': ip_address
        }
    except Exception as e:
        logging.error(f"Error getting domain information: {str(e)}")
        return None

@app.route('/check_domain', methods=['POST'])
def check_domain():
    """Endpoint for checking domain information."""
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Get domain information
        domain_info = get_domain_info(domain)
        
        if not domain_info:
            return jsonify({'error': 'Could not fetch domain information'}), 500
        
        return jsonify(domain_info)
    except Exception as e:
        logging.error(f"Error in check_domain: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/analyze_url', methods=['POST'])
def analyze_url_endpoint():
    """Endpoint for analyzing URLs."""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Analyze URL
        url_analysis = analyze_url(url)
        
        if not url_analysis:
            return jsonify({'error': 'Could not analyze URL'}), 500
        
        return jsonify(url_analysis)
    except Exception as e:
        logging.error(f"Error in analyze_url: {str(e)}")
        return jsonify({'error': str(e)}), 500

@timed_lru_cache(seconds=CACHE_TTL)
def get_intezer_analysis(file_path=None, file_hash=None):
    """Analyze a file using Intezer's API."""
    try:
        if not intezer_api_key:
            logger.warning("Intezer API key not configured")
            return None
        if file_path:
            analysis = FileAnalysis(file_path=file_path)
        elif file_hash:
            analysis = FileAnalysis(file_hash=file_hash)
        else:
            return None
        # Send the analysis and wait for results
        analysis.send(wait=True)
        result = analysis.result()
        # Get additional information
        root_analysis = analysis.get_root_analysis()
        code_reuse = root_analysis.code_reuse if root_analysis else None
        metadata = root_analysis.metadata if root_analysis else None
        # Add all possible fields
        return {
            'analysis_id': result.get('analysis_id'),
            'analysis_time': result.get('analysis_time'),
            'analysis_url': result.get('analysis_url'),
            'family_name': result.get('family_name'),
            'is_private': result.get('is_private'),
            'sha256': result.get('sha256'),
            'sub_verdict': result.get('sub_verdict'),
            'verdict': result.get('verdict'),
            'code_reuse': code_reuse,
            'metadata': metadata,
            'malware_family': result.get('malware_family'),
            'threat_type': result.get('threat_type'),
            'indicators': result.get('indicators'),
            'classification': result.get('classification'),
        }
    except Exception as e:
        logger.error(f"Intezer analysis failed: {str(e)}")
        return None

@app.route('/analyze_file', methods=['POST'])
def analyze_file():
    """Endpoint for analyzing files using Intezer."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Save the file temporarily
        temp_path = os.path.join('/tmp', file.filename)
        file.save(temp_path)

        try:
            # Analyze the file
            analysis_result = get_intezer_analysis(file_path=temp_path)
            
            if not analysis_result:
                return jsonify({'error': 'Could not analyze file'}), 500

            return jsonify(analysis_result)
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception as e:
        logger.error(f"Error in analyze_file: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint for container orchestration."""
    health_status = {
        'status': 'healthy',
        'checks': {
            'server_ip': False,
            'api_keys': False,
            'database': False
        }
    }
    
    try:
        # Check server IP
        server_ip = get_server_ip()
        if server_ip and server_ip != "127.0.0.1":
            health_status['checks']['server_ip'] = True
        
        # Check essential API keys
        required_keys = ['VPNAPI_KEY', 'IPINFO_TOKEN', 'SHODAN_KEY']
        missing_keys = [key for key in required_keys if not os.getenv(key)]
        if not missing_keys:
            health_status['checks']['api_keys'] = True
        
        # If all checks pass, return healthy status
        if all(health_status['checks'].values()):
            return jsonify(health_status), 200
        else:
            health_status['status'] = 'unhealthy'
            health_status['message'] = 'One or more health checks failed'
            return jsonify(health_status), 503
            
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        health_status['status'] = 'unhealthy'
        health_status['error'] = str(e)
        return jsonify(health_status), 503

class RateLimiter:
    def __init__(self, max_requests, time_window):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self.lock = Lock()

    def acquire(self):
        with self.lock:
            now = datetime.now()
            # Remove old requests
            while self.requests and (now - self.requests[0]) > self.time_window:
                self.requests.popleft()
            
            if len(self.requests) >= self.max_requests:
                # Calculate sleep time
                sleep_time = (self.requests[0] + self.time_window - now).total_seconds()
                if sleep_time > 0:
                    time.sleep(sleep_time)
                # Clean up again after sleep
                now = datetime.now()
                while self.requests and (now - self.requests[0]) > self.time_window:
                    self.requests.popleft()
            
            self.requests.append(now)
            return True

# Create rate limiters for different APIs
alienvault_limiter = RateLimiter(max_requests=4, time_window=timedelta(seconds=1))  # 4 requests per second
vpnapi_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))     # 2 requests per second
abuseipdb_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))  # 2 requests per second
ipinfo_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))     # 2 requests per second

if __name__ == '__main__':
    try:
        # Get port from environment variable or default to 5000
        port = int(os.getenv('PORT', '5000'))
        
        # Open browser after a 1.5 second delay to ensure server is running
        Timer(1.5, open_browser).start()
        logger.info(f"Starting Flask application on port {port}")
        app.run(debug=False, host='0.0.0.0', port=port)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        raise 