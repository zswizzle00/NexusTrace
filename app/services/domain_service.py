import os
import socket
import ssl
import dns.resolver
import whois
import logging
import requests
from concurrent.futures import ThreadPoolExecutor
import json
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
from datetime import timedelta
from ..utils.rate_limiter import RateLimiter

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiters
ip2whois_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))

def setup_domain_services(app):
    """Setup domain-related services."""
    pass  # Add any necessary setup code here

def get_whois_info(domain):
    """Fetch WHOIS information for a domain using IP2Location API."""
    try:
        ip2whois_key = os.getenv('IP2WHOIS_KEY')
        if not ip2whois_key:
            logger.warning("IP2WHOIS_KEY not configured")
            return None
        ip2whois_limiter.acquire()
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

def get_reverse_ip_domains(ip):
    """Get domains sharing the same IP using hackertarget.com (free endpoint)."""
    try:
        resp = requests.get(f'https://api.hackertarget.com/reverseiplookup/?q={ip}', timeout=10)
        if resp.status_code == 200 and 'No records' not in resp.text:
            return resp.text.splitlines()
    except Exception as e:
        logger.error(f"Error in reverse IP lookup: {str(e)}")
    return []

def get_subdomains_crtsh(domain):
    """Get subdomains from crt.sh (certificate transparency logs)."""
    try:
        resp = requests.get(f'https://crt.sh/?q=%25.{domain}&output=json', timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data:
                name = entry.get('name_value')
                if name:
                    for sub in name.split('\n'):
                        if sub.endswith(domain):
                            subdomains.add(sub.strip())
            return sorted(subdomains)
    except Exception as e:
        logger.error(f"Error in crt.sh subdomain lookup: {str(e)}")
    return []

def parse_spf_dkim_dmarc(txt_records):
    spf = [r for r in txt_records if r.startswith('v=spf1')]
    dkim = [r for r in txt_records if 'dkim' in r.lower()]
    dmarc = [r for r in txt_records if r.startswith('v=DMARC1')]
    return {'spf': spf, 'dkim': dkim, 'dmarc': dmarc}

def extract_domain_for_phishtank(indicator):
    # If it's a URL, extract the domain; if it's an IP, return None; else, return as is
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
    domain = extract_domain_for_phishtank(indicator)
    if domain:
        return f'https://phishtank.org/search.php?valid=y&active=y&Search={domain}'
    return None

def get_mxtoolbox_email_security(domain):
    """Fetch DMARC, DKIM, SPF, and other info from MXToolbox (scrape or API)."""
    api_key = os.getenv('MXTOOLBOX_API_KEY')
    results = {'spf': None, 'dmarc': None, 'dkim': None, 'raw': {}}
    if api_key:
        # Paid API usage
        try:
            headers = {'Authorization': f'Bearer {api_key}'}
            for record in ['spf', 'dmarc', 'dkim']:
                resp = requests.get(f'https://api.mxtoolbox.com/api/v1/lookup/{record}/{domain}', headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    results[record] = data.get('Information', '')
                    results['raw'][record] = data
        except Exception as e:
            logger.error(f"MXToolbox API error: {str(e)}")
    else:
        # Scrape public web interface (rate-limited, for demo only)
        try:
            for record in ['spf', 'dmarc', 'dkim']:
                url = f'https://mxtoolbox.com/SuperTool.aspx?action={record}%3a{domain}'
                resp = requests.get(url, timeout=10)
                soup = BeautifulSoup(resp.text, 'html.parser')
                result_div = soup.find('div', {'id': 'ctl00_ContentPlaceHolder1_lblToolOutput'})
                if result_div:
                    results[record] = result_div.get_text(strip=True)
                results['raw'][record] = result_div.get_text(strip=True) if result_div else None
        except Exception as e:
            logger.error(f"MXToolbox scrape error: {str(e)}")
    return results

def get_talos_reputation(domain):
    """Fetch Cisco Talos reputation and web category for a domain or IP."""
    url = f'https://talosintelligence.com/reputation_center/lookup?search={domain}'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36',
        'Referer': 'https://talosintelligence.com/'
    }
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        verdict = None
        category = None
        # Reputation verdict
        rep_div = soup.find('div', class_='reputation-score')
        if rep_div:
            verdict = rep_div.get_text(strip=True)
        # Web category
        cat_div = soup.find('div', class_='category')
        if cat_div:
            category = cat_div.get_text(strip=True)
        return {
            'verdict': verdict,
            'category': category,
            'talos_url': url
        }
    except Exception as e:
        logger.error(f"Talos reputation error: {str(e)}")
        return None

def get_domain_info(domain):
    """Get comprehensive domain information in parallel, with extra enrichment."""
    try:
        with ThreadPoolExecutor() as executor:
            whois_future = executor.submit(whois.whois, domain)
            dns_future = executor.submit(get_dns_records, domain)
            ssl_future = executor.submit(get_ssl_info, domain)

            whois_info = whois_future.result()
            dns_records = dns_future.result()
            ssl_info = ssl_future.result()

        # Get IP address
        try:
            ip_address = socket.gethostbyname(domain)
        except:
            ip_address = None

        # Reverse IP lookup
        reverse_domains = get_reverse_ip_domains(ip_address) if ip_address else []
        # Subdomain enumeration
        subdomains = get_subdomains_crtsh(domain)
        # SPF/DKIM/DMARC
        txt_records = dns_records.get('TXT', [])
        email_security = parse_spf_dkim_dmarc(txt_records)
        # Blacklist/PhishTank
        phishtank_url = check_phishtank(domain)
        # MXToolbox enrichment
        mxtoolbox_email_security = get_mxtoolbox_email_security(domain)
        # Talos reputation
        talos_reputation = get_talos_reputation(domain)

        return {
            'domain': domain,
            'whois': whois_info,
            'dns_records': dns_records,
            'ssl_info': ssl_info,
            'ip_address': ip_address,
            'reverse_domains': reverse_domains,
            'subdomains': subdomains,
            'email_security': email_security,
            'phishtank_url': phishtank_url,
            'mxtoolbox_email_security': mxtoolbox_email_security,
            'talos_reputation': talos_reputation
        }
    except Exception as e:
        logger.error(f"Error getting domain information: {str(e)}")
        return None 