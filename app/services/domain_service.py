import os
import socket
import ssl
import dns.resolver
import whois
import logging
import requests
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logger = logging.getLogger(__name__)

def setup_domain_services(app):
    """Setup domain-related services."""
    pass  # Add any necessary setup code here

def get_whois_info(domain):
    """Fetch WHOIS information for a domain using IP2Location API."""
    try:
        ip2whois_key = os.getenv('IP2WHOIS_KEY', '***REMOVED***')
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

def get_domain_info(domain):
    """Get comprehensive domain information in parallel."""
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