from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory
import re
from app.services.file_service import get_intezer_analysis
from app.services.hash_service import get_hash_info
from app.services.ip_service import get_ipinfo_data, get_shodan_info, check_abuseipdb, get_vpn_data, get_proxycheck_data, get_alienvault_data, get_ip2location_data
from app.services.domain_service import get_domain_info, get_whois_info
from app.services.url_service import analyze_url
from app.services.user_agent_service import parse_user_agent
import os
import requests
from dotenv import load_dotenv
from app.services.event_service import get_event_info
from urllib.parse import urlparse
import socket

# Load environment variables
load_dotenv()

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def home():
    return render_template('home.html')

@home_bp.route('/ip')
def ip_section():
    return render_template('ip_section.html')

@home_bp.route('/domain')
def domain_section():
    return render_template('domain_section.html')

@home_bp.route('/ip_search', methods=['GET', 'POST'])
def ip_search():
    error = None
    result = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not ip:
            error = 'IP address is required.'
        else:
            # For demo, just echo the IP. Replace with real lookup as needed.
            result = {'ip': ip, 'message': f'Search results for {ip} would appear here.'}
    return render_template('ip_search.html', error=error, result=result)

@home_bp.route('/domain_search', methods=['GET', 'POST'])
def domain_search():
    error = None
    result = None
    if request.method == 'POST':
        indicator = request.form.get('indicator', '').strip()
        if not indicator:
            error = 'Domain or URL is required.'
        else:
            # Redirect to the appropriate analysis endpoint
            if indicator.lower().startswith(('http://', 'https://')):
                return redirect(url_for('domain.analyze_domain', indicator=indicator))
            else:
                return redirect(url_for('domain.analyze_domain', indicator=indicator))
    return render_template('domain_search.html', error=error, result=result)

@home_bp.route('/hash_analysis', methods=['GET'])
def hash_analysis_form():
    return render_template('hash_analysis.html')

@home_bp.route('/health')
def health_check():
    return {'status': 'healthy'}, 200

def parse_alienvault_otx(raw_data):
    if not raw_data or not isinstance(raw_data, dict):
        return None
    general = raw_data.get('general', {})
    if not general:
        return None
    pulse_info = general.get('pulse_info', {})
    summary = {
        'indicator': general.get('indicator', 'N/A'),
        'reputation': general.get('reputation', 'N/A'),
        'pulse_count': pulse_info.get('count', 0),
        'tags': ', '.join(pulse_info.get('tags', [])),
    }
    pulses = []
    for pulse in pulse_info.get('pulses', []):
        pulses.append({
            'name': pulse.get('name'),
            'author': pulse.get('author', {}).get('username', 'N/A'),
            'created': pulse.get('created', '')[:10],
            'tags': ', '.join(pulse.get('tags', [])),
            'link': f"https://otx.alienvault.com/pulse/{pulse.get('id')}"
        })
    tables = {}
    if pulses:
        tables['pulses'] = pulses
    related = []
    for rel in pulse_info.get('related', {}).get('indicators', []):
        related.append({'indicator': rel.get('indicator')})
    if related:
        tables['related_indicators'] = related
    return {
        'summary': summary,
        'tables': tables,
        'raw': raw_data
    }

def parse_shodan(shodan_data):
    if not shodan_data or not isinstance(shodan_data, dict):
        return None
    summary = {
        'ip': shodan_data.get('ip'),
        'organization': shodan_data.get('organization'),
        'operating_system': shodan_data.get('operating_system'),
        'hostnames': ', '.join(shodan_data.get('hostnames', [])),
        'country': shodan_data.get('country_name'),
        'city': shodan_data.get('city'),
        'isp': shodan_data.get('isp'),
        'last_update': shodan_data.get('last_update'),
    }
    tables = {}
    if shodan_data.get('ports'):
        tables['open_ports'] = shodan_data['ports']
    if shodan_data.get('vulnerabilities'):
        tables['vulnerabilities'] = shodan_data['vulnerabilities']
    return {
        'summary': summary,
        'tables': tables,
        'raw': shodan_data
    }

def parse_abuseipdb(abuse_data):
    if not abuse_data or not isinstance(abuse_data, dict):
        return None
    summary = {
        'risk_score': abuse_data.get('abuse_confidence_score'),
        'total_reports': abuse_data.get('total_reports'),
        'last_reported': abuse_data.get('last_reported'),
        'country': abuse_data.get('country_name'),
        'isp': abuse_data.get('isp'),
        'domain': abuse_data.get('domain'),
    }
    tables = {}
    if abuse_data.get('reports'):
        tables['reports'] = abuse_data['reports']
    return {
        'summary': summary,
        'tables': tables,
        'raw': abuse_data
    }

def is_valid_ip(ip):
    """Check if the string is a valid IPv4 or IPv6 address."""
    try:
        # Try IPv4 first
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            # Try IPv6 if IPv4 fails
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

@home_bp.route('/analyze', methods=['POST'])
def analyze():
    indicator = request.form.get('indicator', '').strip()
    if not indicator:
        flash('Please enter an indicator to analyze.', 'error')
        return redirect(url_for('home.home'))

    # Initialize result_data and card_count
    result_data = {}
    card_count = 0

    # Determine indicator type
    indicator_type = None
    
    # Check for IP address (both IPv4 and IPv6)
    if is_valid_ip(indicator):
        indicator_type = 'ip'
    # Check for domain
    elif re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', indicator):
        indicator_type = 'domain'
    # Check for URL
    elif re.match(r'^https?://', indicator):
        indicator_type = 'url'
    # Check for hash
    elif re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', indicator):
        indicator_type = 'hash'
    # Check for event ID
    elif re.match(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', indicator):
        indicator_type = 'event'
    # Check for AD code (assuming it's a numeric code)
    elif re.match(r'^\d+$', indicator):
        indicator_type = 'ad_code'
    # Default to user agent if no other type matches
    else:
        print(f"[DEBUG] Treating as User Agent: {indicator}")
        try:
            result_data['user_agent'] = parse_user_agent(indicator)
            indicator_type = 'user_agent'
        except Exception as e:
            print(f"[DEBUG] User Agent parsing error: {e}")
            result_data['user_agent_error'] = f"User Agent analysis failed: {str(e)}"
            indicator_type = 'user_agent'

    print(f"[DEBUG] indicator_type: {indicator_type}")
    print(f"[DEBUG] result_data: {result_data}")

    if indicator_type == 'hash':
        intezer_result = get_intezer_analysis(file_hash=indicator)
        result_data['intezer_result'] = intezer_result if intezer_result else None
        hash_info = get_hash_info(indicator)
        result_data['hash_info'] = hash_info if hash_info else None
        alienvault_raw = get_alienvault_data(indicator)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None
        # If all are None, set an error
        if not any([result_data['intezer_result'], result_data['hash_info'], result_data['alienvault']]):
            result_data['hash_error'] = 'No hash analysis results found.'
        card_count = sum(1 for k in ['intezer_result', 'alienvault', 'hash_info'] if result_data.get(k))
        return render_template('hash_analysis.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type == 'user_agent':
        return render_template('user_agent_analysis.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              **result_data)
    elif indicator_type == 'event':
        return render_template('event_analysis.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              **result_data)
    elif indicator_type == 'ad_code':
        # Get event information for the AD code
        event_info = get_event_info(indicator)
        result_data['event_info'] = event_info if event_info else None
        if not result_data['event_info']:
            result_data['ad_error'] = 'No AD code analysis results found.'
        return render_template('event_analysis.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              **result_data)
    elif indicator_type == 'ip':
        result_data['ipinfo'] = get_ipinfo_data(indicator) or None
        result_data['ip2location'] = get_ip2location_data(indicator) or None
        result_data['vpnapi'] = get_vpn_data(indicator) or None
        result_data['proxycheck'] = get_proxycheck_data(indicator) or None
        shodan_raw = get_shodan_info(indicator)
        result_data['shodan'] = parse_shodan(shodan_raw) if shodan_raw else None
        abuseipdb_raw = check_abuseipdb(indicator)
        result_data['abuseipdb'] = parse_abuseipdb(abuseipdb_raw) if abuseipdb_raw else None
        alienvault_raw = get_alienvault_data(indicator)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None
        # If all are None, set an error
        if not any([result_data['ipinfo'], result_data['ip2location'], result_data['vpnapi'], result_data['proxycheck'], result_data['shodan'], result_data['abuseipdb'], result_data['alienvault']]):
            result_data['ip_error'] = 'No IP analysis results found.'
        card_count = sum(1 for k in ['ipinfo', 'ip2location', 'vpnapi', 'proxycheck', 'shodan', 'abuseipdb', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type == 'url':
        # Get URL analysis
        url_analysis = analyze_url(indicator)
        result_data['url_analysis'] = url_analysis['url_analysis'] if url_analysis and 'url_analysis' in url_analysis else None
        # Extract domain from URL for additional analysis
        domain = urlparse(indicator).netloc
        # Get domain information
        domain_info = get_domain_info(domain)
        result_data['domain_info'] = domain_info if domain_info else None
        # Get WHOIS information
        whois_info = get_whois_info(domain)
        result_data['whois_info'] = whois_info if whois_info else None
        # Get AlienVault OTX information
        alienvault_raw = get_alienvault_data(domain)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None
        # If all are None, set an error
        if not any([result_data['url_analysis'], result_data['domain_info'], result_data['whois_info'], result_data['alienvault']]):
            result_data['url_error'] = 'No URL analysis results found.'
        card_count = sum(1 for k in ['url_analysis', 'domain_info', 'whois_info', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type == 'domain':
        # First try to analyze as URL
        normalized_url = f'https://{indicator}'
        url_analysis = analyze_url(normalized_url)
        result_data['url_analysis'] = url_analysis['url_analysis'] if url_analysis and 'url_analysis' in url_analysis else None
        
        # Get domain information
        domain_info = get_domain_info(indicator)
        result_data['domain_info'] = domain_info if domain_info else None
        # Get WHOIS information
        whois_info = get_whois_info(indicator)
        result_data['whois_info'] = whois_info if whois_info else None
        # Get AlienVault OTX information
        alienvault_raw = get_alienvault_data(indicator)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None
        # If all are None, set an error
        if not any([result_data['url_analysis'], result_data['domain_info'], result_data['whois_info'], result_data['alienvault']]):
            result_data['domain_error'] = 'No domain analysis results found.'
        card_count = sum(1 for k in ['url_analysis', 'domain_info', 'whois_info', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)

@home_bp.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon') 