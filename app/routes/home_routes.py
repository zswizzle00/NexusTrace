from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory
import re
import logging
from app.services.file_service import get_intezer_analysis

logger = logging.getLogger(__name__)
from app.services.hash_service import get_hash_info_quick, get_hash_info_deep
from app.services.ip_service import get_ipinfo_data, get_shodan_info, check_abuseipdb, get_vpn_data, get_proxycheck_data, get_alienvault_data, get_ip2location_data
from app.services.domain_service import get_domain_info, get_domain_info_quick
from app.services.url_service import analyze_url_quick, analyze_url_deep
from app.services.user_agent_service import parse_user_agent
from app.services.azure_error_service import get_azure_error_info
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
    # Check for Azure error code (AADSTS + numbers, or just numbers that could be Azure codes)
    elif re.match(r'^AADSTS\d+$', indicator, re.IGNORECASE) or (re.match(r'^\d+$', indicator) and len(indicator) >= 5):
        indicator_type = 'azure_error'
    # Check for AD code (assuming it's a numeric code)
    elif re.match(r'^\d+$', indicator):
        indicator_type = 'ad_code'
    # Default to user agent if no other type matches
    else:
        logger.debug(f"Treating as User Agent: {indicator}")
        try:
            result_data['user_agent'] = parse_user_agent(indicator)
            indicator_type = 'user_agent'
        except ValueError as e:
            logger.debug(f"User Agent parsing error: {e}")
            result_data['user_agent_error'] = f"User Agent analysis failed: {str(e)}"
            indicator_type = 'user_agent'

    logger.debug(f"indicator_type: {indicator_type}")

    if indicator_type == 'hash':
        # Quick scan by default - fast response with VT, MalwareBazaar, ThreatFox
        hash_info = get_hash_info_quick(indicator)
        result_data['hash_info'] = hash_info if hash_info and not hash_info.get('error') else None
        alienvault_raw = get_alienvault_data(indicator)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        # Check if we got meaningful hash analysis results
        has_meaningful_data = (
            (hash_info and hash_info.get('summary', {}).get('is_malicious')) or
            (hash_info and hash_info.get('sources', {}).get('virustotal', {}).get('status') == 'found') or
            (hash_info and hash_info.get('sources', {}).get('malwarebazaar', {}).get('status') == 'found') or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
        )

        # If no meaningful data found, redirect to no results page
        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='hash')

        card_count = sum(1 for k in ['alienvault', 'hash_info'] if result_data.get(k))
        return render_template('hash_analysis.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type == 'user_agent':
        if not result_data.get('user_agent') and result_data.get('user_agent_error'):
            return render_template('no_results.html', indicator=indicator, error_type='user_agent')
        
        # Check if we got meaningful user agent information (not just "Unknown" values)
        user_agent = result_data.get('user_agent')
        has_meaningful_data = (
            user_agent and 
            user_agent.get('browser', {}).get('name') != 'Unknown' and
            user_agent.get('os', {}).get('name') != 'Unknown'
        )
        
        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='user_agent')
        
        return render_template('user_agent_analysis.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              **result_data)
    elif indicator_type == 'event':
        return render_template('event_analysis.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              **result_data)
    elif indicator_type == 'azure_error':
        # Get Azure error information
        azure_error_info = get_azure_error_info(indicator)
        result_data['azure_error_info'] = azure_error_info if azure_error_info else None
        
        # Check if we got meaningful error information (not just generic/error responses)
        has_meaningful_data = (
            azure_error_info and 
            azure_error_info.get('description') and 
            not azure_error_info.get('description', '').startswith('No specific information found for error code') and
            not azure_error_info.get('description', '').startswith('Unable to fetch error information:') and
            not azure_error_info.get('description', '').startswith('Error processing request:')
        )
        
        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='azure_error')
        
        return render_template('azure_error_analysis.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              **result_data)
    elif indicator_type == 'ad_code':
        # Get event information for the AD code
        event_info = get_event_info(indicator)
        result_data['event_info'] = event_info if event_info else None
        
        # Check if we got meaningful event information (not just empty data)
        has_meaningful_data = (
            event_info and 
            event_info.get('title') and 
            event_info.get('summary') and 
            not event_info.get('summary', '').startswith('Error fetching event information:')
        )
        
        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='event')
        
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
        
        # Check if we got meaningful IP analysis results
        has_meaningful_data = (
            (result_data['ipinfo'] and result_data['ipinfo'].get('ipinfo', {}).get('city')) or
            (result_data['vpnapi'] and result_data['vpnapi'].get('location', {}).get('city')) or
            (result_data['shodan'] and result_data['shodan'].get('summary', {}).get('organization')) or
            (result_data['abuseipdb'] and result_data['abuseipdb'].get('summary', {}).get('risk_score') is not None) or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
        )
        
        # If no meaningful data found, redirect to no results page
        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='ip')
        
        card_count = sum(1 for k in ['ipinfo', 'ip2location', 'vpnapi', 'proxycheck', 'shodan', 'abuseipdb', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type == 'url':
        # Get URL analysis (quick mode by default)
        url_analysis = analyze_url_quick(indicator)
        result_data['url_analysis'] = url_analysis['url_analysis'] if url_analysis and 'url_analysis' in url_analysis else None
        # Extract domain from URL for additional analysis
        domain = urlparse(indicator).netloc
        # Get domain information (includes WHOIS)
        domain_info = get_domain_info(domain)
        result_data['domain_info'] = domain_info if domain_info else None
        # Extract WHOIS from domain_info for template compatibility
        result_data['whois_info'] = domain_info.get('whois') if domain_info else None
        # Get AlienVault OTX information
        alienvault_raw = get_alienvault_data(domain)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        # Check if we got meaningful URL analysis results
        has_meaningful_data = (
            (result_data['url_analysis'] and result_data['url_analysis'].get('status_code') is not None) or
            (result_data['domain_info'] and result_data['domain_info'].get('ssl_info')) or
            (result_data['whois_info'] and result_data['whois_info'].get('domain')) or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
        )

        # If no meaningful data found, redirect to no results page
        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='url')

        card_count = sum(1 for k in ['url_analysis', 'domain_info', 'whois_info', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type == 'domain':
        # First try to analyze as URL (quick mode)
        normalized_url = f'https://{indicator}'
        url_analysis = analyze_url_quick(normalized_url)
        result_data['url_analysis'] = url_analysis['url_analysis'] if url_analysis and 'url_analysis' in url_analysis else None

        # Get domain information (includes WHOIS)
        domain_info = get_domain_info(indicator)
        result_data['domain_info'] = domain_info if domain_info else None
        # Extract WHOIS from domain_info for template compatibility
        result_data['whois_info'] = domain_info.get('whois') if domain_info else None
        # Get AlienVault OTX information
        alienvault_raw = get_alienvault_data(indicator)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        # Check if we got meaningful domain analysis results
        has_meaningful_data = (
            (result_data['url_analysis'] and result_data['url_analysis'].get('status_code') is not None) or
            (result_data['domain_info'] and result_data['domain_info'].get('ssl_info')) or
            (result_data['whois_info'] and result_data['whois_info'].get('domain')) or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
        )

        # If no meaningful data found, redirect to no results page
        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='domain')

        card_count = sum(1 for k in ['url_analysis', 'domain_info', 'whois_info', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)

@home_bp.route('/no_results')
def no_results():
    """Route for displaying no results page when accessed directly."""
    indicator = request.args.get('indicator', 'Unknown Indicator')
    error_type = request.args.get('error_type', None)
    return render_template('no_results.html', indicator=indicator, error_type=error_type)

@home_bp.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon') 