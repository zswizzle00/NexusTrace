from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory
import re
from app.services.file_service import get_intezer_analysis
from app.services.hash_service import get_hash_info
from app.services.ip_service import get_ipinfo_data, get_shodan_info, check_abuseipdb, get_vpn_data, get_proxycheck_data, get_alienvault_data, get_ip2location_data
from app.services.domain_service import get_domain_info, get_whois_info
from app.services.url_service import analyze_url
import os
import requests
from dotenv import load_dotenv

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

@home_bp.route('/url')
def url_section():
    return render_template('url_section.html')

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
        domain = request.form.get('domain', '').strip()
        if not domain:
            error = 'Domain or URL is required.'
        else:
            # For demo, just echo the domain. Replace with real lookup as needed.
            result = {'domain': domain, 'message': f'Search results for {domain} would appear here.'}
    return render_template('domain_search.html', error=error, result=result)

@home_bp.route('/hash_analysis', methods=['GET'])
def hash_analysis_form():
    return render_template('hash_analysis.html')

def parse_alienvault_otx(raw_data):
    if not raw_data or not isinstance(raw_data, dict):
        return None
    general = raw_data.get('general', {})
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

# Unified analyze endpoint
@home_bp.route('/analyze', methods=['POST'])
def analyze():
    indicator = request.form.get('indicator', '').strip()
    # Simple regexes for hash detection
    md5_re = re.compile(r'^[a-fA-F0-9]{32}$')
    sha1_re = re.compile(r'^[a-fA-F0-9]{40}$')
    sha256_re = re.compile(r'^[a-fA-F0-9]{64}$')
    ip_re = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    domain_re = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,})$')
    url_re = re.compile(r'^(https?://)?([\da-z.-]+)\.([a-z.]{2,6})([/\w .-]*)*/?$')
    event_id_re = re.compile(r'^\d{1,5}$')  # Windows Event IDs are typically 1-5 digits

    hash_type = None
    indicator_type = None
    result_data = {}

    if md5_re.match(indicator):
        hash_type = 'MD5'
        indicator_type = 'hash'
    elif sha1_re.match(indicator):
        hash_type = 'SHA1'
        indicator_type = 'hash'
    elif sha256_re.match(indicator):
        hash_type = 'SHA256'
        indicator_type = 'hash'
    elif ip_re.match(indicator):
        indicator_type = 'ip'
    elif url_re.match(indicator):
        indicator_type = 'url'
    elif domain_re.match(indicator):
        indicator_type = 'domain'
    elif event_id_re.match(indicator):
        indicator_type = 'event'
        try:
            from app.services.event_service import get_event_info
            event_info = get_event_info(indicator)
            if event_info:
                result_data['event_info'] = event_info
            else:
                result_data['event_error'] = "Could not find information for this Event ID"
        except Exception as e:
            result_data['event_error'] = f"Error analyzing Event ID: {str(e)}"
    else:
        print(f"[DEBUG] Treating as User Agent: {indicator}")
        api_key = os.getenv('APILAYER_API_KEY')
        if api_key:
            url = "https://api.apilayer.com/user_agent/parse"
            headers = {"apikey": api_key}
            params = {"ua": indicator}
            try:
                response = requests.get(url, headers=headers, params=params)
                print(f"[DEBUG] User Agent API status code: {response.status_code}")
                print(f"[DEBUG] User Agent API response text: {response.text}")
                response.raise_for_status()
                results = response.json()
                print(f"[DEBUG] User Agent API response: {results}")
                formatted_results = {
                    'browser': {
                        'name': results.get('browser', {}).get('name', 'Unknown'),
                        'version': results.get('browser', {}).get('version', 'Unknown')
                    },
                    'os': {
                        'name': results.get('os', {}).get('name', 'Unknown'),
                        'version': results.get('os', {}).get('version', 'Unknown')
                    },
                    'device': {
                        'type': results.get('device', {}).get('type', 'Unknown'),
                        'brand': results.get('device', {}).get('brand', 'Unknown'),
                        'model': results.get('device', {}).get('model', 'Unknown')
                    },
                    'is_mobile': results.get('is_mobile', False),
                    'is_tablet': results.get('is_tablet', False),
                    'is_desktop': results.get('is_desktop', False)
                }
                result_data['user_agent'] = formatted_results
                indicator_type = 'user_agent'
            except Exception as e:
                print(f"[DEBUG] User Agent API error: {e}")
                result_data['user_agent_error'] = f"User Agent analysis failed: {str(e)}"
                indicator_type = 'user_agent'
        else:
            print("[DEBUG] User Agent API key not configured.")
            result_data['user_agent_error'] = "User Agent API key not configured."
            indicator_type = 'user_agent'
    print(f"[DEBUG] indicator_type: {indicator_type}")
    print(f"[DEBUG] result_data: {result_data}")

    if indicator_type == 'hash':
        intezer_result = get_intezer_analysis(file_hash=indicator)
        if intezer_result:
            result_data['intezer_result'] = intezer_result
        else:
            result_data['hash_info'] = get_hash_info(indicator)
    elif indicator_type == 'ip':
        result_data['ipinfo'] = get_ipinfo_data(indicator)
        result_data['ip2location'] = get_ip2location_data(indicator)
        result_data['vpnapi'] = get_vpn_data(indicator)
        result_data['proxycheck'] = get_proxycheck_data(indicator)
        shodan_raw = get_shodan_info(indicator)
        result_data['shodan'] = parse_shodan(shodan_raw)
        abuseipdb_raw = check_abuseipdb(indicator)
        result_data['abuseipdb'] = parse_abuseipdb(abuseipdb_raw)
        alienvault_raw = get_alienvault_data(indicator)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw)
    elif indicator_type == 'domain':
        result_data['domain_info'] = get_domain_info(indicator)
        result_data['whois'] = get_whois_info(indicator)
        if result_data['domain_info'] and result_data['domain_info'].get('ip_address'):
            ip = result_data['domain_info']['ip_address']
            result_data['ipinfo'] = get_ipinfo_data(ip)
            result_data['ip2location'] = get_ip2location_data(ip)
    elif indicator_type == 'url':
        # Normalize URL: prepend https:// if no scheme is present
        if not indicator.lower().startswith(('http://', 'https://')):
            indicator = f'https://{indicator}'
        result_data['url_analysis'] = analyze_url(indicator)

    return render_template('analyze_result.html', indicator=indicator, hash_type=hash_type, indicator_type=indicator_type, **result_data)

# Serve favicon.ico at the root
@home_bp.route('/favicon.ico')
def favicon():
    abs_path = os.path.abspath(os.path.join('static', 'favicon_io'))
    print(f"[DEBUG] Favicon absolute path: {abs_path}")
    return send_from_directory(
        abs_path,
        'favicon.ico',
        mimetype='image/vnd.microsoft.icon'
    ) 