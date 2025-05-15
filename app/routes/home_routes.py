from flask import Blueprint, render_template, request, redirect, url_for, flash
import re
from app.services.file_service import get_intezer_analysis
from app.services.ip_service import get_ipinfo_data, get_shodan_info, check_abuseipdb, get_vpn_data, get_proxycheck_data, get_alienvault_data, get_ip2location_data
from app.services.domain_service import get_domain_info, get_whois_info
from app.services.url_service import analyze_url

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
    else:
        indicator_type = None

    if indicator_type == 'hash':
        result_data['intezer_result'] = get_intezer_analysis(file_hash=indicator)
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
        result_data['url_analysis'] = analyze_url(indicator)

    return render_template('analyze_result.html', indicator=indicator, hash_type=hash_type, indicator_type=indicator_type, **result_data) 