from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)
from app.services.hash_service import get_hash_info_quick, get_hash_info_deep
from app.services.ip_service import get_ipinfo_data, get_shodan_info, check_abuseipdb, get_vpn_data, get_proxycheck_data, get_alienvault_data, get_ip2location_data, get_ipapi_data
from app.services.domain_service import get_domain_info, get_domain_info_quick
from app.services.url_service import analyze_url_quick, analyze_url_deep
from app.services.user_agent_service import parse_user_agent
from app.services.azure_error_service import get_azure_error_info
import os
import requests
from dotenv import load_dotenv
from app.services.event_service import get_event_info
from urllib.parse import urlparse
from app.utils.validators import is_valid_ip, is_valid_domain

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
        'distinct_users': abuse_data.get('distinct_users'),
        'last_reported': abuse_data.get('last_reported'),
        'country': abuse_data.get('country_name'),
        'isp': abuse_data.get('isp'),
        'domain': abuse_data.get('domain'),
        'usage_type': abuse_data.get('usage_type'),
        'is_whitelisted': abuse_data.get('is_whitelisted'),
    }
    tables = {}
    if abuse_data.get('reports'):
        tables['reports'] = abuse_data['reports']
    return {
        'summary': summary,
        'tables': tables,
        'raw': abuse_data
    }

def _run_analysis(indicator):
    """Core analysis logic shared by the POST /analyze form and GET /i/<indicator> deep-link route."""
    result_data = {}
    card_count = 0

    # Determine indicator type
    indicator_type = None

    normalized_ip = is_valid_ip(indicator)
    if normalized_ip:
        indicator = normalized_ip  # use normalized form for all downstream calls and cache keys
        indicator_type = 'ip'
    elif is_valid_domain(indicator):
        indicator_type = 'domain'
    elif re.match(r'^https?://', indicator):
        indicator_type = 'url'
    elif re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', indicator):
        indicator_type = 'hash'
    elif re.match(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', indicator):
        indicator_type = 'event'
    elif re.match(r'^AADSTS\d+$', indicator, re.IGNORECASE) or (re.match(r'^\d+$', indicator) and len(indicator) >= 5):
        indicator_type = 'azure_error'
    elif re.match(r'^\d+$', indicator):
        indicator_type = 'ad_code'
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
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(get_hash_info_quick, indicator): 'hash_info',
                executor.submit(get_alienvault_data, indicator): 'alienvault_raw',
            }
            raw = {}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    raw[key] = future.result()
                except Exception as e:
                    logger.warning(f"Hash lookup {key} failed: {e}")
                    raw[key] = None
        hash_info = raw.get('hash_info')
        result_data['hash_info'] = hash_info if hash_info and not hash_info.get('error') else None
        alienvault_raw = raw.get('alienvault_raw')
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        has_meaningful_data = (
            (hash_info and hash_info.get('summary', {}).get('is_malicious')) or
            (hash_info and hash_info.get('sources', {}).get('virustotal', {}).get('status') == 'found') or
            (hash_info and hash_info.get('sources', {}).get('malwarebazaar', {}).get('status') == 'found') or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
        )

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
        azure_error_info = get_azure_error_info(indicator)
        result_data['azure_error_info'] = azure_error_info if azure_error_info else None

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
        event_info = get_event_info(indicator)
        result_data['event_info'] = event_info if event_info else None

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
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {
                executor.submit(get_ipinfo_data, indicator): 'ipinfo',
                executor.submit(get_ip2location_data, indicator): 'ip2location',
                executor.submit(get_vpn_data, indicator): 'vpnapi',
                executor.submit(get_proxycheck_data, indicator): 'proxycheck',
                executor.submit(get_ipapi_data, indicator): 'ipapi',
                executor.submit(get_shodan_info, indicator): 'shodan_raw',
                executor.submit(check_abuseipdb, indicator): 'abuseipdb_raw',
                executor.submit(get_alienvault_data, indicator): 'alienvault_raw',
            }
            raw = {}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    raw[key] = future.result()
                except Exception as e:
                    logger.warning(f"IP lookup {key} failed: {e}")
                    raw[key] = None
        result_data['ipinfo'] = raw.get('ipinfo') or None
        result_data['ip2location'] = raw.get('ip2location') or None
        result_data['vpnapi'] = raw.get('vpnapi') or None
        result_data['proxycheck'] = raw.get('proxycheck') or None
        result_data['ipapi'] = raw.get('ipapi') or None
        shodan_raw = raw.get('shodan_raw')
        result_data['shodan'] = parse_shodan(shodan_raw) if shodan_raw else None
        abuseipdb_raw = raw.get('abuseipdb_raw')
        result_data['abuseipdb'] = parse_abuseipdb(abuseipdb_raw) if abuseipdb_raw else None
        alienvault_raw = raw.get('alienvault_raw')
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        has_meaningful_data = (
            (result_data['ipinfo'] and (result_data['ipinfo'].get('country') or result_data['ipinfo'].get('asn'))) or
            (result_data['ipapi'] and result_data['ipapi'].get('country')) or
            (result_data['vpnapi'] and result_data['vpnapi'].get('location', {}).get('city')) or
            (result_data['shodan'] and result_data['shodan'].get('summary', {}).get('organization')) or
            (result_data['abuseipdb'] and result_data['abuseipdb'].get('summary', {}).get('risk_score') is not None) or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
        )

        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='ip')

        card_count = sum(1 for k in ['ipinfo', 'ip2location', 'ipapi', 'vpnapi', 'proxycheck', 'shodan', 'abuseipdb', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type == 'url':
        domain = urlparse(indicator).netloc
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(analyze_url_quick, indicator): 'url_result',
                executor.submit(get_domain_info, domain): 'domain_info',
                executor.submit(get_alienvault_data, domain): 'alienvault_raw',
            }
            raw = {}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    raw[key] = future.result()
                except Exception as e:
                    logger.warning(f"URL lookup {key} failed: {e}")
                    raw[key] = None
        url_result = raw.get('url_result') or {}
        result_data['url_analysis'] = url_result.get('url_analysis') if url_result else None
        domain_info = raw.get('domain_info')
        result_data['domain_info'] = domain_info if domain_info else None
        result_data['whois_info'] = domain_info.get('whois') if domain_info else None
        alienvault_raw = raw.get('alienvault_raw')
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        has_meaningful_data = (
            (result_data['url_analysis'] and result_data['url_analysis'].get('status_code') is not None) or
            (result_data['domain_info'] and result_data['domain_info'].get('ssl_info')) or
            (result_data['whois_info'] and result_data['whois_info'].get('domain')) or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
        )

        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='url')

        card_count = sum(1 for k in ['url_analysis', 'domain_info', 'whois_info', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type == 'domain':
        normalized_url = f'https://{indicator}'
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(analyze_url_quick, normalized_url): 'url_result',
                executor.submit(get_domain_info, indicator): 'domain_info',
                executor.submit(get_alienvault_data, indicator): 'alienvault_raw',
            }
            raw = {}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    raw[key] = future.result()
                except Exception as e:
                    logger.warning(f"Domain lookup {key} failed: {e}")
                    raw[key] = None
        url_result = raw.get('url_result') or {}
        result_data['url_analysis'] = url_result.get('url_analysis') if url_result else None
        domain_info = raw.get('domain_info')
        result_data['domain_info'] = domain_info if domain_info else None
        result_data['whois_info'] = domain_info.get('whois') if domain_info else None
        alienvault_raw = raw.get('alienvault_raw')
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        has_meaningful_data = (
            (result_data['url_analysis'] and result_data['url_analysis'].get('status_code') is not None) or
            (result_data['domain_info'] and result_data['domain_info'].get('ssl_info')) or
            (result_data['whois_info'] and result_data['whois_info'].get('domain')) or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
        )

        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='domain')

        card_count = sum(1 for k in ['url_analysis', 'domain_info', 'whois_info', 'alienvault'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)


@home_bp.route('/analyze', methods=['POST'])
def analyze():
    indicator = request.form.get('indicator', '').strip()
    if not indicator:
        flash('Please enter an indicator to analyze.', 'error')
        return redirect(url_for('home.home'))
    return _run_analysis(indicator)


@home_bp.route('/i/<path:indicator>', methods=['GET'])
def analyze_deeplink(indicator):
    """Deep-link route: GET /i/<indicator> runs the same analysis as the POST form.

    Examples:
        /i/8.8.8.8
        /i/google.com
        /i/d41d8cd98f00b204e9800998ecf8427e
        /i/AADSTS50034
        /i/https%3A%2F%2Fexample.com%2Fpath   (URL-encode full URLs)
    """
    from urllib.parse import unquote
    indicator = unquote(indicator).strip()
    if not indicator:
        flash('Please enter an indicator to analyze.', 'error')
        return redirect(url_for('home.home'))
    return _run_analysis(indicator)

@home_bp.route('/no_results')
def no_results():
    """Route for displaying no results page when accessed directly."""
    indicator = request.args.get('indicator', 'Unknown Indicator')
    error_type = request.args.get('error_type', None)
    return render_template('no_results.html', indicator=indicator, error_type=error_type)

@home_bp.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(current_app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon') 