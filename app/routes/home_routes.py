from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app
import re
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)
from app.services.hash_service import get_hash_info_quick, has_reputation_record, unknown_hash_report
from app.services.ip_service import get_ipinfo_data, get_shodan_info, check_abuseipdb, get_vpn_data, get_proxycheck_data, get_alienvault_data, get_ip2location_data, get_ipapi_data
from app.services.domain_service import get_domain_info
from app.services.url_service import analyze_url_quick
from app.services.user_agent_service import parse_user_agent
from app.services.azure_error_service import get_azure_error_info
from dotenv import load_dotenv
from app.services.event_service import get_event_info
from urllib.parse import urlparse
from app.utils.validators import is_valid_ip, is_valid_domain
from app.utils.parsers import parse_alienvault_otx, parse_shodan, parse_abuseipdb

try:
    from app.services.abusech import threatfox_lookup, urlhaus_host
except ImportError:
    # The module is optional at import time; without it the two abuse.ch sources are
    # simply absent from the fan-out and their cards never reach the template.
    threatfox_lookup = None
    urlhaus_host = None

load_dotenv()

home_bp = Blueprint('home', __name__)

@home_bp.route('/')
def home():
    return render_template('home.html')

@home_bp.route('/ip_search', methods=['GET', 'POST'])
def ip_search():
    error = None
    result = None
    if request.method == 'POST':
        ip = request.form.get('ip', '').strip()
        if not ip:
            error = 'IP address is required.'
        else:
            # Stub: echoes the IP back. Real lookup goes through /analyze.
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
            if indicator.lower().startswith(('http://', 'https://')):
                return redirect(url_for('domain.analyze_domain', indicator=indicator))
            else:
                return redirect(url_for('domain.analyze_domain', indicator=indicator))
    return render_template('domain_search.html', error=error, result=result)

@home_bp.route('/hash_analysis', methods=['GET'])
def hash_analysis_form():
    return render_template('hash_analysis.html')

@home_bp.route('/file_analysis', methods=['GET'])
def file_analysis_form():
    # submit_url must point at the HTML route; the template defaults to the JSON
    # endpoint, which would hand the analyst a raw record instead of a page.
    return render_template('file_analysis.html',
                           submit_url=url_for('file.analyze_file_page'))

def _run_parallel(tasks, max_workers, label):
    """Run a dict of {key: zero-arg callable} in parallel.
    Returns {key: result_or_None}; individual failures are logged at WARNING."""
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(fn): key for key, fn in tasks.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as e:
                logger.warning(f"{label} lookup {key} failed: {e}")
                results[key] = None
    return results


def _abusech_found(envelope):
    """True only when an abuse.ch envelope carries an actual record. `no_record`,
    `skipped` and `unavailable` are answers, not data, so they must not keep a
    page alive on their own."""
    return isinstance(envelope, dict) and envelope.get('state') == 'found'


def _run_analysis(indicator):
    """Core analysis logic shared by the POST /analyze form and GET /i/<indicator> deep-link route."""
    result_data = {}
    card_count = 0
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
        raw = _run_parallel({
            'hash_info':     lambda: get_hash_info_quick(indicator),
            'alienvault_raw': lambda: get_alienvault_data(indicator),
        }, max_workers=2, label='Hash')
        hash_info = raw.get('hash_info')
        result_data['hash_info'] = hash_info if hash_info and not hash_info.get('error') else None
        alienvault_raw = raw.get('alienvault_raw')
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        if not has_reputation_record(result_data['hash_info'], alienvault_raw):
            # "Nobody has seen it" is a finding, not an error - a freshly staged
            # dropper looks exactly like this, so keep the hash on screen.
            return render_template('hash_analysis.html',
                                   indicator=indicator,
                                   indicator_type=indicator_type,
                                   unknown_hash=unknown_hash_report(
                                       indicator, result_data['hash_info'], alienvault_raw))

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
        tasks = {
            'ipinfo':        lambda: get_ipinfo_data(indicator),
            'ip2location':   lambda: get_ip2location_data(indicator),
            'vpnapi':        lambda: get_vpn_data(indicator),
            'proxycheck':    lambda: get_proxycheck_data(indicator),
            'ipapi':         lambda: get_ipapi_data(indicator),
            'shodan_raw':    lambda: get_shodan_info(indicator),
            'abuseipdb_raw': lambda: check_abuseipdb(indicator),
            'alienvault_raw': lambda: get_alienvault_data(indicator),
        }
        if threatfox_lookup is not None:
            tasks['threatfox'] = lambda: threatfox_lookup(indicator)
        if urlhaus_host is not None:
            tasks['urlhaus'] = lambda: urlhaus_host(indicator)
        raw = _run_parallel(tasks, max_workers=len(tasks), label='IP')
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
        result_data['threatfox'] = raw.get('threatfox') or None
        result_data['urlhaus'] = raw.get('urlhaus') or None

        has_meaningful_data = (
            (result_data['ipinfo'] and (result_data['ipinfo'].get('country') or result_data['ipinfo'].get('asn'))) or
            (result_data['ipapi'] and result_data['ipapi'].get('country')) or
            (result_data['vpnapi'] and result_data['vpnapi'].get('location', {}).get('city')) or
            (result_data['shodan'] and result_data['shodan'].get('summary', {}).get('organization')) or
            (result_data['abuseipdb'] and result_data['abuseipdb'].get('summary', {}).get('risk_score') is not None) or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0) or
            _abusech_found(result_data['threatfox']) or
            _abusech_found(result_data['urlhaus'])
        )

        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='ip')

        card_count = sum(1 for k in ['ipinfo', 'ip2location', 'ipapi', 'vpnapi', 'proxycheck', 'shodan', 'abuseipdb', 'alienvault', 'threatfox', 'urlhaus'] if result_data.get(k))
        return render_template('analyze_result.html',
                              indicator=indicator,
                              indicator_type=indicator_type,
                              card_count=card_count,
                              **result_data)
    elif indicator_type in ('url', 'domain'):
        # Both domains and full URLs go through the URL scanner. Do NOT prepend a
        # scheme here: url_guard.normalize() owns scheme defaulting, and a second
        # rule here made the same bare domain scan differently via /analyze than
        # via /url_scan.
        from app.services.scan_service import run_scan, save_scan
        from app.utils.url_guard import is_scannable
        if not is_scannable(indicator):
            return render_template('no_results.html', indicator=indicator, error_type=indicator_type)
        scan = run_scan(indicator)
        save_scan(scan)
        return redirect(url_for('scan.url_scan_result', scan_id=scan['id']))


@home_bp.route('/analyze', methods=['POST'])
def analyze():
    indicator = request.form.get('indicator', '').strip()
    if not indicator:
        flash('Please enter an indicator to analyze.', 'error')
        return redirect(url_for('home.home'))
    return _run_analysis(indicator)


@home_bp.route('/i/<path:indicator>', methods=['GET'])
def analyze_deeplink(indicator):
    """Runs the same analysis as the POST form. Full URLs must be percent-encoded
    (``/i/https%3A%2F%2Fexample.com%2Fpath``)."""
    from urllib.parse import unquote
    indicator = unquote(indicator).strip()
    if not indicator:
        flash('Please enter an indicator to analyze.', 'error')
        return redirect(url_for('home.home'))
    return _run_analysis(indicator)

@home_bp.route('/no_results')
def no_results():
    """The no-results page when reached directly rather than via a redirect."""
    indicator = request.args.get('indicator', 'Unknown Indicator')
    error_type = request.args.get('error_type', None)
    return render_template('no_results.html', indicator=indicator, error_type=error_type)

@home_bp.route('/favicon.ico')
def favicon():
    # static_folder, not root_path/'static': the app package has no static dir.
    return send_from_directory(current_app.static_folder,
                               'favicon_io/favicon.ico',
                               mimetype='image/vnd.microsoft.icon')