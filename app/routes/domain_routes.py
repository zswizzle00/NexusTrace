from flask import Blueprint, request, jsonify, render_template
from ..services.domain_service import get_domain_info, get_domain_info_quick
from ..services.ip_service import get_alienvault_data
from ..services.url_service import analyze_url_quick, analyze_url_deep
from app.utils.parsers import parse_alienvault_otx
from ..utils.validators import is_valid_domain, is_valid_url
import logging
from urllib.parse import urlparse

try:
    from ..services.abusech import threatfox_lookup, urlhaus_host
except ImportError:
    threatfox_lookup = None
    urlhaus_host = None

logger = logging.getLogger(__name__)

domain_bp = Blueprint('domain', __name__)

@domain_bp.route('/check_domain', methods=['POST'])
def check_domain():
    """Domain information lookup (JSON)."""
    try:
        data = request.get_json(silent=True) or {}
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
            
        if not is_valid_domain(domain):
            return jsonify({'error': 'Invalid domain format. Please enter a valid domain name.'}), 400
        
        domain_info = get_domain_info(domain)
        
        if not domain_info:
            return jsonify({'error': 'Could not fetch domain information. The domain may not exist or be accessible.'}), 500
        
        return jsonify(domain_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@domain_bp.route('/analyze', methods=['GET', 'POST'])
def analyze_domain():
    """Analyze a domain or URL with all available services."""
    error = None
    result_data = {}
    card_count = 0

    # request.values, not request.form: /domain_search redirects here as a GET
    # with ?indicator=..., which a form-only read would miss and 500 on.
    indicator = (request.values.get('indicator') or '').strip()
    deep_scan = (request.values.get('deep_scan') or 'false').lower() == 'true'

    if request.method == 'POST' and not indicator:
        error = 'Domain or URL is required'
    elif indicator:
        url_analyze_fn = analyze_url_deep if deep_scan else analyze_url_quick

        if indicator.lower().startswith(('http://', 'https://')):
            url_result = url_analyze_fn(indicator)
            # Unwrap to the inner dict that analyze_result.html expects.
            result_data['url_analysis'] = url_result.get('url_analysis') if url_result else None
            domain = urlparse(indicator).netloc
        else:
            normalized_url = f'https://{indicator}'
            if is_valid_url(normalized_url):
                url_result = url_analyze_fn(normalized_url)
                result_data['url_analysis'] = url_result.get('url_analysis') if url_result else None
                domain = urlparse(normalized_url).netloc
            else:
                domain = indicator

        domain_info = get_domain_info(domain)
        result_data['domain_info'] = domain_info if domain_info else None
        # Hoisted out of domain_info for template compatibility.
        result_data['whois_info'] = domain_info.get('whois') if domain_info else None

        alienvault_raw = get_alienvault_data(domain)
        result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

        # Both accept a bare domain. `analyze_result.html` already renders these two
        # envelopes from the IP path; passing them here lights up the same cards.
        if threatfox_lookup and urlhaus_host:
            result_data['threatfox'] = threatfox_lookup(domain)
            result_data['urlhaus'] = urlhaus_host(domain)

        def _abusech_found(env):
            return isinstance(env, dict) and env.get('state') == 'found'

        has_meaningful_data = (
            (result_data['url_analysis'] and result_data['url_analysis'].get('response', {}).get('status_code') is not None) or
            (result_data['domain_info'] and result_data['domain_info'].get('ssl_info')) or
            (result_data['whois_info'] and result_data['whois_info'].get('domain')) or
            (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0) or
            _abusech_found(result_data.get('threatfox')) or
            _abusech_found(result_data.get('urlhaus'))
        )

        if not has_meaningful_data:
            return render_template('no_results.html', indicator=indicator, error_type='domain')

        card_count = sum(1 for k in ['url_analysis', 'domain_info', 'whois_info', 'alienvault'] if result_data.get(k))
    return render_template('analyze_result.html', error=error, card_count=card_count,
                           indicator=indicator, indicator_type='domain', **result_data)

@domain_bp.route('/analyze_url', methods=['POST'])
def analyze_url_endpoint():
    """URL analysis (JSON)."""
    try:
        data = request.get_json()
        url = data.get('url')
        deep_scan = data.get('deep_scan', False)

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        if not url.lower().startswith(('http://', 'https://')):
            url = f'https://{url}'

        url_analysis = analyze_url_deep(url) if deep_scan else analyze_url_quick(url)

        if not url_analysis:
            return jsonify({'error': 'Could not analyze URL'}), 500

        return jsonify(url_analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 