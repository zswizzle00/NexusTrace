from flask import Blueprint, request, jsonify, render_template
from ..services.domain_service import get_domain_info, get_domain_info_quick
from ..services.ip_service import get_alienvault_data
from ..services.url_service import analyze_url_quick, analyze_url_deep
from app.routes.home_routes import parse_alienvault_otx
import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

domain_bp = Blueprint('domain', __name__)

# Maximum domain length per RFC 1035
MAX_DOMAIN_LENGTH = 253
# Maximum label length per RFC 1035
MAX_LABEL_LENGTH = 63

# Valid TLDs are dynamically maintained by IANA, so we use a basic pattern check
# This validates the structure, not whether the TLD actually exists
DOMAIN_PATTERN = re.compile(
    r'^(?!-)'  # Cannot start with hyphen
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'  # Subdomains
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'  # Domain name
    r'\.[a-zA-Z]{2,}$'  # TLD (at least 2 chars)
)

# Pattern for single-label domains (internal/local use)
SINGLE_LABEL_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')


def is_valid_domain(domain, allow_single_label=False):
    """
    Check if the domain is valid.

    Args:
        domain: The domain string to validate
        allow_single_label: If True, allows domains without TLD (e.g., 'localhost')

    Returns:
        bool: True if the domain is valid
    """
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    # Check length constraints
    if len(domain) > MAX_DOMAIN_LENGTH:
        return False

    # Check each label's length
    labels = domain.split('.')
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH or len(label) == 0:
            return False

    # Check for valid domain pattern
    if DOMAIN_PATTERN.match(domain):
        return True

    # Optionally allow single-label domains for internal use
    if allow_single_label and SINGLE_LABEL_PATTERN.match(domain):
        return True

    return False


def is_valid_url(url):
    """Check if the URL is valid."""
    if not url or not isinstance(url, str):
        return False
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except ValueError:
        return False

@domain_bp.route('/check_domain', methods=['POST'])
def check_domain():
    """Endpoint for checking domain information."""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
            
        if not is_valid_domain(domain):
            return jsonify({'error': 'Invalid domain format. Please enter a valid domain name.'}), 400
        
        # Get domain information
        domain_info = get_domain_info(domain)
        
        if not domain_info:
            return jsonify({'error': 'Could not fetch domain information. The domain may not exist or be accessible.'}), 500
        
        return jsonify(domain_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@domain_bp.route('/analyze', methods=['GET', 'POST'])
def analyze_domain():
    """Endpoint for analyzing a domain or URL with all available services."""
    error = None
    result_data = {}
    card_count = 0

    if request.method == 'POST':
        indicator = request.form.get('indicator', '').strip()
        deep_scan = request.form.get('deep_scan', 'false').lower() == 'true'

        if not indicator:
            error = 'Domain or URL is required'
        else:
            # Select analysis function based on scan mode
            url_analyze_fn = analyze_url_deep if deep_scan else analyze_url_quick

            # Check if it's a URL
            if indicator.lower().startswith(('http://', 'https://')):
                # Get URL analysis
                url_analysis = url_analyze_fn(indicator)
                result_data['url_analysis'] = url_analysis if url_analysis else None
                # Extract domain from URL for additional analysis
                domain = urlparse(indicator).netloc
            else:
                # Try to normalize as URL first
                normalized_url = f'https://{indicator}'
                if is_valid_url(normalized_url):
                    url_analysis = url_analyze_fn(normalized_url)
                    result_data['url_analysis'] = url_analysis if url_analysis else None
                    domain = urlparse(normalized_url).netloc
                else:
                    domain = indicator

            # Get domain information (includes WHOIS)
            domain_info = get_domain_info(domain)
            result_data['domain_info'] = domain_info if domain_info else None
            # Extract WHOIS from domain_info for template compatibility
            result_data['whois_info'] = domain_info.get('whois') if domain_info else None

            # Get AlienVault OTX information
            alienvault_raw = get_alienvault_data(domain)
            result_data['alienvault'] = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

            # Check if we got meaningful domain analysis results
            has_meaningful_data = (
                (result_data['url_analysis'] and result_data['url_analysis'].get('url_analysis', {}).get('status_code') is not None) or
                (result_data['domain_info'] and result_data['domain_info'].get('ssl_info')) or
                (result_data['whois_info'] and result_data['whois_info'].get('domain')) or
                (alienvault_raw and alienvault_raw.get('general', {}).get('pulse_info', {}).get('count', 0) > 0)
            )

            # If no meaningful data found, redirect to no results page
            if not has_meaningful_data:
                return render_template('no_results.html', indicator=indicator, error_type='domain')

            card_count = sum(1 for k in ['url_analysis', 'domain_info', 'whois_info', 'alienvault'] if result_data.get(k))
    return render_template('analyze_result.html', error=error, card_count=card_count, **result_data)

@domain_bp.route('/analyze_url', methods=['POST'])
def analyze_url_endpoint():
    """API endpoint for analyzing URLs."""
    try:
        data = request.get_json()
        url = data.get('url')
        deep_scan = data.get('deep_scan', False)

        if not url:
            return jsonify({'error': 'URL is required'}), 400

        # Normalize URL: prepend https:// if no scheme is present
        if not url.lower().startswith(('http://', 'https://')):
            url = f'https://{url}'

        # Analyze URL based on scan mode
        url_analysis = analyze_url_deep(url) if deep_scan else analyze_url_quick(url)

        if not url_analysis:
            return jsonify({'error': 'Could not analyze URL'}), 500

        return jsonify(url_analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 