from flask import Blueprint, request, jsonify, render_template
from ..services.domain_service import get_domain_info, get_whois_info
from ..services.ip_service import get_alienvault_data
from ..services.url_service import analyze_url
from app.routes.home_routes import parse_alienvault_otx
import re
from urllib.parse import urlparse

domain_bp = Blueprint('domain', __name__)

def is_valid_domain(domain):
    """Check if the domain is valid."""
    # Basic domain validation - allows domains without TLD for internal use
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    return bool(re.match(domain_pattern, domain))

def is_valid_url(url):
    """Check if the URL is valid."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
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
        if not indicator:
            error = 'Domain or URL is required'
        else:
            # Check if it's a URL
            if indicator.lower().startswith(('http://', 'https://')):
                # Get URL analysis
                url_analysis = analyze_url(indicator)
                result_data['url_analysis'] = url_analysis if url_analysis else None
                # Extract domain from URL for additional analysis
                domain = urlparse(indicator).netloc
            else:
                # Try to normalize as URL first
                normalized_url = f'https://{indicator}'
                if is_valid_url(normalized_url):
                    url_analysis = analyze_url(normalized_url)
                    result_data['url_analysis'] = url_analysis if url_analysis else None
                    domain = urlparse(normalized_url).netloc
                else:
                    domain = indicator
            # Get domain information
            domain_info = get_domain_info(domain)
            result_data['domain_info'] = domain_info if domain_info else None
            # Get WHOIS information
            whois_info = get_whois_info(domain)
            result_data['whois_info'] = whois_info if whois_info else None
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
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Normalize URL: prepend https:// if no scheme is present
        if not url.lower().startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        # Analyze URL
        url_analysis = analyze_url(url)
        
        if not url_analysis:
            return jsonify({'error': 'Could not analyze URL'}), 500
        
        return jsonify(url_analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 