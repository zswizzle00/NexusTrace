from flask import Blueprint, request, jsonify
from ..services.domain_service import get_domain_info
import re

domain_bp = Blueprint('domain', __name__)

def is_valid_domain(domain):
    """Check if the domain is valid."""
    # Basic domain validation - allows domains without TLD for internal use
    domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    return bool(re.match(domain_pattern, domain))

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