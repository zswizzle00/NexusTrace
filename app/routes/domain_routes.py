from flask import Blueprint, request, jsonify
from ..services.domain_service import get_domain_info

domain_bp = Blueprint('domain', __name__)

@domain_bp.route('/check_domain', methods=['POST'])
def check_domain():
    """Endpoint for checking domain information."""
    try:
        data = request.get_json()
        domain = data.get('domain')
        
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Get domain information
        domain_info = get_domain_info(domain)
        
        if not domain_info:
            return jsonify({'error': 'Could not fetch domain information'}), 500
        
        return jsonify(domain_info)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 