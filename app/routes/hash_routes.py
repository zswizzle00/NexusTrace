from flask import Blueprint, render_template, request, jsonify
from ..services.hash_service import get_hash_info
from ..services.file_service import get_intezer_analysis
from ..services.ip_service import get_alienvault_data
from app.routes.home_routes import parse_alienvault_otx  # If you have a parse function
import logging

# Configure logging
logger = logging.getLogger(__name__)

hash_bp = Blueprint('hash', __name__)

@hash_bp.route('/check_hash', methods=['POST'])
def check_hash():
    """Endpoint for checking hash information."""
    try:
        data = request.get_json()
        hash_value = data.get('hash', '').strip()
        
        if not hash_value:
            return jsonify({'error': 'Hash is required'}), 400
        
        # Get hash information
        hash_info = get_hash_info(hash_value)
        
        if 'error' in hash_info:
            return jsonify(hash_info), 400
        
        return jsonify(hash_info)
    except Exception as e:
        logger.error(f"Error in check_hash: {str(e)}")
        return jsonify({'error': str(e)}), 500

@hash_bp.route('/hash/analyze', methods=['GET', 'POST'])
def analyze_hash():
    result = None
    error = None
    intezer_result = None
    alienvault = None

    if request.method == 'POST':
        hash_value = request.form.get('hash', '').strip()
        if not hash_value:
            error = 'Hash is required'
        else:
            # Intezer enrichment
            intezer_result = get_intezer_analysis(file_hash=hash_value)
            # AlienVault enrichment
            alienvault_raw = get_alienvault_data(hash_value)
            alienvault = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None
            # Fallback: basic hash info
            if not intezer_result:
                result = get_hash_info(hash_value)

    return render_template(
        'hash_analysis.html',
        result=result,
        error=error,
        intezer_result=intezer_result,
        alienvault=alienvault
    ) 