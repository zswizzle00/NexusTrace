from flask import Blueprint, render_template, request, jsonify
from ..services.hash_service import get_hash_info, get_hash_info_quick, get_hash_info_deep
from ..services.file_service import get_intezer_analysis
from ..services.ip_service import get_alienvault_data
from app.routes.home_routes import parse_alienvault_otx
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
        deep_scan = data.get('deep_scan', False)

        if not hash_value:
            return jsonify({'error': 'Hash is required'}), 400

        # Get hash information based on scan mode
        hash_info = get_hash_info_deep(hash_value) if deep_scan else get_hash_info_quick(hash_value)

        if 'error' in hash_info:
            return jsonify(hash_info), 400

        return jsonify(hash_info)
    except Exception as e:
        logger.error(f"Error in check_hash: {str(e)}")
        return jsonify({'error': str(e)}), 500

@hash_bp.route('/analyze', methods=['GET', 'POST'])
def analyze_hash():
    result = None
    error = None
    intezer_result = None
    alienvault = None

    if request.method == 'POST':
        hash_value = request.form.get('hash', '').strip()
        deep_scan = request.form.get('deep_scan', 'false').lower() == 'true'

        if not hash_value:
            error = 'Hash is required'
        else:
            # Get comprehensive hash info (includes VT, MalwareBazaar, ThreatFox)
            result = get_hash_info_deep(hash_value) if deep_scan else get_hash_info_quick(hash_value)

            # Intezer enrichment (only in deep scan mode - it's slow)
            if deep_scan:
                intezer_result = get_intezer_analysis(file_hash=hash_value)

            # AlienVault enrichment
            alienvault_raw = get_alienvault_data(hash_value)
            alienvault = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

    return render_template(
        'hash_analysis.html',
        result=result,
        error=error,
        intezer_result=intezer_result,
        alienvault=alienvault
    ) 