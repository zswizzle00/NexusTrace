from flask import Blueprint, render_template, request, jsonify
from ..services.hash_service import (
    get_hash_info, get_hash_info_quick, get_hash_info_deep,
    has_reputation_record, unknown_hash_report,
)
from ..services.ip_service import get_alienvault_data
from app.utils.parsers import parse_alienvault_otx
import logging

logger = logging.getLogger(__name__)

hash_bp = Blueprint('hash', __name__)


@hash_bp.route('/check_hash', methods=['POST'])
def check_hash():
    """Hash reputation lookup (JSON)."""
    try:
        data = request.get_json()
        hash_value = data.get('hash', '').strip()
        deep_scan = data.get('deep_scan', False)

        if not hash_value:
            return jsonify({'error': 'Hash is required'}), 400

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
    alienvault = None

    if request.method == 'POST':
        hash_value = request.form.get('hash', '').strip()
        deep_scan = request.form.get('deep_scan', 'false').lower() == 'true'

        if not hash_value:
            error = 'Hash is required'
        else:
            result = get_hash_info_deep(hash_value) if deep_scan else get_hash_info_quick(hash_value)

            if result.get('error'):
                # Bad hash format — a real input error, not an unknown hash.
                error = result['error']
                result = None
            else:
                alienvault_raw = get_alienvault_data(hash_value)
                alienvault = parse_alienvault_otx(alienvault_raw) if alienvault_raw else None

                if not has_reputation_record(result, alienvault_raw):
                    # Same "nobody has seen it" page /analyze and /i/<hash> render.
                    return render_template(
                        'hash_analysis.html',
                        indicator=hash_value,
                        indicator_type='hash',
                        unknown_hash=unknown_hash_report(hash_value, result, alienvault_raw)
                    )

    return render_template(
        'hash_analysis.html',
        hash_info=result,
        error=error,
        alienvault=alienvault
    )