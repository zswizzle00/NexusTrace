from flask import Blueprint, render_template, request, jsonify
from ..services.hash_service import (
    get_hash_info, get_hash_info_quick, get_hash_info_deep,
    has_reputation_record, unknown_hash_report,
)
from ..services.ip_service import get_alienvault_data
from app.utils.parsers import parse_alienvault_otx
from app.utils.accounts import virustotal_key
import logging

logger = logging.getLogger(__name__)

hash_bp = Blueprint('hash', __name__)


@hash_bp.route('/check_hash', methods=['POST'])
def check_hash():
    try:
        data = request.get_json()
        hash_value = data.get('hash', '').strip()
        deep_scan = data.get('deep_scan', False)

        if not hash_value:
            return jsonify({'error': 'Hash is required'}), 400

        lookup = get_hash_info_deep if deep_scan else get_hash_info_quick
        hash_info = lookup(hash_value, vt_key=virustotal_key())

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
            lookup = get_hash_info_deep if deep_scan else get_hash_info_quick
            vt_key = virustotal_key()
            result = lookup(hash_value, vt_key=vt_key)

            if result.get('error'):
                # Bad hash format: a real input error, not an unknown hash.
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
                        unknown_hash=unknown_hash_report(hash_value, result, alienvault_raw,
                                                         vt_key=vt_key)
                    )

    return render_template(
        'hash_analysis.html',
        hash_info=result,
        error=error,
        alienvault=alienvault
    )