from flask import Blueprint, render_template, request, jsonify
from ..services.hash_service import get_hash_info
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

@hash_bp.route('/analyze', methods=['GET', 'POST'])
def analyze_hash():
    logger.debug("Entering analyze_hash route")
    result = None
    error = None
    
    if request.method == 'POST':
        logger.debug("Processing POST request")
        hash_value = request.form.get('hash', '').strip()
        logger.debug(f"Received hash value: {hash_value}")
        
        if not hash_value:
            error = 'Hash is required'
            logger.debug("No hash value provided")
        else:
            hash_info = get_hash_info(hash_value)
            logger.debug(f"Hash info result: {hash_info}")
            
            if 'error' in hash_info:
                error = hash_info['error']
                logger.debug(f"Error in hash info: {error}")
            else:
                result = hash_info
                logger.debug("Successfully processed hash")
    
    logger.debug(f"Rendering template with result: {result}, error: {error}")
    return render_template('hash_analysis.html', result=result, error=error) 