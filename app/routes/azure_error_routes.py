from flask import Blueprint, render_template, request, jsonify
import re
from app.services.azure_error_service import get_azure_error_info

azure_error_bp = Blueprint('azure_error', __name__)

@azure_error_bp.route('/azure_error_search', methods=['GET'])
def azure_error_section():
    return render_template('azure_error_section.html')

@azure_error_bp.route('/api/azure_error/search', methods=['POST'])
def search_azure_error():
    error_code = request.form.get('error_code', '').strip()
    
    # Validate error code format (should be AADSTS followed by numbers, or just numbers)
    if not error_code:
        return jsonify({
            'error': 'Please enter an Azure error code.'
        }), 400
    
    # Clean the error code for validation
    clean_code = error_code.upper().replace('AADSTS', '').strip()
    
    # Check if it's a valid format (numbers only)
    if not clean_code.isdigit():
        return jsonify({
            'error': 'Invalid error code format. Please enter a valid Azure error code (e.g., AADSTS50058 or 50058).'
        }), 400
    
    # Get error information from the service
    error_info = get_azure_error_info(error_code)
    
    return jsonify(error_info) 