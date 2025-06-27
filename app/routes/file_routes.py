from flask import Blueprint, request, jsonify
import os
from ..services.file_service import get_combined_file_analysis

file_bp = Blueprint('file', __name__)

@file_bp.route('/analyze_file', methods=['POST'])
def analyze_file():
    """Endpoint for analyzing files using Intezer."""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400

        # Save the file temporarily
        temp_path = os.path.join('/tmp', file.filename)
        file.save(temp_path)

        try:
            # Analyze the file
            analysis_result = get_combined_file_analysis(file_path=temp_path)
            
            if not analysis_result:
                return jsonify({'error': 'Could not analyze file'}), 500

            return jsonify(analysis_result)
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_path):
                os.remove(temp_path)

    except Exception as e:
        return jsonify({'error': str(e)}), 500 