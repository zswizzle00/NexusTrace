from flask import Blueprint, request, jsonify
from ..services.url_service import analyze_url

url_bp = Blueprint('url', __name__)

@url_bp.route('/analyze_url', methods=['POST'])
def analyze_url_endpoint():
    """Endpoint for analyzing URLs."""
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Analyze URL
        url_analysis = analyze_url(url)
        
        if not url_analysis:
            return jsonify({'error': 'Could not analyze URL'}), 500
        
        return jsonify(url_analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500 