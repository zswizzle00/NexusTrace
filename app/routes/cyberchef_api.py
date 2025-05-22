from flask import Blueprint, request, jsonify
import json

cyberchef_api = Blueprint('cyberchef_api', __name__)

@cyberchef_api.route('/api/cyberchef/run', methods=['POST'])
def run_cyberchef():
    data = request.json
    input_data = data.get('input')
    recipe = data.get('recipe')
    
    try:
        # Return the recipe and input to be processed by the frontend
        return jsonify({
            'input': input_data,
            'recipe': recipe
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400 