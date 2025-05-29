from flask import Blueprint, render_template, request
import requests
import os
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)

load_dotenv()

user_agent_bp = Blueprint('user_agent', __name__)

@user_agent_bp.route('/user_agent_search', methods=['GET', 'POST'])
def user_agent_search():
    if request.method == 'POST':
        user_agent = request.form.get('user_agent')
        if not user_agent:
            return render_template('user_agent_search.html', error="Please provide a User Agent string")

        # Get API key from environment
        api_key = os.getenv('APILAYER_API_KEY')
        if not api_key:
            return render_template('user_agent_search.html', error="API key not configured")

        # Make request to APILayer User Agent API
        url = "https://api.apilayer.com/user_agent/parse"
        headers = {
            "apikey": api_key
        }
        params = {
            "ua": user_agent
        }

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            results = response.json()
            
            # Format the results for display
            formatted_results = {
                'browser': {
                    'name': results.get('browser', {}).get('name', 'Unknown'),
                    'version': results.get('browser', {}).get('version', 'Unknown')
                },
                'os': {
                    'name': results.get('os', {}).get('name', 'Unknown'),
                    'version': results.get('os', {}).get('version', 'Unknown')
                },
                'device': {
                    'type': results.get('device', {}).get('type', 'Unknown'),
                    'brand': results.get('device', {}).get('brand', 'Unknown'),
                    'model': results.get('device', {}).get('model', 'Unknown')
                },
                'is_mobile': results.get('is_mobile', False),
                'is_tablet': results.get('is_tablet', False),
                'is_desktop': results.get('is_desktop', False)
            }
            
            return render_template('user_agent_search.html', results=formatted_results)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"User Agent API request failed: {str(e)}")
            return render_template('user_agent_search.html', error=f"Error analyzing User Agent: {str(e)}")
    
    return render_template('user_agent_search.html') 