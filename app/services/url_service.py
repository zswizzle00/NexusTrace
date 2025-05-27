import os
import requests
import logging
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import builtwith
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from ..utils.cache import timed_lru_cache

# Configure logging
logger = logging.getLogger(__name__)

def setup_url_services(app):
    """Setup URL-related services."""
    pass  # Add any necessary setup code here

def submit_to_urlscan(url):
    """Submit a URL to urlscan.io for analysis."""
    api_key = os.getenv('URLSCAN_API_KEY')
    if not api_key:
        logger.warning("URLSCAN_API_KEY not configured")
        return None

    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json'
    }
    
    data = {
        'url': url,
        'visibility': 'public'
    }
    
    try:
        # Submit URL for scanning
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json=data
        )
        response.raise_for_status()
        result = response.json()
        
        # Wait for scan to complete (poll every 5 seconds, timeout after 2 minutes)
        scan_id = result.get('uuid')
        if not scan_id:
            return None
            
        for _ in range(24):  # 24 * 5 seconds = 2 minutes timeout
            time.sleep(5)
            result_response = requests.get(
                f'https://urlscan.io/api/v1/result/{scan_id}/',
                headers=headers
            )
            if result_response.status_code == 200:
                return result_response.json()
                
        return None
    except Exception as e:
        logger.error(f"Error submitting to urlscan.io: {str(e)}")
        return None

@timed_lru_cache(seconds=1800)
def analyze_url(url):
    """Analyze a URL for various security and technical aspects."""
    try:
        # Configure retry strategy
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Parse URL
        parsed_url = urlparse(url)
        
        # Get response with headers
        response = session.get(url, timeout=10, allow_redirects=True)
        
        # Analyze redirect chain
        redirect_chain = []
        if response.history:
            for resp in response.history:
                redirect_chain.append({
                    'url': resp.url,
                    'status_code': resp.status_code,
                    'headers': dict(resp.headers)
                })
        
        # Get final response info
        final_response = {
            'url': response.url,
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type', ''),
            'headers': dict(response.headers),
            'redirect_chain': redirect_chain
        }
        
        # Check security headers
        security_headers = {
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security', 'Not Set'),
            'X-Frame-Options': response.headers.get('X-Frame-Options', 'Not Set'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options', 'Not Set'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy', 'Not Set'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Not Set')
        }
        
        # Detect technologies
        try:
            tech_stack = builtwith.builtwith(url)
        except:
            tech_stack = {}
        
        # Parse content if it's HTML
        if 'text/html' in response.headers.get('content-type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = [{'name': tag.get('name', ''), 'content': tag.get('content', '')} 
                        for tag in soup.find_all('meta')]
            title = soup.title.string if soup.title else ''
        else:
            meta_tags = []
            title = ''

        # Get Intezer analysis if API key is configured
        intezer_analysis = None
        if os.getenv('INTEZER_API_KEY'):
            try:
                from .file_service import get_intezer_analysis
                # Create a temporary file with the URL content
                temp_file = f'/tmp/url_content_{hash(url)}.html'
                with open(temp_file, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                
                # Analyze the file
                intezer_analysis = get_intezer_analysis(file_path=temp_file)
                
                # Clean up temporary file
                os.remove(temp_file)
            except Exception as e:
                logger.error(f"Intezer URL analysis failed: {str(e)}")

        # Get urlscan.io analysis
        urlscan_analysis = submit_to_urlscan(url)
        
        return {
            'url_analysis': {
                'parsed_url': {
                    'scheme': parsed_url.scheme,
                    'netloc': parsed_url.netloc,
                    'path': parsed_url.path,
                    'params': parsed_url.params,
                    'query': parsed_url.query,
                    'fragment': parsed_url.fragment
                },
                'response': final_response,
                'security_headers': security_headers,
                'technologies': tech_stack,
                'meta_tags': meta_tags,
                'title': title,
                'intezer_analysis': intezer_analysis,
                'urlscan_analysis': urlscan_analysis
            }
        }
    except Exception as e:
        logging.error(f"Error analyzing URL: {str(e)}")
        return None 