import os
import requests
import logging
import time
import tempfile
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import builtwith
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from ..utils.cache import timed_lru_cache
from ..utils.rate_limiter import RateLimiter
from datetime import timedelta
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logger = logging.getLogger(__name__)

# Initialize rate limiters
urlscan_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
builtwith_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))

# Timeout settings
TIMEOUT_SHORT = 5
TIMEOUT_MEDIUM = 10


def setup_url_services(app):
    """Setup URL-related services."""
    pass


def submit_to_urlscan(url, wait_for_result=False, max_polls=3):
    """
    Submit a URL to urlscan.io for analysis.

    Args:
        url: The URL to scan
        wait_for_result: If True, poll for results. If False, just return scan link.
        max_polls: Maximum number of times to poll (each poll waits 5 seconds)

    Returns:
        dict with scan results or scan link
    """
    api_key = os.getenv('URLSCAN_API_KEY')
    if not api_key:
        logger.debug("URLSCAN_API_KEY not configured")
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
        urlscan_limiter.acquire()

        # Submit URL for scanning
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json=data,
            timeout=TIMEOUT_MEDIUM
        )

        if response.status_code == 429:
            logger.warning("URLscan rate limit exceeded")
            return {'status': 'rate_limited', 'message': 'Rate limit exceeded'}

        response.raise_for_status()
        result = response.json()

        scan_id = result.get('uuid')
        scan_url = result.get('result')  # Direct link to results

        if not scan_id:
            return None

        # If not waiting for results, return the scan link immediately
        if not wait_for_result:
            return {
                'status': 'submitted',
                'scan_id': scan_id,
                'result_url': scan_url or f'https://urlscan.io/result/{scan_id}/',
                'api_url': f'https://urlscan.io/api/v1/result/{scan_id}/',
                'message': 'Scan submitted. Results will be available shortly.'
            }

        # Poll for results (limited polling for deep scan)
        for i in range(max_polls):
            time.sleep(5)
            try:
                result_response = requests.get(
                    f'https://urlscan.io/api/v1/result/{scan_id}/',
                    headers=headers,
                    timeout=TIMEOUT_MEDIUM
                )
                if result_response.status_code == 200:
                    data = result_response.json()
                    data['status'] = 'completed'
                    return data
            except Exception:
                pass

        # Return partial result with link if polling didn't complete
        return {
            'status': 'pending',
            'scan_id': scan_id,
            'result_url': scan_url or f'https://urlscan.io/result/{scan_id}/',
            'message': f'Scan still processing after {max_polls * 5}s. Check the link for results.'
        }

    except requests.Timeout:
        logger.warning(f"URLscan submission timed out for {url}")
        return {'status': 'timeout', 'message': 'Request timed out'}
    except Exception as e:
        logger.error(f"Error submitting to urlscan.io: {str(e)}")
        return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_favicon_hash(url):
    """Get favicon and compute its MD5 hash."""
    try:
        parsed = urlparse(url)
        favicon_url = f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        resp = requests.get(favicon_url, timeout=TIMEOUT_SHORT)
        if resp.status_code == 200 and len(resp.content) > 0:
            h = hashlib.md5(resp.content).hexdigest()
            return {'url': favicon_url, 'md5': h, 'size': len(resp.content)}
    except Exception as e:
        logger.debug(f"Error fetching favicon: {str(e)}")
    return None


def parse_opengraph_twitter(soup):
    """Parse OpenGraph and Twitter meta tags."""
    og = {}
    twitter = {}
    for tag in soup.find_all('meta'):
        prop = tag.get('property', '')
        name = tag.get('name', '')
        content = tag.get('content', '')
        if prop.startswith('og:'):
            og[prop] = content
        if name.startswith('twitter:'):
            twitter[name] = content
    return {'opengraph': og, 'twitter': twitter}


def check_phishtank_url(url):
    """Generate PhishTank search URL."""
    return f'https://phishtank.org/search.php?valid=y&active=y&Search={url}'


def get_google_safebrowsing_link(url):
    """Generate Google Safe Browsing transparency report link."""
    encoded_url = requests.utils.quote(url, safe='')
    return f'https://transparencyreport.google.com/safe-browsing/search?url={encoded_url}'


@timed_lru_cache(seconds=1800, maxsize=500)
def get_tech_stack(url):
    """Detect technologies used by the website."""
    try:
        builtwith_limiter.acquire()
        return builtwith.builtwith(url)
    except Exception as e:
        logger.debug(f"Could not detect technologies: {e}")
        return {}


def analyze_url(url, deep_scan=False):
    """
    Analyze a URL for various security and technical aspects.

    Args:
        url: The URL to analyze
        deep_scan: If True, wait for URLscan results and run Intezer analysis.
                   If False, return quickly with essential info only.
    """
    try:
        # Configure retry strategy
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Parse URL
        parsed_url = urlparse(url)

        # Get response with headers
        response = session.get(url, timeout=TIMEOUT_MEDIUM, allow_redirects=True)

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
            'X-XSS-Protection': response.headers.get('X-XSS-Protection', 'Not Set'),
            'Referrer-Policy': response.headers.get('Referrer-Policy', 'Not Set'),
            'Permissions-Policy': response.headers.get('Permissions-Policy', 'Not Set'),
        }

        # Parse content if it's HTML
        meta_tags = []
        title = ''
        og_twitter = {'opengraph': {}, 'twitter': {}}
        if 'text/html' in response.headers.get('content-type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            meta_tags = [{'name': tag.get('name', ''), 'content': tag.get('content', '')}
                         for tag in soup.find_all('meta') if tag.get('name') or tag.get('content')]
            title = soup.title.string if soup.title else ''
            og_twitter = parse_opengraph_twitter(soup)

        # Prepare result structure
        result = {
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
                'technologies': {},
                'meta_tags': meta_tags[:20],  # Limit to 20 tags
                'title': title,
                'intezer_analysis': None,
                'urlscan_analysis': None,
                'screenshot_url': None,
                'favicon': None,
                'opengraph': og_twitter['opengraph'],
                'twitter': og_twitter['twitter'],
                'phishtank_url': check_phishtank_url(url),
                'safebrowsing_url': get_google_safebrowsing_link(url),
                'scan_mode': 'deep' if deep_scan else 'quick'
            }
        }

        # Quick scan: Run fast lookups in parallel
        if not deep_scan:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {
                    executor.submit(get_favicon_hash, url): 'favicon',
                    executor.submit(get_tech_stack, url): 'tech',
                    executor.submit(submit_to_urlscan, url, False): 'urlscan',
                }
                for future in as_completed(futures, timeout=TIMEOUT_MEDIUM):
                    key = futures[future]
                    try:
                        data = future.result(timeout=TIMEOUT_SHORT)
                        if key == 'favicon':
                            result['url_analysis']['favicon'] = data
                        elif key == 'tech':
                            result['url_analysis']['technologies'] = data or {}
                        elif key == 'urlscan':
                            result['url_analysis']['urlscan_analysis'] = data
                    except Exception:
                        pass

            return result

        # Deep scan: Run all lookups including URLscan polling and Intezer
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {
                executor.submit(get_favicon_hash, url): 'favicon',
                executor.submit(get_tech_stack, url): 'tech',
                executor.submit(submit_to_urlscan, url, True, 6): 'urlscan',  # Wait up to 30s
            }

            # Add Intezer analysis if configured and we have HTML content
            intezer_future = None
            if os.getenv('INTEZER_KEY') and 'text/html' in response.headers.get('content-type', '').lower():
                def run_intezer():
                    try:
                        from .file_service import get_intezer_analysis
                        with tempfile.NamedTemporaryFile(
                            mode='w', suffix='.html', prefix='nexustrace_',
                            delete=False, encoding='utf-8'
                        ) as temp_file:
                            temp_file.write(response.text)
                            temp_path = temp_file.name
                        try:
                            return get_intezer_analysis(file_path=temp_path)
                        finally:
                            if os.path.exists(temp_path):
                                os.remove(temp_path)
                    except Exception as e:
                        logger.error(f"Intezer analysis failed: {e}")
                        return None

                intezer_future = executor.submit(run_intezer)
                futures[intezer_future] = 'intezer'

            for future in as_completed(futures, timeout=45):
                key = futures[future]
                try:
                    data = future.result(timeout=TIMEOUT_MEDIUM)
                    if key == 'favicon':
                        result['url_analysis']['favicon'] = data
                    elif key == 'tech':
                        result['url_analysis']['technologies'] = data or {}
                    elif key == 'urlscan':
                        result['url_analysis']['urlscan_analysis'] = data
                        if data and data.get('status') == 'completed':
                            result['url_analysis']['screenshot_url'] = data.get('task', {}).get('screenshotURL')
                    elif key == 'intezer':
                        result['url_analysis']['intezer_analysis'] = data
                except Exception as e:
                    logger.debug(f"URL analysis {key} failed: {e}")

        return result

    except requests.Timeout:
        logger.warning(f"URL analysis timed out for {url}")
        return {'error': 'Request timed out', 'url': url}
    except requests.RequestException as e:
        logger.error(f"Error analyzing URL: {str(e)}")
        return {'error': str(e), 'url': url}
    except Exception as e:
        logger.error(f"Unexpected error analyzing URL: {str(e)}")
        return {'error': str(e), 'url': url}


def analyze_url_quick(url):
    """Quick URL analysis - essential info only, fast response."""
    return analyze_url(url, deep_scan=False)


def analyze_url_deep(url):
    """Deep URL analysis - full analysis with URLscan polling and Intezer."""
    return analyze_url(url, deep_scan=True)
