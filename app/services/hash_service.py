import os
import re
import requests
import logging
from typing import Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..utils.cache import timed_lru_cache
from ..utils.rate_limiter import RateLimiter
from datetime import timedelta

# Configure logging
logger = logging.getLogger(__name__)

# Rate limiters
virustotal_limiter = RateLimiter(max_requests=4, time_window=timedelta(minutes=1))  # VT free tier: 4/min

# Timeouts
TIMEOUT_SHORT = 5
TIMEOUT_MEDIUM = 10


def identify_hash_type(hash_value: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Identify the type of hash and validate its format.
    Returns a tuple of (hash_type, error_message)
    """
    hash_value = hash_value.lower().strip()

    # MD5: 32 characters
    if re.match(r'^[a-f0-9]{32}$', hash_value):
        return 'MD5', None

    # SHA1: 40 characters
    if re.match(r'^[a-f0-9]{40}$', hash_value):
        return 'SHA1', None

    # SHA256: 64 characters
    if re.match(r'^[a-f0-9]{64}$', hash_value):
        return 'SHA256', None

    # SHA512: 128 characters
    if re.match(r'^[a-f0-9]{128}$', hash_value):
        return 'SHA512', None

    return None, 'Invalid hash format. Supported: MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128)'


@timed_lru_cache(seconds=1800, maxsize=500)
def get_virustotal_report(hash_value: str) -> Optional[Dict]:
    """
    Get VirusTotal report for a hash.
    Requires VIRUSTOTAL_API_KEY environment variable.
    """
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        logger.debug("VIRUSTOTAL_API_KEY not configured")
        return None

    try:
        virustotal_limiter.acquire()
        response = requests.get(
            f'https://www.virustotal.com/api/v3/files/{hash_value}',
            headers={'x-apikey': api_key},
            timeout=TIMEOUT_MEDIUM
        )

        if response.status_code == 404:
            return {'status': 'not_found', 'message': 'Hash not found in VirusTotal'}

        if response.status_code == 429:
            logger.warning("VirusTotal rate limit exceeded")
            return {'status': 'rate_limited', 'message': 'Rate limit exceeded'}

        response.raise_for_status()
        data = response.json().get('data', {})
        attributes = data.get('attributes', {})

        # Parse detection stats
        stats = attributes.get('last_analysis_stats', {})
        total_engines = sum(stats.values())
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)

        # Get detailed results
        results = attributes.get('last_analysis_results', {})
        detections = []
        for engine, result in results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                detections.append({
                    'engine': engine,
                    'category': result.get('category'),
                    'result': result.get('result')
                })

        return {
            'status': 'found',
            'hash': hash_value,
            'sha256': attributes.get('sha256'),
            'sha1': attributes.get('sha1'),
            'md5': attributes.get('md5'),
            'file_size': attributes.get('size'),
            'file_type': attributes.get('type_description'),
            'file_names': attributes.get('names', [])[:10],  # Limit to 10 names
            'first_seen': attributes.get('first_submission_date'),
            'last_seen': attributes.get('last_analysis_date'),
            'detection_stats': {
                'malicious': malicious,
                'suspicious': suspicious,
                'undetected': stats.get('undetected', 0),
                'total': total_engines,
                'detection_ratio': f"{malicious + suspicious}/{total_engines}"
            },
            'detections': detections[:20],  # Limit to top 20 detections
            'tags': attributes.get('tags', []),
            'signature_info': attributes.get('signature_info'),
            'vt_link': f"https://www.virustotal.com/gui/file/{attributes.get('sha256', hash_value)}"
        }

    except requests.Timeout:
        logger.warning(f"VirusTotal request timed out for {hash_value}")
        return {'status': 'timeout', 'message': 'Request timed out'}
    except requests.RequestException as e:
        logger.error(f"VirusTotal API error: {str(e)}")
        return {'status': 'error', 'message': str(e)}
    except Exception as e:
        logger.error(f"Error getting VirusTotal report: {str(e)}")
        return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_malwarebazaar_report(hash_value: str) -> Optional[Dict]:
    """
    Get MalwareBazaar report for a hash (free, no API key required).
    """
    try:
        response = requests.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': hash_value},
            timeout=TIMEOUT_SHORT
        )
        response.raise_for_status()
        data = response.json()

        if data.get('query_status') == 'hash_not_found':
            return {'status': 'not_found'}

        if data.get('query_status') == 'ok' and data.get('data'):
            info = data['data'][0]
            return {
                'status': 'found',
                'sha256': info.get('sha256_hash'),
                'sha1': info.get('sha1_hash'),
                'md5': info.get('md5_hash'),
                'file_type': info.get('file_type'),
                'file_name': info.get('file_name'),
                'file_size': info.get('file_size'),
                'signature': info.get('signature'),
                'first_seen': info.get('first_seen'),
                'last_seen': info.get('last_seen'),
                'reporter': info.get('reporter'),
                'tags': info.get('tags', []),
                'delivery_method': info.get('delivery_method'),
                'intelligence': info.get('intelligence', {}),
                'mb_link': f"https://bazaar.abuse.ch/sample/{info.get('sha256_hash', hash_value)}/"
            }

        return {'status': 'error', 'message': data.get('query_status')}

    except requests.Timeout:
        logger.warning(f"MalwareBazaar request timed out for {hash_value}")
        return {'status': 'timeout'}
    except Exception as e:
        logger.error(f"MalwareBazaar API error: {str(e)}")
        return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_threatfox_iocs(hash_value: str) -> Optional[Dict]:
    """
    Search ThreatFox for IOCs related to a hash (free, no API key required).
    """
    try:
        response = requests.post(
            'https://threatfox-api.abuse.ch/api/v1/',
            json={'query': 'search_hash', 'hash': hash_value},
            timeout=TIMEOUT_SHORT
        )
        response.raise_for_status()
        data = response.json()

        if data.get('query_status') == 'no_result':
            return {'status': 'not_found'}

        if data.get('query_status') == 'ok' and data.get('data'):
            iocs = data['data']
            return {
                'status': 'found',
                'ioc_count': len(iocs),
                'iocs': [{
                    'id': ioc.get('id'),
                    'ioc_type': ioc.get('ioc_type'),
                    'threat_type': ioc.get('threat_type'),
                    'malware': ioc.get('malware'),
                    'confidence': ioc.get('confidence_level'),
                    'first_seen': ioc.get('first_seen_utc'),
                    'tags': ioc.get('tags', [])
                } for ioc in iocs[:10]]  # Limit to 10
            }

        return {'status': 'error'}

    except Exception as e:
        logger.debug(f"ThreatFox API error: {str(e)}")
        return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_hash_info(hash_value: str, deep_scan: bool = False) -> Dict:
    """
    Get comprehensive information about a hash from multiple sources.

    Args:
        hash_value: The hash to look up
        deep_scan: If True, wait for all sources. If False, use shorter timeouts.
    """
    hash_value = hash_value.lower().strip()
    hash_type, error = identify_hash_type(hash_value)

    if error:
        return {'error': error}

    result = {
        'hash': hash_value,
        'type': hash_type,
        'sources': {},
        'summary': {
            'is_malicious': False,
            'detection_count': 0,
            'total_engines': 0,
            'malware_names': set(),
            'tags': set()
        }
    }

    # Run lookups in parallel
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(get_virustotal_report, hash_value): 'virustotal',
            executor.submit(get_malwarebazaar_report, hash_value): 'malwarebazaar',
            executor.submit(get_threatfox_iocs, hash_value): 'threatfox',
        }

        timeout = TIMEOUT_MEDIUM if deep_scan else TIMEOUT_SHORT

        for future in as_completed(futures, timeout=timeout + 5):
            source = futures[future]
            try:
                data = future.result(timeout=timeout)
                if data:
                    result['sources'][source] = data

                    # Update summary
                    if data.get('status') == 'found':
                        # VirusTotal detections
                        if source == 'virustotal':
                            stats = data.get('detection_stats', {})
                            malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                            if malicious > 0:
                                result['summary']['is_malicious'] = True
                                result['summary']['detection_count'] = malicious
                                result['summary']['total_engines'] = stats.get('total', 0)
                            result['summary']['tags'].update(data.get('tags', []))

                        # MalwareBazaar
                        if source == 'malwarebazaar':
                            result['summary']['is_malicious'] = True
                            if data.get('signature'):
                                result['summary']['malware_names'].add(data['signature'])
                            result['summary']['tags'].update(data.get('tags', []))

                        # ThreatFox
                        if source == 'threatfox':
                            result['summary']['is_malicious'] = True
                            for ioc in data.get('iocs', []):
                                if ioc.get('malware'):
                                    result['summary']['malware_names'].add(ioc['malware'])

            except Exception as e:
                logger.debug(f"Hash lookup {source} failed: {str(e)}")
                result['sources'][source] = {'status': 'error', 'message': str(e)}

    # Convert sets to lists for JSON serialization
    result['summary']['malware_names'] = list(result['summary']['malware_names'])
    result['summary']['tags'] = list(result['summary']['tags'])

    # Add quick reference links
    result['reference_links'] = {
        'virustotal': f"https://www.virustotal.com/gui/search/{hash_value}",
        'malwarebazaar': f"https://bazaar.abuse.ch/browse.php?search=sha256:{hash_value}",
        'hybrid_analysis': f"https://www.hybrid-analysis.com/search?query={hash_value}",
        'any_run': f"https://any.run/report/{hash_value}",
        'joesandbox': f"https://www.joesandbox.com/search?q={hash_value}"
    }

    return result


def get_hash_info_quick(hash_value: str) -> Dict:
    """Quick hash lookup - shorter timeouts, essential info only."""
    return get_hash_info(hash_value, deep_scan=False)


def get_hash_info_deep(hash_value: str) -> Dict:
    """Deep hash lookup - full analysis with longer timeouts."""
    return get_hash_info(hash_value, deep_scan=True)
