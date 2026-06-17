import os
import hashlib
import logging
from ..utils.cache import timed_lru_cache
from OTXv2 import OTXv2, IndicatorTypes

# Configure logging
logger = logging.getLogger(__name__)

def setup_file_services(app):
    """Setup file-related services."""
    pass

def _sha256_of_file(file_path):
    """Compute the SHA-256 of a file in streaming chunks."""
    digest = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            digest.update(chunk)
    return digest.hexdigest()

def get_alienvault_analysis(file_hash):
    """Analyze a file hash using AlienVault OTX API."""
    # Support multiple env var names for backwards compatibility
    otx_api_key = os.getenv('ALIENVAULT_KEY') or os.getenv('ALIENVAULT') or os.getenv('OTX_API_KEY')
    if not otx_api_key:
        logger.debug("AlienVault API key not configured (ALIENVAULT_KEY)")
        return None
    try:
        otx = OTXv2(otx_api_key)
        # Query OTX for file hash (supports md5, sha1, sha256)
        result = otx.get_indicator_details(IndicatorTypes.FILE_HASH_MD5, file_hash)
        # Try SHA1/SHA256 if MD5 fails
        if not result or 'general' not in result:
            result = otx.get_indicator_details(IndicatorTypes.FILE_HASH_SHA1, file_hash)
        if not result or 'general' not in result:
            result = otx.get_indicator_details(IndicatorTypes.FILE_HASH_SHA256, file_hash)
        return result
    except Exception as e:
        logger.error(f"AlienVault OTX analysis failed: {str(e)}")
        return None

@timed_lru_cache(seconds=1800)
def get_combined_file_analysis(file_path=None, file_hash=None):
    """Analyze a file or hash via AlienVault OTX hash reputation.

    For an uploaded file we compute its SHA-256 and look the hash up (OTX is hash-based),
    so the endpoint still works without any binary-analysis engine.
    """
    if file_path and not file_hash:
        try:
            file_hash = _sha256_of_file(file_path)
        except OSError as e:
            logger.error(f"Could not read file for hashing: {str(e)}")
            return None
    otx_result = get_alienvault_analysis(file_hash) if file_hash else None
    return {
        'sha256': file_hash,
        'alienvault_otx': otx_result,
    }