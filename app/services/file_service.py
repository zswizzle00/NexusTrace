import os
import logging
from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis
from ..utils.cache import timed_lru_cache
from OTXv2 import OTXv2, IndicatorTypes

# Configure logging
logger = logging.getLogger(__name__)

def setup_file_services(app):
    """Setup file-related services."""
    # Initialize Intezer API
    intezer_api_key = os.getenv('INTEZER_KEY')
    if not intezer_api_key:
        logger.warning("Intezer API key not configured")
    else:
        api.set_global_api(intezer_api_key)

@timed_lru_cache(seconds=1800)
def get_intezer_analysis(file_path=None, file_hash=None):
    """Analyze a file using Intezer's API."""
    try:
        if not os.getenv('INTEZER_KEY'):
            logger.warning("Intezer API key not configured")
            return None
            
        if file_path:
            analysis = FileAnalysis(file_path=file_path)
        elif file_hash:
            analysis = FileAnalysis(file_hash=file_hash)
        else:
            return None
            
        # Send the analysis and wait for results
        analysis.send(wait=True)
        result = analysis.result()
        
        # Get additional information
        root_analysis = analysis.get_root_analysis()
        code_reuse = root_analysis.code_reuse if root_analysis else None
        metadata = root_analysis.metadata if root_analysis else None
        
        # Add all possible fields
        return {
            'analysis_id': result.get('analysis_id'),
            'analysis_time': result.get('analysis_time'),
            'analysis_url': result.get('analysis_url'),
            'family_name': result.get('family_name'),
            'is_private': result.get('is_private'),
            'sha256': result.get('sha256'),
            'sub_verdict': result.get('sub_verdict'),
            'verdict': result.get('verdict'),
            'code_reuse': code_reuse,
            'metadata': metadata,
            'malware_family': result.get('malware_family'),
            'threat_type': result.get('threat_type'),
            'indicators': result.get('indicators'),
            'classification': result.get('classification'),
        }
    except Exception as e:
        logger.error(f"Intezer analysis failed: {str(e)}")
        return None 

def get_alienvault_analysis(file_hash):
    """Analyze a file hash using AlienVault OTX API."""
    otx_api_key = os.getenv('OTX_API_KEY')
    if not otx_api_key:
        logger.warning("AlienVault OTX API key not configured")
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
    """Get combined analysis from Intezer and AlienVault OTX."""
    intezer_result = get_intezer_analysis(file_path=file_path, file_hash=file_hash)
    otx_result = None
    if file_hash:
        otx_result = get_alienvault_analysis(file_hash)
    return {
        'intezer': intezer_result,
        'alienvault_otx': otx_result
    } 