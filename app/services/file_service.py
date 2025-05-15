import os
import logging
from intezer_sdk import api
from intezer_sdk.analysis import FileAnalysis
from ..utils.cache import timed_lru_cache

# Configure logging
logger = logging.getLogger(__name__)

def setup_file_services(app):
    """Setup file-related services."""
    # Initialize Intezer API
    intezer_api_key = os.getenv('INTEZER_API_KEY')
    if not intezer_api_key:
        logger.warning("Intezer API key not configured")
    else:
        api.set_global_api(intezer_api_key)

@timed_lru_cache(seconds=1800)
def get_intezer_analysis(file_path=None, file_hash=None):
    """Analyze a file using Intezer's API."""
    try:
        if not os.getenv('INTEZER_API_KEY'):
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