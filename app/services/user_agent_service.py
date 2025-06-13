import re
from typing import Dict, Any, Optional

class UserAgentParser:
    """A class to parse user agent strings locally without relying on external APIs."""
    
    # Common browser patterns
    BROWSER_PATTERNS = {
        'Chrome': r'Chrome/(\d+\.\d+)',
        'Firefox': r'Firefox/(\d+\.\d+)',
        'Safari': r'Version/(\d+\.\d+)',
        'Edge': r'Edg/(\d+\.\d+)',
        'Opera': r'OPR/(\d+\.\d+)',
        'Internet Explorer': r'MSIE (\d+\.\d+)',
        'Brave': r'Brave/(\d+\.\d+)',
        'Vivaldi': r'Vivaldi/(\d+\.\d+)',
        'Samsung Internet': r'SamsungBrowser/(\d+\.\d+)',
        'UC Browser': r'UCBrowser/(\d+\.\d+)',
    }
    
    # Common OS patterns
    OS_PATTERNS = {
        'Windows': r'Windows NT (\d+\.\d+)',
        'Mac OS X': r'Mac OS X (\d+[._]\d+(?:[._]\d+)?)',
        'Linux': r'Linux',
        'iOS': r'iPhone OS (\d+[._]\d+(?:[._]\d+)?)',
        'Android': r'Android (\d+\.\d+(?:\.\d+)?)',
        'Chrome OS': r'CrOS',
        'Windows Phone': r'Windows Phone (\d+\.\d+)',
        'BlackBerry': r'BlackBerry',
        'Ubuntu': r'Ubuntu',
        'Fedora': r'Fedora',
        'Debian': r'Debian',
    }
    
    # Device patterns
    DEVICE_PATTERNS = {
        'iPhone': r'iPhone',
        'iPad': r'iPad',
        'iPod': r'iPod',
        'Android': r'Android',
        'Windows Phone': r'Windows Phone',
        'BlackBerry': r'BlackBerry',
        'PlayBook': r'PlayBook',
        'Kindle': r'Kindle',
        'Nexus': r'Nexus',
        'Pixel': r'Pixel',
        'Galaxy': r'Galaxy',
        'Xiaomi': r'Xiaomi',
        'Huawei': r'Huawei',
        'OnePlus': r'OnePlus',
    }
    
    # Brand patterns
    BRAND_PATTERNS = {
        'Apple': r'(iPhone|iPad|iPod|Mac)',
        'Samsung': r'(Galaxy|Samsung)',
        'Google': r'(Pixel|Nexus)',
        'Xiaomi': r'Xiaomi',
        'Huawei': r'Huawei',
        'OnePlus': r'OnePlus',
        'Sony': r'Sony',
        'LG': r'LG',
        'Motorola': r'Moto',
        'Nokia': r'Nokia',
        'BlackBerry': r'BlackBerry',
        'Amazon': r'Kindle',
    }
    
    @staticmethod
    def parse(user_agent: str) -> Dict[str, Any]:
        """
        Parse a user agent string and return structured information.
        
        Args:
            user_agent (str): The user agent string to parse
            
        Returns:
            Dict[str, Any]: A dictionary containing parsed information
        """
        if not user_agent:
            return {
                'browser': {'name': 'Unknown', 'version': 'Unknown'},
                'os': {'name': 'Unknown', 'version': 'Unknown'},
                'device': {'type': 'Unknown', 'brand': 'Unknown', 'model': 'Unknown'},
                'is_mobile': False,
                'is_tablet': False,
                'is_desktop': True
            }
        
        # Initialize result dictionary
        result = {
            'browser': {'name': 'Unknown', 'version': 'Unknown'},
            'os': {'name': 'Unknown', 'version': 'Unknown'},
            'device': {'type': 'Unknown', 'brand': 'Unknown', 'model': 'Unknown'},
            'is_mobile': False,
            'is_tablet': False,
            'is_desktop': True
        }
        
        # Parse browser
        for browser, pattern in UserAgentParser.BROWSER_PATTERNS.items():
            match = re.search(pattern, user_agent)
            if match:
                result['browser']['name'] = browser
                result['browser']['version'] = match.group(1)
                break
        
        # Parse OS
        for os_name, pattern in UserAgentParser.OS_PATTERNS.items():
            match = re.search(pattern, user_agent)
            if match:
                result['os']['name'] = os_name
                if match.groups():
                    result['os']['version'] = match.group(1).replace('_', '.')
                break
        
        # Parse device and brand
        for device, pattern in UserAgentParser.DEVICE_PATTERNS.items():
            if re.search(pattern, user_agent):
                result['device']['type'] = 'Mobile' if device in ['iPhone', 'Android', 'Windows Phone', 'BlackBerry', 'Kindle', 'Nexus', 'Pixel', 'Galaxy', 'Xiaomi', 'Huawei', 'OnePlus'] else 'Tablet'
                result['device']['model'] = device
                break
        
        # Parse brand
        for brand, pattern in UserAgentParser.BRAND_PATTERNS.items():
            if re.search(pattern, user_agent):
                result['device']['brand'] = brand
                break
        
        # Determine device type
        if any(x in user_agent for x in ['Mobile', 'Android', 'iPhone', 'Windows Phone', 'BlackBerry', 'Kindle', 'Nexus', 'Pixel', 'Galaxy', 'Xiaomi', 'Huawei', 'OnePlus']):
            result['is_mobile'] = True
            result['is_desktop'] = False
        elif 'iPad' in user_agent or 'PlayBook' in user_agent:
            result['is_tablet'] = True
            result['is_desktop'] = False
        
        return result

def parse_user_agent(user_agent: str) -> Dict[str, Any]:
    """
    Parse a user agent string and return structured information.
    
    Args:
        user_agent (str): The user agent string to parse
        
    Returns:
        Dict[str, Any]: A dictionary containing parsed information
    """
    return UserAgentParser.parse(user_agent) 