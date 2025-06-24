import requests
from bs4 import BeautifulSoup
import re

def get_azure_error_info(error_code):
    """
    Fetch information about an Azure error code from the Microsoft error lookup website.
    
    Args:
        error_code (str): The Azure error code to look up (e.g., 'AADSTS50058')
        
    Returns:
        dict: A dictionary containing the error information
    """
    try:
        # Clean the error code - remove 'AADSTS' prefix if present and ensure proper format
        clean_code = error_code.upper().replace('AADSTS', '').strip()
        
        # Construct the URL for the error lookup
        url = f"https://login.microsoftonline.com/error?code={clean_code}"
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        error_info = {
            'error_code': f"AADSTS{clean_code}",
            'title': '',
            'description': '',
            'solutions': [],
            'additional_info': '',
            'error_type': '',
            'severity': ''
        }

        # Look for the error information table
        # Based on the actual page structure, we need to find the table with error details
        tables = soup.find_all('table')
        
        for table in tables:
            rows = table.find_all('tr')
            for row in rows:
                cells = row.find_all(['td', 'th'])
                if len(cells) >= 2:
                    # Check if this row contains error information
                    first_cell = cells[0].get_text(strip=True).lower()
                    second_cell = cells[1].get_text(strip=True)
                    
                    if 'error code' in first_cell:
                        # Found the error code row
                        error_info['title'] = f"Azure Error Code: AADSTS{clean_code}"
                    elif 'message' in first_cell:
                        # Found the message/description row
                        error_info['description'] = second_cell
                    elif 'remediation' in first_cell:
                        # Found the remediation/solutions row
                        error_info['solutions'] = [second_cell]
                        # Split long remediation text into multiple solutions if it contains multiple sentences
                        if '. ' in second_cell:
                            sentences = [s.strip() for s in second_cell.split('. ') if s.strip()]
                            error_info['solutions'] = sentences[:5]  # Limit to 5 solutions

        # If we didn't find structured data, try to extract from general content
        if not error_info['description']:
            # Look for any paragraph content that might contain error information
            paragraphs = soup.find_all('p')
            for p in paragraphs:
                text = p.get_text(strip=True)
                if text and len(text) > 20 and 'error' in text.lower():
                    error_info['description'] = text
                    break

        # Determine error type based on error code patterns and content
        content_text = soup.get_text().lower()
        
        # Determine error type based on common patterns
        if any(word in content_text for word in ['authentication', 'auth', 'login', 'sign in']):
            error_info['error_type'] = 'Authentication'
        elif any(word in content_text for word in ['authorization', 'permission', 'access']):
            error_info['error_type'] = 'Authorization'
        elif any(word in content_text for word in ['configuration', 'setup', 'tenant']):
            error_info['error_type'] = 'Configuration'
        elif any(word in content_text for word in ['token', 'refresh', 'expired']):
            error_info['error_type'] = 'Token'
        elif any(word in content_text for word in ['session', 'sso', 'single sign']):
            error_info['error_type'] = 'Session'
        else:
            error_info['error_type'] = 'General'

        # Determine severity based on error code patterns and content
        if any(word in content_text for word in ['critical', 'fatal', 'blocking']):
            error_info['severity'] = 'Critical'
        elif any(word in content_text for word in ['warning', 'temporary', 'retry']):
            error_info['severity'] = 'Warning'
        elif any(word in content_text for word in ['information', 'info']):
            error_info['severity'] = 'Information'
        else:
            # Default severity based on error code patterns
            if clean_code.startswith(('5', '6', '7')):
                error_info['severity'] = 'Error'
            elif clean_code.startswith(('1', '2')):
                error_info['severity'] = 'Information'
            else:
                error_info['severity'] = 'Warning'

        # If no meaningful content was found, provide a generic response
        if not error_info['title'] and not error_info['description']:
            error_info['title'] = f"Azure Error Code: AADSTS{clean_code}"
            error_info['description'] = f"No specific information found for error code AADSTS{clean_code}. Please check the Microsoft documentation for the most up-to-date information."
            error_info['solutions'] = [
                "Check the Microsoft Entra ID documentation for this error code",
                "Verify your application configuration",
                "Ensure proper authentication parameters are provided",
                "Contact your system administrator if the issue persists"
            ]

        return error_info

    except requests.RequestException as e:
        return {
            'error_code': f"AADSTS{error_code.replace('AADSTS', '').strip()}",
            'title': 'Error Fetching Information',
            'description': f'Unable to fetch error information: {str(e)}',
            'solutions': [
                "Check your internet connection",
                "Verify the error code format",
                "Try again later",
                "Check Microsoft's official documentation"
            ],
            'additional_info': '',
            'error_type': 'Network Error',
            'severity': 'Error'
        }
    except Exception as e:
        return {
            'error_code': f"AADSTS{error_code.replace('AADSTS', '').strip()}",
            'title': 'Processing Error',
            'description': f'Error processing request: {str(e)}',
            'solutions': [
                "Verify the error code format",
                "Check Microsoft's official documentation",
                "Contact support if the issue persists"
            ],
            'additional_info': '',
            'error_type': 'Processing Error',
            'severity': 'Error'
        } 