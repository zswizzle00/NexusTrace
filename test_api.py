import requests
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API key
api_key = os.getenv('APILAYER_API_KEY')
print(f"API Key: {api_key}")

# Test user agent
test_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"

# Make request
url = "https://api.apilayer.com/user_agent/parse"
headers = {
    "apikey": api_key
}
params = {
    "ua": test_ua
}

try:
    print(f"\nMaking request to: {url}")
    print(f"Headers: {headers}")
    print(f"Params: {params}")
    
    response = requests.get(url, headers=headers, params=params)
    print(f"\nStatus Code: {response.status_code}")
    print(f"Response Text: {response.text}")
    
    if response.status_code == 200:
        print("\nSuccess! API is working correctly.")
    else:
        print("\nError! API request failed.")
        
except Exception as e:
    print(f"\nError occurred: {str(e)}") 