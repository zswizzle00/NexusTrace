import requests
import json

BASE_URL = 'http://localhost:5000'

def test_health():
    """Test the health check endpoint."""
    response = requests.get(f'{BASE_URL}/health')
    print("\nTesting Health Check:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_ip_check():
    """Test the IP check endpoint."""
    test_ip = "8.8.8.8"  # Google's DNS
    response = requests.post(
        f'{BASE_URL}/check_ip',
        json={'ip': test_ip}
    )
    print("\nTesting IP Check:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_domain_check():
    """Test the domain check endpoint."""
    test_domain = "google.com"
    response = requests.post(
        f'{BASE_URL}/check_domain',
        json={'domain': test_domain}
    )
    print("\nTesting Domain Check:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

def test_url_analysis():
    """Test the URL analysis endpoint."""
    test_url = "https://www.google.com"
    response = requests.post(
        f'{BASE_URL}/analyze_url',
        json={'url': test_url}
    )
    print("\nTesting URL Analysis:")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

if __name__ == '__main__':
    try:
        test_health()
        test_ip_check()
        test_domain_check()
        test_url_analysis()
    except requests.exceptions.ConnectionError:
        print("\nError: Could not connect to the server. Make sure the Flask application is running.")
    except Exception as e:
        print(f"\nError: {str(e)}") 